"""Dashboard di Apernix: `apernix` senza argomenti apre questa schermata.

- all'avvio cerca da sola le web application su questa macchina
- Invio su un bersaglio: conferma del certificato (se serve) e dell'autorizzazione, poi parte
- mentre lavora mostra il flusso delle fasi, le barre di avanzamento e cosa sta facendo adesso
- l'analisi gira in un thread separato: lo schermo resta sempre reattivo e x la ferma subito
"""

from __future__ import annotations

import contextlib
import dataclasses
import os
import queue
import threading
import time
import warnings

from apernix import autoconf, tlsinfo
from apernix import discover as disc
from apernix import report as rpt
from apernix.dashboard.state import (
    LEVEL_ROLE,
    P_FINDINGS,
    P_LIVE,
    P_PHASES,
    P_TARGETS,
    PANELS,
    DashState,
    Detail,
    Modal,
    TargetRow,
)
from apernix.dashboard.view import Canvas
from apernix.engine import FLOW, Event, mmss, run_scan
from apernix.i18n import t
from apernix.scope import ScopeError, load_scope, parse_target_url
from apernix.scope_write import add_target, set_internal
from apernix.term import clean
from apernix.web.http import SafeClient

PROFILES = (("web",), ("web", "nuclei", "nmap", "inside"))


def _private(host: str) -> bool:
    from apernix.guided import is_private
    return is_private(host)


def finding_detail(f) -> Detail:
    role = LEVEL_ROLE[f.level]
    lines = [
        [(f"{f.risk} ", role), (t("level." + f.level), role), (f"   {f.impact} × {f.probability}", "muted"),
         (f"  ({t('table.impact').lower()} × {t('table.probability').lower()})", "faint")],
        ("", "text"),
        [(f"{t('table.element')}: ", "accent"), (f.element, "text")],
        [(f"{t('table.pt')}: ", "accent"), (t("pt." + f.pt), "text")],
        [(f"{t('table.source')}: ", "accent"), (f.source, "text"), (f"  {f.check}", "muted")],
        ("", "text"), [(t("table.evidence"), "accent")],
        *[(f"  • {e}", "text") for e in f.evidence],
        ("", "text"), [(t("table.remediation"), "accent")], (f"  {f.remediation}", "text"),
    ]
    return Detail(f.title, lines)


def phase_detail(s, pid: str) -> Detail:
    ph = s.phases[pid]
    state = t(f"dash.state.{ph.state}")
    pct = int((1.0 if ph.state == "done" else ph.frac) * 100)
    lines = [[(f"{t('dash.state')}: ", "accent"), (state, "text")],
             [(f"{t('dash.progress')}: ", "accent"), (f"{pct}%", "text"),
              (f"  {ph.label}" if ph.label else "", "muted")]]
    if ph.note:
        lines.append([(f"{t('dash.note')}: ", "accent"), (ph.note, "text")])
    lines += [("", "text"), (t(f"dash.phase.{pid}.about"), "text")]
    src = {"web": "apernix-web", "nuclei": "nuclei", "nmap": "nmap"}.get(pid)
    if src and src in s.sources:
        lines += [("", "text"), [(f"{t('report.sources')}: ", "accent"), (t("source." + s.sources[src]), "text")]]
    return Detail(t(f"dash.phase.{pid}"), lines)


def open_in_browser(path: str) -> bool:
    """xdg-open in un processo separato: niente shell, uscita scartata (non sporca lo schermo)."""
    import shutil
    import subprocess
    exe = shutil.which("xdg-open")
    if exe is None:
        return False
    try:
        subprocess.Popen([exe, os.path.abspath(path)], stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL,
                         stderr=subprocess.DEVNULL, start_new_session=True)
    except OSError:
        return False
    return True


class Controller:
    """Logica della dashboard, indipendente da curses (così si prova con i test)."""

    def __init__(self, scope_path: str, out_dir: str, spawn=None, finder=disc.discover, tls=tlsinfo,
                 probe=disc.probe, redraw=lambda: None, opener=None, detector=autoconf.detect_internal) -> None:
        self.scope_path, self.out_dir = scope_path, out_dir
        self.state = DashState()
        self.events: queue.Queue = queue.Queue()
        self.cancel = threading.Event()
        self.spawn = spawn or (lambda fn: threading.Thread(target=fn, daemon=True).start())
        self.finder, self.tls, self.probe, self.redraw = finder, tls, probe, redraw
        self.opener = opener or open_in_browser
        self.detector = detector
        self._internal_asked: set = set()
        self.discovered: list = []
        self.quit = False
        self.last_targets: dict = {}

    # ------------------------------------------------------------ bersagli
    def scope(self):
        if not os.path.exists(self.scope_path):
            return None
        try:
            return load_scope(self.scope_path)
        except ScopeError as exc:
            params = dict(exc.params)
            if "reason_key" in params:
                params["reason"] = t(params.pop("reason_key"), **params)
            self.state.status = t(exc.code, **params)
            return None

    def reload_targets(self) -> None:
        sc = self.scope()
        rows = [TargetRow(x.url, x.name, True) for x in (sc.targets if sc else ())]
        known = {r.url for r in rows}
        for c in self.discovered:
            try:
                url = parse_target_url(c.url).url
            except ValueError:
                continue
            if url not in known:
                rows.append(TargetRow(url, c.name, False, c.via))
                known.add(url)
        self.state.targets = rows
        self.state.selected = min(self.state.selected, max(0, len(rows) - 1))

    def start_discovery(self) -> None:
        if self.state.discovering:
            return
        self.state.discovering = True
        self.state.log(t("g.searching"))

        def work():
            try:
                found = self.finder()
            except Exception:       # la scoperta non deve mai far cadere la dashboard
                found = []
            self.events.put(Event("_discovered", {"items": found}))
        self.spawn(work)

    # ------------------------------------------------------------ eventi dal motore
    def pump(self) -> None:
        while True:
            try:
                ev = self.events.get_nowait()
            except queue.Empty:
                return
            if ev.kind == "_discovered":
                self.discovered = ev.data["items"]
                self.state.discovering = False
                self.state.log(t("dash.found", n=len(self.discovered)))
                self.reload_targets()
            elif ev.kind == "_done":
                self._finish(ev.data)
            else:
                self.state.apply(ev)

    def _finish(self, d: dict) -> None:
        s = self.state
        s.finish()
        res = d["result"]
        s.sources = dict(res.sources)
        if d.get("folder"):
            s.report = clean(d["folder"], 200)
        if res.cancelled:
            s.status, s.status_role = t("dash.status.cancelled"), "warn"
            for ph in s.phases.values():
                if ph.state in ("run", "wait"):
                    ph.state, ph.note = "fail", t("dash.phase.stopped")
        elif not res.reached:
            outcome = next(iter(res.errors.values()), "net")
            s.status = t("g.tls") if outcome == "tls" else t("g.unreachable")
            s.status_role = "alert"
            if outcome == "tls":
                tg = d["target"]
                self.ask_trust(tg.url, changed=bool(tg.ca_file), then=lambda ca: self._retrust(tg.url, ca))
        else:
            s.status, s.status_role = t("dash.status.done", n=len(res.findings)), "ok"
        s.log([(s.status, s.status_role)])
        if d.get("error"):
            s.status, s.status_role = t(d["error"]), "alert"

    def _retrust(self, url: str, ca: str) -> None:
        add_target(self.scope_path, url, ca_file=ca)
        self.start_scan(url)

    # ------------------------------------------------------------ avvio analisi
    def start_scan(self, url: str) -> None:
        sc = self.scope()
        tg = next((x for x in sc.targets if x.url == url), None) if sc else None
        if tg is None or self.state.running:
            return
        if sc.internal is None and url not in self._internal_asked:
            self._internal_asked.add(url)
            if self._offer_internal(url):
                return
        phases = PROFILES[self.state.profile]
        one = dataclasses.replace(sc, targets=(tg,))
        self.cancel = threading.Event()
        self.state.reset_run(url, phases)
        out_dir, cancel, events = self.out_dir, self.cancel, self.events

        def work():
            started = time.monotonic()
            client = SafeClient(one)
            res = run_scan(one, client, phases, emit=events.put, cancel=cancel)
            data = {"result": res, "target": tg}
            if res.reached:
                events.put(Event("phase", {"id": "report", "state": "start"}))
                events.put(Event("action", {"text": t("dash.act.report")}))
                extra = {"fingerprint": res.fingerprint, "services": res.services,
                         "sources": [{"name": k, "status": v} for k, v in res.sources.items()]}
                label = t("dash.profile." + ("full" if len(phases) > 1 else "quick"))
                meta = {"name": tg.name or tg.host, "profile": label,
                        "duration": mmss(time.monotonic() - started)}
                doc = rpt.build([tg.url], res.findings, client.requests_made, extra, meta)
                try:
                    data["folder"] = rpt.save(doc, out_dir)
                    events.put(Event("phase", {"id": "report", "state": "done", "note": t("dash.note.saved")}))
                except rpt.ReportError as exc:
                    data["error"] = exc.code
                    events.put(Event("phase", {"id": "report", "state": "fail"}))
            events.put(Event("_done", data))
        self.spawn(work)

    def _offer_internal(self, url: str) -> bool:
        """Se l'app gira in Docker qui, propone l'analisi interna. True se ha aperto la domanda."""
        try:
            found = self.detector(url)
        except Exception:       # il rilevamento non deve mai bloccare l'analisi
            found = None
        if not found:
            return False

        def yes():
            try:
                set_internal(self.scope_path, found)
            except (ScopeError, OSError):
                self.info(t("dash.modal.error"), [t("err.output_dir")])
                return
            self.start_scan(url)
        self.state.modal = Modal("confirm", t("dash.modal.internal"),
                                 [t("dash.internal.question"), "", *autoconf.internal_lines(found)],
                                 on_yes=yes, on_no=lambda: self.start_scan(url))
        return True

    # ------------------------------------------------------------ nuovo bersaglio
    def new_target(self, url: str, name: str = "") -> None:
        try:
            tg = parse_target_url(url)
        except ValueError:
            self.info(t("dash.modal.error"), [t("err.scope_invalid", reason=t("scope.reason.bad_url", url=url[:200]))])
            return
        if tg.scheme == "https":
            self.state.status = t("dash.checking_cert")
            self.redraw()
            self.ask_trust(tg.url, then=lambda ca: self.ask_auth(tg.url, name, ca))
        else:
            self.ask_auth(tg.url, name, "")

    def ask_trust(self, url: str, then, changed: bool = False) -> None:
        tg = parse_target_url(url)
        try:
            if not changed and self.tls.publicly_trusted(tg.host, tg.port):
                then("")
                return
            chain = self.tls.fetch_chain(tg.host, tg.port)
        except OSError:
            self.info(t("dash.modal.error"), [t("g.unreachable")])
            return
        if not chain:
            self.info(t("dash.modal.error"), [t("g.tls")])
            return
        leaf, top = self.tls.describe(chain[0]), self.tls.describe(chain[-1])
        lines = [t("g.cert_changed" if changed else "g.cert_private"), "",
                 f"{t('g.cert.subject')}: {leaf['subject']}", f"{t('g.cert.issuer')}: {top['issuer']}",
                 f"{t('g.cert.expires')}: {leaf['not_after']}", f"{t('g.cert.trusting')}: {top['subject']}",
                 f"SHA-256: {top['sha256']}", "", t("dash.trust.question")]

        def yes():
            base = os.path.dirname(os.path.abspath(self.scope_path))
            then(self.tls.save_pin(base, tg.host, tg.port, chain[-1]))
        self.state.status = ""
        self.state.modal = Modal("confirm", t("dash.modal.cert"), lines, on_yes=yes, danger=changed)

    def ask_auth(self, url: str, name: str, ca: str) -> None:
        def yes():
            tg = parse_target_url(url)
            label = name
            if not label:
                hit = self.probe(tg.host, tg.port)
                label = hit[1] if hit and hit[1] else tg.host
            try:
                add_target(self.scope_path, url, label, ca, None, 20.0 if _private(tg.host) else None)
            except (ScopeError, OSError):
                self.info(t("dash.modal.error"), [t("err.output_dir")])
                return
            self.reload_targets()
            self.state.selected = next((i for i, r in enumerate(self.state.targets) if r.url == url), 0)
            self.start_scan(url)
        self.state.modal = Modal("confirm", t("dash.modal.auth"), [t("dash.auth.question", url=url)], on_yes=yes)

    def info(self, title: str, lines: list[str]) -> None:
        self.state.modal = Modal("info", title, lines)

    # ------------------------------------------------------------ tastiera
    def handle_key(self, key: str) -> None:
        s = self.state
        if s.modal:
            self._modal_key(key)
            return
        if s.detail:
            self._detail_key(key)
            return
        if key in ("q", "Q"):
            if s.zoom is not None:
                s.zoom = None
            elif s.running:
                s.modal = Modal("confirm", t("dash.modal.quit"), [t("dash.quit.question")], on_yes=self.shutdown)
            else:
                self.quit = True
        elif key == "ESC":
            s.zoom = None
        elif key == "TAB":
            s.focus = (s.focus + 1) % len(PANELS)
            if s.zoom is not None:
                s.zoom = s.focus
        elif key == "BTAB":
            s.focus = (s.focus - 1) % len(PANELS)
            if s.zoom is not None:
                s.zoom = s.focus
        elif key in ("1", "2", "3", "4", "5"):
            idx = int(key) - 1
            s.zoom = None if s.zoom == idx else idx       # stesso numero: torna alla vista d'insieme
            s.focus = idx
        elif key in ("UP", "k"):
            self._move(-1)
        elif key in ("DOWN", "j"):
            self._move(1)
        elif key == "PGUP":
            self._move(-10)
        elif key == "PGDN":
            self._move(10)
        elif key in ("HOME", "g"):
            self._move(-10**6)
        elif key in ("END", "G"):
            self._move(10**6)
        elif key == "ENTER":
            self._enter()
        elif key == "x" and s.running:
            self.cancel.set()
            s.status, s.status_role = t("dash.stopping"), "warn"
        elif key == "a" and not s.running:
            s.modal = Modal("input", t("dash.modal.url"), [t("g.url")], on_yes=lambda text: self.new_target(text))
        elif key == "p" and not s.running:
            s.profile = 1 - s.profile
        elif key == "d" and not s.running:
            self.start_discovery()
        elif key == "r":
            self.show_report()
        elif key == "o":
            self.open_report()
        elif key == "?":
            s.detail = Detail(t("dash.modal.guide"), [(line, "text") for line in t("dash.guide").split("|")])

    def _detail_key(self, key: str) -> None:
        d = self.state.detail
        if key in ("TAB", "BTAB", "1", "2", "3", "4", "5"):
            # anche da un dettaglio si viaggia tra le sezioni: si chiude e si passa alla sezione
            self.state.detail = None
            self.handle_key(key)
        elif key in ("ESC", "q", "Q", "ENTER", "BACKSPACE"):
            self.state.detail = None
        elif key in ("UP", "k"):
            d.scroll = max(0, d.scroll - 1)
        elif key in ("DOWN", "j"):
            d.scroll += 1
        elif key == "PGUP":
            d.scroll = max(0, d.scroll - 10)
        elif key in ("PGDN", " "):
            d.scroll += 10
        elif key in ("HOME", "g"):
            d.scroll = 0

    def _move(self, step: int) -> None:
        s = self.state
        panel = s.focus
        if panel == P_TARGETS and s.targets:
            s.selected = max(0, min(len(s.targets) - 1, s.selected + step))
        elif panel == P_FINDINGS and s.findings:
            s.finding_sel = max(0, min(len(s.findings) - 1, s.finding_sel + step))
        elif panel == P_PHASES:
            s.phase_sel = max(0, min(len(FLOW) - 1, s.phase_sel + step))
        elif panel == P_LIVE:
            # su = indietro nel tempo; End (passo enorme in giù) torna a seguire gli ultimi passi
            s.live_scroll = max(0, min(len(s.live) - 1, s.live_scroll - step)) if s.live else 0

    def _enter(self) -> None:
        """Invio nella vista d'insieme apre la sezione (con il cursore sulla stessa riga);
        Invio nella sezione aperta agisce sulla riga scelta."""
        s = self.state
        panel = s.focus
        if s.zoom is None:
            s.zoom = panel
            return
        if panel == P_FINDINGS and s.findings:
            s.detail = finding_detail(s.findings[s.finding_sel])
        elif panel == P_PHASES:
            s.detail = phase_detail(s, FLOW[s.phase_sel])
        elif panel == P_LIVE:
            s.live_scroll = 0
        elif panel == P_TARGETS and not s.running and s.targets:
            row = s.targets[s.selected]
            if row.authorized:
                self.start_scan(row.url)
            else:
                self.new_target(row.url, row.name)

    def open_report(self) -> None:
        """Apre report.html nel browser predefinito (xdg-open), senza bloccare la dashboard."""
        s = self.state
        path = os.path.join(s.report, "report.html") if s.report else ""
        if not path or not os.path.isfile(path):
            self.info(t("dash.modal.report"), [t("dash.report.none")])
            return
        if self.opener(path):
            s.status, s.status_role = t("dash.report.opened"), "ok"
        else:
            self.info(t("dash.modal.report"), [t("dash.report.no_browser"), "", os.path.abspath(path)])

    def show_report(self) -> None:
        s = self.state
        if not s.report:
            self.info(t("dash.modal.report"), [t("dash.report.none")])
            return
        lines = [[(f"{t('dash.report')}: ", "accent"), (s.report, "ok")], ("", "text"),
                 [("report.html ", "accent"), (t("dash.report.html"), "text")],
                 [("report.md   ", "accent"), (t("dash.report.md"), "text")],
                 [("report.json ", "accent"), (t("dash.report.json"), "text")]]
        s.detail = Detail(t("dash.modal.report"), lines)

    def _modal_key(self, key: str) -> None:
        m = self.state.modal
        if m.kind == "info":
            if key in ("ENTER", "ESC", "q", " "):
                self.state.modal = None
        elif m.kind == "confirm":
            if key in ("s", "S", "y", "Y"):
                self.state.modal = None
                m.on_yes()
            elif key in ("n", "N", "ESC", "q"):
                self.state.modal = None
                if m.on_no:
                    m.on_no()
        elif m.kind == "input":
            if key == "ENTER":
                self.state.modal = None
                if m.text.strip():
                    m.on_yes(m.text.strip())
            elif key == "ESC":
                self.state.modal = None
            elif key == "BACKSPACE":
                m.text = m.text[:-1]
            elif len(key) == 1 and key.isprintable() and len(m.text) < 2048:
                m.text += key

    def shutdown(self) -> None:
        self.cancel.set()
        self.quit = True


# ---------------------------------------------------------------------------- curses
KEYMAP = {"\t": "TAB", "\n": "ENTER", "\r": "ENTER", "\x1b": "ESC", "\x7f": "BACKSPACE", "\x08": "BACKSPACE"}


@contextlib.contextmanager
def quiet_stderr():
    """Durante la dashboard nulla deve scrivere sul terminale oltre a curses (warning, messaggi di librerie):
    ogni riga estranea sporca lo schermo. stderr va su /dev/null e torna normale all'uscita."""
    if os.environ.get("APERNIX_DEBUG"):
        yield
        return
    try:
        saved = os.dup(2)
        null = os.open(os.devnull, os.O_WRONLY)
    except OSError:
        yield
        return
    try:
        os.dup2(null, 2)
        with warnings.catch_warnings():
            warnings.simplefilter("ignore")
            yield
    finally:
        os.dup2(saved, 2)
        os.close(saved)
        os.close(null)


def run(scope_path: str, out_dir: str) -> int:
    import curses
    import locale

    from apernix.dashboard.view import Glyphs, draw
    from apernix.term import use_color, use_unicode
    locale.setlocale(locale.LC_ALL, "")
    os.environ.setdefault("ESCDELAY", "25")      # Esc risponde subito (di default curses aspetta 1 secondo)
    # Caratteri speciali solo se il terminale parla davvero UTF-8 (con LANG=C si passa all'ASCII).
    utf8 = use_unicode() and locale.nl_langinfo(locale.CODESET).upper().replace("-", "") == "UTF8"
    glyphs = Glyphs(utf8)

    def main(stdscr) -> int:
        roles = _init_colors(curses) if use_color() else {}
        curses.curs_set(0)
        # Niente ottimizzazioni di scorrimento/inserimento: su alcuni terminali lasciano righe sporche.
        stdscr.idlok(False)
        stdscr.idcok(False)
        stdscr.scrollok(False)
        stdscr.keypad(True)
        stdscr.timeout(120)
        canvas_holder = {}

        last_size = {"v": stdscr.getmaxyx()}

        def paint_all():
            h, w = stdscr.getmaxyx()
            if (h, w) != last_size["v"]:        # finestra ridimensionata: si ridisegna tutto da zero
                last_size["v"] = (h, w)
                stdscr.clearok(True)
            stdscr.erase()
            canvas = _CursesCanvas(stdscr, w, h, roles, curses, ascii_only=not utf8)
            canvas_holder["c"] = canvas
            draw(canvas, ctrl.state, glyphs)
            stdscr.refresh()

        ctrl = Controller(scope_path, out_dir, redraw=paint_all)
        ctrl.reload_targets()
        ctrl.start_discovery()
        while not ctrl.quit:
            try:
                ctrl.pump()
                paint_all()
                try:
                    ch = stdscr.get_wch()
                except curses.error:
                    continue
                if ch == curses.KEY_RESIZE or ch == "\x0c":        # resize o Ctrl-L: ridisegno completo
                    if ch == curses.KEY_RESIZE:
                        curses.update_lines_cols()
                    stdscr.clearok(True)
                    continue
                key = _key_name(ch, curses)
                if key == "ESC":
                    key = _read_escape(stdscr, curses)
                if key:
                    ctrl.handle_key(key)
            except KeyboardInterrupt:
                ctrl.shutdown()
        return 0

    try:
        with quiet_stderr():
            return curses.wrapper(main)
    except curses.error:
        return 2
    except Exception:
        # Errore imprevisto: il terminale è già stato ripristinato da curses.wrapper.
        if os.environ.get("APERNIX_DEBUG"):
            raise
        import sys
        print(t("err.dashboard_crash"), file=sys.stderr)
        print("  " + t("err.dashboard_crash.hint"), file=sys.stderr)
        return 2


ESC_SEQ = {"[A": "UP", "[B": "DOWN", "[H": "HOME", "[F": "END", "[5~": "PGUP", "[6~": "PGDN", "[Z": "BTAB",
           "OA": "UP", "OB": "DOWN", "OH": "HOME", "OF": "END", "[1~": "HOME", "[4~": "END"}


def _read_escape(win, curses) -> str:
    """Alcuni terminali mandano le frecce come sequenze che curses non riconosce (es. ESC [ B):
    si leggono i caratteri che seguono subito l'ESC. Se non arriva niente, era davvero Esc."""
    win.nodelay(True)
    seq = ""
    try:
        for _ in range(4):
            try:
                ch = win.get_wch()
            except curses.error:
                break
            if not isinstance(ch, str):
                break
            seq += ch
            if seq in ESC_SEQ:
                return ESC_SEQ[seq]
            if len(seq) >= 2 and (seq[-1].isalpha() or seq[-1] == "~"):
                break
    finally:
        win.nodelay(False)
        win.timeout(120)
    return "ESC" if not seq else ""


def _key_name(ch, curses) -> str:
    if isinstance(ch, int):
        return {curses.KEY_UP: "UP", curses.KEY_DOWN: "DOWN", curses.KEY_ENTER: "ENTER",
                curses.KEY_BACKSPACE: "BACKSPACE", curses.KEY_BTAB: "BTAB", curses.KEY_PPAGE: "PGUP",
                curses.KEY_NPAGE: "PGDN", curses.KEY_HOME: "HOME", curses.KEY_END: "END"}.get(ch, "")
    return KEYMAP.get(ch, ch)


def _xterm256(hex_color: str) -> int:
    from apernix.palette import rgb
    r, g, b = rgb(hex_color)

    def q(v):
        return 0 if v < 48 else 1 if v < 115 else (v - 35) // 40
    return 16 + 36 * q(r) + 6 * q(g) + q(b)


def _init_colors(curses) -> dict:
    from apernix.palette import DARK
    if not curses.has_colors():
        return {}
    curses.start_color()
    try:
        curses.use_default_colors()
        bg = -1
    except curses.error:
        bg = curses.COLOR_BLACK
    rich = curses.COLORS >= 256
    spec = {
        "brand": ("primary", curses.COLOR_RED, curses.A_BOLD), "title": ("text", curses.COLOR_WHITE, curses.A_BOLD),
        "accent": ("accent", curses.COLOR_MAGENTA, 0), "faint": ("faint", curses.COLOR_BLACK, curses.A_BOLD),
        "text": ("text", curses.COLOR_WHITE, 0), "muted": ("muted", curses.COLOR_WHITE, curses.A_DIM),
        "border": ("muted", curses.COLOR_WHITE, curses.A_DIM), "dim": ("low", curses.COLOR_WHITE, curses.A_DIM),
        "ok": ("ok", curses.COLOR_GREEN, 0), "warn": ("medium", curses.COLOR_YELLOW, 0),
        "high": ("high", curses.COLOR_YELLOW, curses.A_BOLD), "alert": ("critical", curses.COLOR_RED, curses.A_BOLD),
        "critical": ("critical", curses.COLOR_RED, curses.A_BOLD | curses.A_REVERSE),
    }
    roles = {}
    for i, (role, (key, basic, attr)) in enumerate(spec.items(), start=1):
        fg = _xterm256(DARK[key]) if rich else basic
        try:
            curses.init_pair(i, fg, bg)
            roles[role] = curses.color_pair(i) | attr
        except curses.error:
            roles[role] = attr
    return roles


def to_ascii(text: str) -> str:
    """Per terminali non UTF-8: lettere accentate senza accento, altri simboli sostituiti da '?'
    (la lunghezza resta uguale, così l'impaginazione non si sposta)."""
    import unicodedata
    out = []
    for ch in text:
        if ord(ch) < 128:
            out.append(ch)
            continue
        base = unicodedata.normalize("NFKD", ch).encode("ascii", "ignore").decode()
        out.append(base[:1] if base else {"→": ">", "•": "*", "×": "x"}.get(ch, "?"))
    return "".join(out)


class _CursesCanvas(Canvas):
    def __init__(self, win, w, h, roles, curses, ascii_only=False) -> None:
        super().__init__(w, h)
        self.win, self.roles, self.curses = win, roles, curses
        self.ascii_only = ascii_only

    def put(self, y, x, text, role="text") -> None:
        if self.ascii_only:
            text = to_ascii(text)
        try:
            self.win.addstr(y, x, text, self.roles.get(role, 0))
        except self.curses.error:
            pass      # l'ultima cella dello schermo dà sempre errore: si ignora

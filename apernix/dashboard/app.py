"""Dashboard di Apernix: `apernix` senza argomenti apre questa schermata.

- all'avvio cerca da sola le web application su questa macchina
- Invio su un bersaglio: conferma del certificato (se serve) e dell'autorizzazione, poi parte
- mentre lavora mostra il flusso delle fasi, le barre di avanzamento e cosa sta facendo adesso
- l'analisi gira in un thread separato: lo schermo resta sempre reattivo e x la ferma subito
"""

from __future__ import annotations

import dataclasses
import os
import queue
import threading
import time

from apernix import discover as disc
from apernix import report as rpt
from apernix import tlsinfo
from apernix.dashboard.state import DashState, Modal, TargetRow
from apernix.engine import Event, run_scan
from apernix.i18n import t
from apernix.scope import ScopeError, load_scope, parse_target_url
from apernix.scope_write import add_target
from apernix.term import clean
from apernix.web.http import SafeClient

PROFILES = (("web",), ("web", "nuclei", "nmap"))


def _private(host: str) -> bool:
    from apernix.guided import is_private
    return is_private(host)


class Controller:
    """Logica della dashboard, indipendente da curses (così si prova con i test)."""

    def __init__(self, scope_path: str, out_dir: str, spawn=None, finder=disc.discover, tls=tlsinfo,
                 probe=disc.probe, redraw=lambda: None) -> None:
        self.scope_path, self.out_dir = scope_path, out_dir
        self.state = DashState()
        self.events: queue.Queue = queue.Queue()
        self.cancel = threading.Event()
        self.spawn = spawn or (lambda fn: threading.Thread(target=fn, daemon=True).start())
        self.finder, self.tls, self.probe, self.redraw = finder, tls, probe, redraw
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
        s.running, s.finished = False, time.monotonic()
        res = d["result"]
        if d.get("folder"):
            s.report = clean(d["folder"], 200)
        if res.cancelled:
            s.status = t("dash.status.cancelled")
            for ph in s.phases.values():
                if ph.state in ("run", "wait"):
                    ph.state, ph.note = "fail", t("dash.phase.stopped")
        elif not res.reached:
            outcome = next(iter(res.errors.values()), "net")
            s.status = t("g.tls") if outcome == "tls" else t("g.unreachable")
            if outcome == "tls":
                tg = d["target"]
                self.ask_trust(tg.url, changed=bool(tg.ca_file), then=lambda ca: self._retrust(tg.url, ca))
        else:
            s.status = t("dash.status.done", n=len(res.findings))
        s.log(s.status)
        if d.get("error"):
            s.status = t(d["error"])

    def _retrust(self, url: str, ca: str) -> None:
        add_target(self.scope_path, url, ca_file=ca)
        self.start_scan(url)

    # ------------------------------------------------------------ avvio analisi
    def start_scan(self, url: str) -> None:
        sc = self.scope()
        tg = next((x for x in sc.targets if x.url == url), None) if sc else None
        if tg is None or self.state.running:
            return
        phases = PROFILES[self.state.profile]
        one = dataclasses.replace(sc, targets=(tg,))
        self.cancel = threading.Event()
        self.state.reset_run(url, phases)
        self.state.status = ""
        out_dir, cancel, events = self.out_dir, self.cancel, self.events

        def work():
            client = SafeClient(one)
            res = run_scan(one, client, phases, emit=events.put, cancel=cancel)
            data = {"result": res, "target": tg}
            if res.reached:
                events.put(Event("phase", {"id": "report", "state": "start"}))
                events.put(Event("action", {"text": t("dash.act.report")}))
                extra = {"fingerprint": res.fingerprint, "services": res.services,
                         "sources": [{"name": k, "status": v} for k, v in res.sources.items()]}
                doc = rpt.build([tg.url], res.findings, client.requests_made, extra)
                try:
                    data["folder"] = rpt.save(doc, out_dir)
                    events.put(Event("phase", {"id": "report", "state": "done", "note": t("dash.note.saved")}))
                except rpt.ReportError as exc:
                    data["error"] = exc.code
                    events.put(Event("phase", {"id": "report", "state": "fail"}))
            events.put(Event("_done", data))
        self.spawn(work)

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
        if key in ("q", "Q"):
            if s.running:
                s.modal = Modal("confirm", t("dash.modal.quit"), [t("dash.quit.question")], on_yes=self.shutdown)
            else:
                self.quit = True
        elif key == "TAB":
            s.focus = (s.focus + 1) % 3
        elif key in ("1", "2", "4"):
            s.focus = {"1": 0, "2": 1, "4": 2}[key]
        elif key in ("UP", "k"):
            self._move(-1)
        elif key in ("DOWN", "j"):
            self._move(1)
        elif key == "ENTER":
            self._enter()
        elif key in ("s",) and not s.running and s.targets:
            self._enter(start=True)
        elif key == "x" and s.running:
            self.cancel.set()
            s.status = t("dash.stopping")
        elif key == "a" and not s.running:
            s.modal = Modal("input", t("dash.modal.url"), [t("g.url")], on_yes=lambda text: self.new_target(text))
        elif key == "p" and not s.running:
            s.profile = 1 - s.profile
        elif key == "d" and not s.running:
            self.start_discovery()
        elif key == "r":
            self.info(t("dash.modal.report"), [s.report or t("dash.report.none")])
        elif key == "?":
            self.info(t("dash.modal.guide"), t("dash.guide").split("|"))

    def _move(self, step: int) -> None:
        s = self.state
        if s.focus == 0 and s.targets:
            s.selected = max(0, min(len(s.targets) - 1, s.selected + step))
        elif s.focus == 2 and s.findings:
            s.finding_sel = max(0, min(len(s.findings) - 1, s.finding_sel + step))
        elif s.focus == 1:
            s.live_scroll = max(0, min(len(s.live) - 1, s.live_scroll - step))

    def _enter(self, start: bool = False) -> None:
        s = self.state
        if s.focus == 2 and s.findings and not start:
            f = s.findings[s.finding_sel]
            lines = [f"{t('table.element')}: {f.element}",
                     f"{t('table.risk')}: {f.impact} × {f.probability} = {f.risk} ({t('level.' + f.level)})",
                     f"{t('table.pt')}: {t('pt.' + f.pt)}", f"{t('table.source')}: {f.source} ({f.check})", "",
                     f"{t('table.evidence')}:", *[f"  • {e}" for e in f.evidence], "",
                     f"{t('table.remediation')}: {f.remediation}"]
            self.info(f.title, lines)
            return
        if s.running or not s.targets:
            return
        row = s.targets[s.selected]
        if row.authorized:
            self.start_scan(row.url)
        else:
            self.new_target(row.url, row.name)

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


def run(scope_path: str, out_dir: str) -> int:
    import curses
    import locale

    from apernix.dashboard.view import Glyphs, draw
    from apernix.term import use_color, use_unicode
    locale.setlocale(locale.LC_ALL, "")
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

        def paint_all():
            h, w = stdscr.getmaxyx()
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
                key = _key_name(ch, curses)
                if key:
                    ctrl.handle_key(key)
            except KeyboardInterrupt:
                ctrl.shutdown()
        return 0

    try:
        return curses.wrapper(main)
    except curses.error:
        return 2


def _key_name(ch, curses) -> str:
    if isinstance(ch, int):
        return {curses.KEY_UP: "UP", curses.KEY_DOWN: "DOWN", curses.KEY_ENTER: "ENTER",
                curses.KEY_BACKSPACE: "BACKSPACE", curses.KEY_BTAB: "TAB"}.get(ch, "")
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


class _CursesCanvas:
    def __init__(self, win, w, h, roles, curses, ascii_only=False) -> None:
        from apernix.dashboard.view import Canvas
        self._canvas = Canvas(w, h)
        self._canvas.put = self.put
        self.w, self.h = w, h
        self.win, self.roles, self.curses = win, roles, curses
        self.ascii_only = ascii_only

    def put(self, y, x, text, role="text") -> None:
        if self.ascii_only:
            text = to_ascii(text)
        try:
            self.win.addstr(y, x, text, self.roles.get(role, 0))
        except self.curses.error:
            pass      # l'ultima cella dello schermo dà sempre errore: si ignora

    def text(self, *a, **k):
        return self._canvas.text(*a, **k)

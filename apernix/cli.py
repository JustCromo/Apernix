"""Interfaccia a riga di comando di Apernix (stile Erinix).

Un solo comando `apernix`, due modi d'uso in questa versione:
  - comando che esegue ed esce:   apernix scan --scope scope.toml
  - console classica:             apernix console   (o apernix senza argomenti)
Codici di uscita: 0 = tutto ok, 1 = trovati problemi di rischio alto/critico, 2 = errore.
"""

from __future__ import annotations

import json
import shlex
import sys
import time
from dataclasses import dataclass, field

from apernix import __version__, engine
from apernix import report as rpt
from apernix.engine import PHASES, ScanResult, mmss
from apernix.guided import Guided, prompt_text
from apernix.i18n import t
from apernix.scope import Scope, ScopeError, load_scope
from apernix.term import clean, level_role, paint, symbol
from apernix.web.http import SafeClient

EXIT_OK, EXIT_FINDINGS, EXIT_ERROR = 0, 1, 2
DEFAULT_SCOPE = "scope.toml"
DEFAULT_OUT = "apernix-reports"


class CliError(Exception):
    def __init__(self, code: str, **params: object) -> None:
        super().__init__(code)
        self.code = code
        self.params = params


@dataclass
class Opts:
    scope: str = DEFAULT_SCOPE
    out: str = DEFAULT_OUT
    json: bool = False
    quick: bool = False
    only: tuple[str, ...] = PHASES
    fmt: str = "md"
    args: list[str] = field(default_factory=list)


def parse_opts(cmd: str, argv: list[str]) -> Opts:
    o = Opts()
    it = iter(argv)
    for a in it:
        if a == "--json":
            o.json = True
        elif a == "--quick":
            o.quick = True
        elif a == "--only":
            value = next(it, None) or ""
            chosen = tuple(p for p in PHASES if p in value.split(","))
            if not chosen or any(p not in PHASES for p in value.split(",")):
                raise CliError("err.usage", cmd=cmd)
            o.only = chosen
        elif a in ("--scope", "--out", "--format"):
            value = next(it, None)
            if value is None or value.startswith("--"):
                raise CliError("err.usage", cmd=cmd)
            if a == "--scope":
                o.scope = value
            elif a == "--out":
                o.out = value
            else:
                if value not in ("md", "json", "html"):
                    raise CliError("err.usage", cmd=cmd)
                o.fmt = value
        elif a.startswith("--"):
            raise CliError("err.usage", cmd=cmd)
        else:
            o.args.append(a)
    return o


def out(text: str = "") -> None:
    print(text)


def emit_json(obj: dict) -> None:
    print(json.dumps(obj, ensure_ascii=False, indent=2))


# ---------------------------------------------------------------- comandi

def cmd_help(o: Opts) -> int:
    if o.json:
        emit_json({"ok": True, "commands": {name: t(k) for name, (_, k) in COMMANDS.items()}})
        return EXIT_OK
    out(paint(f"APERNIX {__version__}", "brand") + f" — {t('app.tagline')}")
    out()
    out(t("help.title") + ":")
    for name, (_, key) in COMMANDS.items():
        out(f"  {name:<9} {t(key)}")
    out()
    out(t("help.options"))
    return EXIT_OK


def cmd_version(o: Opts) -> int:
    if o.json:
        emit_json({"ok": True, "version": __version__})
    else:
        out(f"Apernix {__version__}")
    return EXIT_OK


def _scope(o: Opts) -> Scope:
    try:
        return load_scope(o.scope)
    except ScopeError as exc:
        params = dict(exc.params)
        if "reason_key" in params:
            params["reason"] = t(params.pop("reason_key"), **params)
        raise CliError(exc.code, **params) from exc


def cmd_scope(o: Opts) -> int:
    sc = _scope(o)
    if o.json:
        emit_json({"ok": True, "targets": [{"url": x.url, "name": x.name} for x in sc.targets],
                   "limits": {"rate": sc.rate, "max_requests": sc.max_requests, "timeout": sc.timeout}})
        return EXIT_OK
    out(paint(f"{symbol('ok')} {t('scope.ok', n=len(sc.targets))}", "ok"))
    for x in sc.targets:
        label = f" ({clean(x.name, 64)})" if x.name else ""
        out(f"  {symbol('dot')} {clean(x.url)}{label}")
    return EXIT_OK


PHASE_KEYS = {"web": "scan.phase.web", "nuclei": "scan.phase.nuclei", "nmap": "scan.phase.nmap"}


class Ticker:
    """Riga di avanzamento per le fasi lunghe (solo su terminale vero)."""

    def __init__(self, enabled: bool) -> None:
        self.enabled = enabled and sys.stdout.isatty()
        self.active = False

    def __call__(self, elapsed: float, limit: float) -> None:
        if not self.enabled:
            return
        self.active = True
        text = t("scan.wait", elapsed=mmss(elapsed), limit=mmss(limit))
        sys.stdout.write("\r    " + paint(f"{symbol('dot')} {text}", "dim") + "   ")
        sys.stdout.flush()

    def done(self) -> None:
        if self.active:
            sys.stdout.write("\r\x1b[2K")
            sys.stdout.flush()
            self.active = False


def run_scan(sc: Scope, client: SafeClient, progress=lambda s: None, quick: bool = False,
             phases: tuple[str, ...] = PHASES, ticker: Ticker | None = None) -> ScanResult:
    """Analisi con uscita a righe (comando singolo e console a numeri)."""
    ticker = ticker or Ticker(False)

    def emit(ev) -> None:
        d = ev.data
        if ev.kind == "target":
            progress(t("scan.start", url=d["url"]))
        elif ev.kind == "phase" and d["state"] == "start" and d["id"] in PHASE_KEYS:
            progress(f"  {symbol('arrow')} {t(PHASE_KEYS[d['id']])}")
        elif ev.kind == "wait":
            ticker(d["elapsed"], d["limit"])
        elif ev.kind == "phase" and d["state"] in ("done", "fail"):
            ticker.done()
    return engine.run_scan(sc, client, ("web",) if quick else phases, emit)


def cmd_scan(o: Opts) -> int:
    sc = _scope(o)
    client = SafeClient(sc)
    progress = (lambda s: None) if o.json else (lambda s: out(paint(s, "info")))
    started = time.monotonic()
    res = run_scan(sc, client, progress, quick=o.quick, phases=o.only, ticker=Ticker(not o.json))
    if not res.reached:
        if "tls" in res.errors.values():
            raise CliError("err.tls")
        raise CliError("err.target_unreachable")
    try:
        doc, folder = save_scan(sc, client, res, o.out, profile_label(("web",) if o.quick else o.only),
                                time.monotonic() - started)
    except rpt.ReportError as exc:
        raise CliError(exc.code) from exc
    if o.json:
        emit_json(dict(doc, ok=True, saved=folder))
    else:
        show_scan(doc, folder)
    worst = any(f.level in ("high", "critical") for f in res.findings)
    return EXIT_FINDINGS if worst else EXIT_OK


def profile_label(phases) -> str:
    """Nome leggibile del profilo usato, per il report."""
    phases = tuple(phases)
    if phases == ("web",):
        return t("dash.profile.quick")
    if set(phases) == set(PHASES):
        return t("dash.profile.full")
    return t("html.profile.custom", phases=", ".join(phases))


def save_scan(sc: Scope, client: SafeClient, res: ScanResult, out_dir: str, profile: str = "",
              duration: float = 0.0) -> tuple[dict, str]:
    extra = {"fingerprint": res.fingerprint, "services": res.services,
             "sources": [{"name": k, "status": v} for k, v in res.sources.items()]}
    names = [x.name or x.host for x in sc.targets]
    meta = {"name": names[0] if len(names) == 1 else ", ".join(names)[:120], "profile": profile,
            "duration": mmss(duration) if duration else ""}
    doc = rpt.build([x.url for x in sc.targets], res.findings, client.requests_made, extra, meta)
    return doc, rpt.save(doc, out_dir)


def show_scan(doc: dict, folder: str) -> None:
    print_table(doc)
    out()
    for src in doc["sources"]:
        if src["status"] not in ("ok", "skipped"):
            out(paint(f"{symbol('warn')} " + t("scan.source_skipped", name=src["name"],
                                                 status=t("source." + src["status"])), "warn"))
    out(t("scan.done", n=len(doc["findings"])))
    out(paint(t("scan.saved", path=clean(folder)), "dim"))


def _line_editing() -> None:
    try:
        import readline  # noqa: F401  (frecce e cronologia nei prompt)
    except ImportError:
        pass


def cmd_dashboard(o: Opts) -> int:
    if not (sys.stdin.isatty() and sys.stdout.isatty()):
        raise CliError("err.no_tty")
    from apernix.dashboard.app import run
    return run(o.scope, o.out)


def cmd_menu(o: Opts) -> int:
    _line_editing()
    def runner(sc: Scope, client: SafeClient, phases: tuple[str, ...]):
        started = time.monotonic()
        res = run_scan(sc, client, lambda s: out(paint(s, "info")), phases=phases, ticker=Ticker(True))
        if not res.reached:
            return "tls" if "tls" in res.errors.values() else "net"
        try:
            doc, folder = save_scan(sc, client, res, o.out, profile_label(phases), time.monotonic() - started)
        except rpt.ReportError as exc:
            return exc
        show_scan(doc, folder)
        return "ok"

    return Guided(o.scope, o.out, runner=runner).run()


def print_table(doc: dict) -> None:
    if not doc["findings"]:
        out(paint(f"{symbol('ok')} {t('scan.none')}", "ok"))
        return
    out()
    out(paint(f"{t('table.risk'):>8}  {t('table.problem')}", "title"))
    for f in doc["findings"]:
        risk = f"{f['risk']:>2} {t('level.' + f['level']):<7}"
        out(f"{paint(risk, level_role(f['level']))}  {clean(f['title'], 90)}")
        out(paint(f"{'':>11}{clean(f['element'], 90)}", "dim"))


def cmd_report(o: Opts) -> int:
    if len(o.args) != 1:
        raise CliError("err.usage", cmd="report")
    try:
        doc = rpt.load(o.args[0])
    except rpt.ReportError as exc:
        raise CliError(exc.code) from exc
    if o.json or o.fmt == "json":
        emit_json(doc)
    elif o.fmt == "html":
        from apernix.report_html import to_html
        sys.stdout.write(to_html(doc) + "\n")
    else:
        sys.stdout.write(rpt.to_markdown(doc) + "\n")
    return EXIT_OK


def cmd_console(o: Opts) -> int:
    _line_editing()
    out(paint(f"APERNIX {__version__}", "brand") + " — " + t("console.welcome"))
    while True:
        try:
            line = input(_console_prompt())
        except EOFError:
            out()
            break
        except KeyboardInterrupt:
            out()
            continue
        try:
            parts = shlex.split(line)
        except ValueError:
            report_error(CliError("err.usage", cmd="console"), False)
            continue
        if not parts:
            continue
        if parts[0] in ("exit", "quit"):
            break
        if parts[0] in ("console", "menu", "dashboard"):
            continue
        dispatch(parts)
    out(t("console.bye"))
    return EXIT_OK


def _console_prompt() -> str:
    return prompt_text("apernix> ")


COMMANDS = {
    "help": (cmd_help, "cmd.help"),
    "version": (cmd_version, "cmd.version"),
    "scope": (cmd_scope, "cmd.scope"),
    "scan": (cmd_scan, "cmd.scan"),
    "report": (cmd_report, "cmd.report"),
    "console": (cmd_console, "cmd.console"),
    "menu": (cmd_menu, "cmd.menu"),
    "dashboard": (cmd_dashboard, "cmd.dashboard"),
}


def report_error(err: CliError, as_json: bool) -> None:
    if as_json:
        emit_json({"ok": False, "error": err.code})
        return
    params = {k: clean(v, 200) for k, v in err.params.items()}
    msg = t(err.code, **params)
    hint = t(err.code + ".hint")
    print(paint(f"{symbol('alert')} {t('err.prefix')}: {msg}", "alert"), file=sys.stderr)
    print(f"  {t('err.hint')}: {hint}", file=sys.stderr)


def dispatch(argv: list[str]) -> int:
    cmd, rest = argv[0], argv[1:]
    as_json = "--json" in rest
    entry = COMMANDS.get(cmd)
    if entry is None:
        report_error(CliError("err.unknown_command", cmd=cmd), as_json)
        return EXIT_ERROR
    try:
        return entry[0](parse_opts(cmd, rest))
    except CliError as err:
        report_error(err, as_json)
        return EXIT_ERROR
    except KeyboardInterrupt:
        report_error(CliError("err.interrupted"), as_json)
        return EXIT_ERROR


def main(argv: list[str] | None = None) -> int:
    argv = sys.argv[1:] if argv is None else argv
    if not argv:
        argv = ["dashboard"] if sys.stdin.isatty() and sys.stdout.isatty() else ["help"]
    if argv[0] in ("-h", "--help"):
        argv = ["help"] + argv[1:]
    if argv[0] in ("-V", "--version"):
        argv = ["version"] + argv[1:]
    try:
        return dispatch(argv)
    finally:
        sys.stdout.flush()

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
from dataclasses import dataclass, field

import requests

from apernix import __version__
from apernix import report as rpt
from apernix.i18n import t
from apernix.models import Finding
from apernix.scope import Scope, ScopeError, load_scope
from apernix.term import clean, level_role, paint, symbol
from apernix.web import checks
from apernix.web.http import BudgetExceeded, OutOfScope, SafeClient

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
    fmt: str = "md"
    args: list[str] = field(default_factory=list)


def parse_opts(cmd: str, argv: list[str]) -> Opts:
    o = Opts()
    it = iter(argv)
    for a in it:
        if a == "--json":
            o.json = True
        elif a in ("--scope", "--out", "--format"):
            value = next(it, None)
            if value is None or value.startswith("--"):
                raise CliError("err.usage", cmd=cmd)
            if a == "--scope":
                o.scope = value
            elif a == "--out":
                o.out = value
            else:
                if value not in ("md", "json"):
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
    out(paint(f"Apernix {__version__} — {t('app.tagline')}", "title"))
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


def run_scan(sc: Scope, client: SafeClient, progress=lambda s: None) -> tuple[list[Finding], list[str]]:
    findings: list[Finding] = []
    reached: list[str] = []
    for tg in sc.targets:
        progress(t("scan.start", url=tg.url))
        progress(f"  {symbol('arrow')} {t('scan.phase.web')}")
        try:
            resp = client.get(tg.url)
        except (requests.RequestException, OutOfScope, BudgetExceeded):
            continue
        reached.append(tg.url)
        findings.extend(checks.run_passive(resp))
    return findings, reached


def cmd_scan(o: Opts) -> int:
    sc = _scope(o)
    client = SafeClient(sc)
    progress = (lambda s: None) if o.json else (lambda s: out(paint(s, "info")))
    findings, reached = run_scan(sc, client, progress)
    if not reached:
        raise CliError("err.target_unreachable")
    doc = rpt.build([x.url for x in sc.targets], findings, client.requests_made)
    try:
        folder = rpt.save(doc, o.out)
    except rpt.ReportError as exc:
        raise CliError(exc.code) from exc
    worst = any(f.level in ("high", "critical") for f in findings)
    if o.json:
        doc = dict(doc, ok=True, saved=folder)
        emit_json(doc)
    else:
        print_table(doc)
        out()
        out(t("scan.done", n=len(findings)))
        out(paint(t("scan.saved", path=clean(folder)), "dim"))
    return EXIT_FINDINGS if worst else EXIT_OK


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
    else:
        sys.stdout.write(rpt.to_markdown(doc) + "\n")
    return EXIT_OK


def cmd_console(o: Opts) -> int:
    out(paint(f"Apernix {__version__}", "title") + " — " + t("console.welcome"))
    while True:
        try:
            line = input(paint("apernix> ", "info"))
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
        if parts[0] == "console":
            continue
        dispatch(parts)
    out(t("console.bye"))
    return EXIT_OK


COMMANDS = {
    "help": (cmd_help, "cmd.help"),
    "version": (cmd_version, "cmd.version"),
    "scope": (cmd_scope, "cmd.scope"),
    "scan": (cmd_scan, "cmd.scan"),
    "report": (cmd_report, "cmd.report"),
    "console": (cmd_console, "cmd.console"),
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
        argv = ["console"] if sys.stdin.isatty() else ["help"]
    if argv[0] in ("-h", "--help"):
        argv = ["help"] + argv[1:]
    if argv[0] in ("-V", "--version"):
        argv = ["version"] + argv[1:]
    try:
        return dispatch(argv)
    finally:
        sys.stdout.flush()

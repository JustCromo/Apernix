"""Controlli sui log dei container: errori con dettagli interni, segreti scritti nei log, tentativi di accesso."""

from __future__ import annotations

import re

from apernix.i18n import t
from apernix.inside.transport import Transport
from apernix.models import Finding

SOURCE = "logs"
TAIL = 500
_TRACE = re.compile(r"Traceback \(most recent call last\)|\bpanic:|Unhandled ?[Ee]xception|\bat [\w.$]+\([\w.]+:\d+\)")
_SECRET = re.compile(r"(?i)\b(password|passwd|secret|token|api[_-]?key|authorization)\b\s*[=:]\s*(?!\*{3}|\[|<)\S{4,}")
_FAIL = re.compile(r"(?i)(failed (login|password|authentication)|invalid (password|credentials)|authentication failed|"
                   r"login failed|accesso negato)")
FAIL_THRESHOLD = 10


def _f(check: str, element: str, impact: int, prob: int, evidence: list[str]) -> Finding:
    return Finding(check=check, title=t(f"{check}.title"), element=element, impact=impact, probability=prob,
                   source=SOURCE, evidence=evidence, pt="confirmed", remediation=t(f"{check}.fix"))


def analyze(name: str, text: str) -> list[Finding]:
    lines = text.splitlines()[-TAIL:]
    trace = [i + 1 for i, ln in enumerate(lines) if _TRACE.search(ln)]
    secret = [i + 1 for i, ln in enumerate(lines) if _SECRET.search(ln)]
    fails = [i + 1 for i, ln in enumerate(lines) if _FAIL.search(ln)]
    out: list[Finding] = []
    if secret:      # solo i numeri di riga: i valori restano fuori dal report
        ev = [t("ev.log.secrets", n=len(secret), lines=", ".join(map(str, secret[:5]))), t("SEC.value_hidden")]
        out.append(_f("LOG-SECRETS", name, 4, 3, ev))
    if trace:
        ev = [t("ev.log.traces", n=len(trace), lines=", ".join(map(str, trace[:5])))]
        out.append(_f("LOG-TRACES", name, 2, 3, ev))
    if len(fails) >= FAIL_THRESHOLD:
        out.append(_f("LOG-AUTHFAIL", name, 3, 3, [t("ev.log.authfail", n=len(fails), last=TAIL)]))
    return out


def run(tr: Transport, names: tuple[str, ...]):
    """Restituisce (problemi, motivo dell'errore o '')."""
    out: list[Finding] = []
    seen_any = False
    for name in names:
        res = tr.run(["docker", "logs", "--tail", str(TAIL), name], timeout=30, merge_stderr=True)
        if not res.ok:
            continue
        seen_any = True
        out += analyze(name, res.output.decode("utf-8", "replace"))
    return out, ("" if seen_any or not names else "failed")

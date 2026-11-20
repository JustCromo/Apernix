"""Fonte per l'analisi interna: trivy. Dipendenze vulnerabili, segreti nel codice, configurazioni sbagliate.

I valori dei segreti NON vengono mai copiati nel report: solo la regola e il punto in cui sono.
"""

from __future__ import annotations

import json

from apernix.i18n import t
from apernix.models import Finding
from apernix.sources.semgrep import _s
from apernix.tools import ToolResult, run_tool

SOURCE = "trivy"
MAX_DEPS = 60
MAX_OTHER = 60
SEVERITY = {"CRITICAL": (5, 4), "HIGH": (4, 3), "MEDIUM": (3, 3), "LOW": (2, 2)}
ORDER = ("CRITICAL", "HIGH", "MEDIUM", "LOW")


def scan(src: str, max_time: float = 600, tick=None) -> ToolResult:
    argv = ["trivy", "fs", "--format", "json", "--scanners", "vuln,secret,misconfig", "--quiet",
            "--skip-dirs", "node_modules,.git,.venv,venv", src]
    return run_tool(argv, lambda path: ["--output", path], max_time, tick)


def _list(value: object) -> list:
    return value if isinstance(value, list) else []


def parse(data: bytes) -> list[Finding]:
    try:
        doc = json.loads(data)
    except (json.JSONDecodeError, UnicodeDecodeError, RecursionError):
        raise ValueError("json") from None
    if not isinstance(doc, dict):
        raise ValueError("json") from None
    deps: list[Finding] = []
    other: list[Finding] = []
    for res in _list(doc.get("Results")):
        if not isinstance(res, dict):
            continue
        target = _s(res.get("Target"), 200)
        for v in _list(res.get("Vulnerabilities")):
            if not isinstance(v, dict):
                continue
            sev = _s(v.get("Severity")).upper()
            if sev not in SEVERITY:
                continue
            vid, pkg = _s(v.get("VulnerabilityID"), 40), _s(v.get("PkgName"), 80)
            ver = _s(v.get("InstalledVersion"), 40)
            fixed = _s(v.get("FixedVersion"), 60)
            impact, prob = SEVERITY[sev]
            ev = [f"{vid} ({sev.lower()})", f"{pkg} {ver} in {target}"]
            ev.append(f"corretta in: {fixed}" if fixed else "nessuna versione corretta disponibile")
            deps.append(Finding(
                check=f"DEP-{vid}"[:64], title=f"{pkg} {ver}: {_s(v.get('Title'), 120) or vid}",
                element=f"{pkg} {ver}", impact=impact, probability=prob, source=SOURCE,
                evidence=ev, pt="not_applicable",
                remediation=t("DEP.fix_to", version=fixed) if fixed else t("DEP.fix"),
            ))
        for m in _list(res.get("Misconfigurations")):
            if not isinstance(m, dict):
                continue
            sev = _s(m.get("Severity")).upper()
            if sev not in SEVERITY or _s(m.get("Status")).upper() == "PASS":
                continue
            impact, prob = SEVERITY[sev]
            other.append(Finding(
                check=f"CFG-{_s(m.get('ID'), 40)}"[:64], title=_s(m.get("Title"), 200) or "?", element=target,
                impact=impact, probability=prob, source=SOURCE,
                evidence=[_s(m.get("Message"), 250) or _s(m.get("ID"), 40), f"file: {target}"],
                pt="not_applicable", remediation=_s(m.get("Resolution"), 400) or t("CFG.fix"),
            ))
        for sc in _list(res.get("Secrets")):
            if not isinstance(sc, dict):
                continue
            where = f"{target}:{_s(sc.get('StartLine'), 8)}"
            other.append(Finding(
                check=f"SEC-{_s(sc.get('RuleID'), 40)}"[:64], title=_s(sc.get("Title"), 120) or t("SEC.title"),
                element=where, impact=5, probability=4, source=SOURCE,
                evidence=[f"regola {_s(sc.get('RuleID'), 40)}", f"file: {where}", t("SEC.value_hidden")],
                pt="not_applicable", remediation=t("SEC.fix"),
            ))
    key = lambda f: -f.risk                                              # noqa: E731
    return sorted(deps, key=key)[:MAX_DEPS] + sorted(other, key=key)[:MAX_OTHER]

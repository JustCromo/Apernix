"""Fonte per l'analisi interna: semgrep. Analisi statica del codice sorgente (regole pubbliche)."""

from __future__ import annotations

import json
import os

from apernix.i18n import t
from apernix.models import Finding
from apernix.sources.filters import is_audit_rule, is_dev_path, uses_django
from apernix.tools import ToolResult, run_tool

SOURCE = "semgrep"
MAX_FINDINGS = 100
SEVERITY = {"ERROR": (4, 3), "WARNING": (3, 3), "INFO": (2, 2)}


EXCLUDE = ("tests", "test", "test_*.py", "*_test.py", "node_modules", ".venv", "venv", "migrations")
MAX_LOCATIONS = 8


def build_argv(src: str) -> list[str]:
    # p/default = regole pubbliche per i problemi di sicurezza più comuni; metriche spente (nessun dato inviato).
    argv = ["semgrep", "scan", "--config", "p/default", "--metrics", "off", "--json", "--quiet",
            "--timeout", "30", "--max-target-bytes", "1000000"]
    for pattern in EXCLUDE:
        argv += ["--exclude", pattern]
    return [*argv, src]


def scan(src: str, max_time: float = 600, tick=None) -> ToolResult:
    return run_tool(build_argv(src), lambda path: ["--output", path], max_time, tick)


def _s(value: object, limit: int = 300) -> str:
    return str(value)[:limit] if isinstance(value, (str, int, float)) else ""


def rel(path: str, src: str) -> str:
    try:
        return os.path.relpath(path, src) if os.path.isabs(path) else path
    except ValueError:
        return path


def first_sentence(text: str, limit: int = 140) -> str:
    cut = text.replace("\n", " ").strip()
    end = cut.find(". ")
    if 0 < end < limit:
        return cut[:end + 1]
    return cut[:limit]


def group(entries: list[dict], source: str) -> list[Finding]:
    """Un solo problema per regola, con l'elenco dei punti: 60 ripetizioni sono un problema, non 60.

    Ogni voce: {check, title, where, impact, prob, rule}."""
    groups: dict[str, list[dict]] = {}
    for e in entries:
        groups.setdefault(e["check"], []).append(e)
    out: list[Finding] = []
    for check, items in groups.items():
        items = list({e["where"]: e for e in items}.values())
        first = items[0]
        extra = len(items) - 1
        element = first["where"] + (f" (+{extra} altri punti)" if extra else "")
        evidence = [first["rule"]] + [f"file: {e['where']}" for e in items[:MAX_LOCATIONS]]
        if len(items) > MAX_LOCATIONS:
            evidence.append(f"... e altri {len(items) - MAX_LOCATIONS} punti")
        out.append(Finding(
            check=check, title=first["title"], element=element,
            impact=max(e["impact"] for e in items), probability=max(e["prob"] for e in items), source=source,
            evidence=evidence, pt="not_tested", remediation=t("SAST.fix")))
    out.sort(key=lambda f: -f.risk)
    return out[:MAX_FINDINGS]


def parse(data: bytes, src: str) -> list[Finding]:
    try:
        doc = json.loads(data)
    except (json.JSONDecodeError, UnicodeDecodeError, RecursionError):
        raise ValueError("json") from None
    results = doc.get("results") if isinstance(doc, dict) else None
    if not isinstance(results, list):
        raise ValueError("json")
    entries = []
    django = uses_django(src)
    for item in results[:5000]:
        if not isinstance(item, dict):
            continue
        extra = item.get("extra") if isinstance(item.get("extra"), dict) else {}
        meta = extra.get("metadata") if isinstance(extra.get("metadata"), dict) else {}
        category = _s(meta.get("category")).lower()
        if category and category != "security":          # performance, stile, ecc.: non sono problemi di sicurezza
            continue
        start = item.get("start") if isinstance(item.get("start"), dict) else {}
        rule = _s(item.get("check_id"), 200).split(".")[-1]
        path = rel(_s(item.get("path"), 300), src)
        if not rule or not path or is_dev_path(path):
            continue
        check_id = _s(item.get("check_id"), 200)
        if ".django." in check_id and not django:         # regole Django su un'app che non usa Django: falso allarme
            continue
        impact, prob = SEVERITY.get(_s(extra.get("severity")).upper(), (2, 2))
        note = ""
        if is_audit_rule(check_id):                       # segnale da verificare, non vulnerabilità confermata
            impact, prob, note = min(impact, 3), min(prob, 2), " (segnale da verificare a mano)"
        entries.append({"check": f"SAST-{rule}"[:64], "title": first_sentence(_s(extra.get("message"), 400)) or rule,
                        "where": f"{path}:{_s(start.get('line'), 8)}", "impact": impact, "prob": prob,
                        "rule": f"regola {_s(item.get('check_id'), 150)}{note}"})
    return group(entries, SOURCE)

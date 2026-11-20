"""Fonte per l'analisi interna: semgrep. Analisi statica del codice sorgente (regole pubbliche)."""

from __future__ import annotations

import json
import os

from apernix.i18n import t
from apernix.models import Finding
from apernix.tools import ToolResult, run_tool

SOURCE = "semgrep"
MAX_FINDINGS = 100
SEVERITY = {"ERROR": (4, 3), "WARNING": (3, 3), "INFO": (2, 2)}


def build_argv(src: str) -> list[str]:
    # p/default = regole pubbliche per i problemi di sicurezza più comuni; metriche spente (nessun dato inviato).
    return ["semgrep", "scan", "--config", "p/default", "--metrics", "off", "--json", "--quiet",
            "--timeout", "30", "--max-target-bytes", "1000000", src]


def scan(src: str, max_time: float = 600, tick=None) -> ToolResult:
    return run_tool(build_argv(src), lambda path: ["--output", path], max_time, tick)


def _s(value: object, limit: int = 300) -> str:
    return str(value)[:limit] if isinstance(value, (str, int, float)) else ""


def rel(path: str, src: str) -> str:
    try:
        return os.path.relpath(path, src) if os.path.isabs(path) else path
    except ValueError:
        return path


def parse(data: bytes, src: str) -> list[Finding]:
    try:
        doc = json.loads(data)
    except (json.JSONDecodeError, UnicodeDecodeError, RecursionError):
        raise ValueError("json") from None
    results = doc.get("results") if isinstance(doc, dict) else None
    if not isinstance(results, list):
        raise ValueError("json") from None
    out: list[Finding] = []
    seen: set[tuple[str, str]] = set()
    for item in results:
        if not isinstance(item, dict):
            continue
        extra = item.get("extra") if isinstance(item.get("extra"), dict) else {}
        start = item.get("start") if isinstance(item.get("start"), dict) else {}
        rule = _s(item.get("check_id"), 200).split(".")[-1]
        path = rel(_s(item.get("path"), 300), src)
        if not rule or not path:
            continue
        where = f"{path}:{_s(start.get('line'), 8)}"
        if (rule, where) in seen:
            continue
        seen.add((rule, where))
        impact, prob = SEVERITY.get(_s(extra.get("severity")).upper(), (2, 2))
        out.append(Finding(
            check=f"SAST-{rule}"[:64], title=_s(extra.get("message"), 200) or rule, element=where,
            impact=impact, probability=prob, source=SOURCE,
            evidence=[f"regola {_s(item.get('check_id'), 150)}", f"file: {where}"],
            pt="not_applicable", remediation=t("SAST.fix"),
        ))
        if len(out) >= MAX_FINDINGS:
            break
    return out

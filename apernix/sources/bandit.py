"""Fonte per l'analisi interna: bandit. Analisi statica di sicurezza per il codice Python."""

from __future__ import annotations

import json

from apernix.i18n import t
from apernix.models import Finding
from apernix.sources.semgrep import _s, rel
from apernix.tools import ToolResult, run_tool

SOURCE = "bandit"
MAX_FINDINGS = 100
LEVEL = {"HIGH": 4, "MEDIUM": 3, "LOW": 2}


def scan(src: str, max_time: float = 300, tick=None) -> ToolResult:
    argv = ["bandit", "-r", src, "-f", "json", "-q", "-x", ".git,node_modules,.venv,venv"]
    return run_tool(argv, lambda path: ["-o", path], max_time, tick)


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
        tid = _s(item.get("test_id"), 12) or "B000"
        where = f"{rel(_s(item.get('filename'), 300), src)}:{_s(item.get('line_number'), 8)}"
        if (tid, where) in seen:
            continue
        seen.add((tid, where))
        impact = LEVEL.get(_s(item.get("issue_severity")).upper(), 2)
        prob = LEVEL.get(_s(item.get("issue_confidence")).upper(), 2)
        out.append(Finding(
            check=f"SAST-{tid}", title=_s(item.get("issue_text"), 200) or tid, element=where,
            impact=impact, probability=prob, source=SOURCE,
            evidence=[f"test bandit {tid} ({_s(item.get('test_name'), 60)})", f"file: {where}"],
            pt="not_applicable", remediation=t("SAST.fix"),
        ))
        if len(out) >= MAX_FINDINGS:
            break
    return out

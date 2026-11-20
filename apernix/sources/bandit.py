"""Fonte per l'analisi interna: bandit. Analisi statica di sicurezza per il codice Python."""

from __future__ import annotations

import json

from apernix.models import Finding
from apernix.sources.filters import is_dev_path
from apernix.sources.semgrep import _s, group, rel
from apernix.tools import ToolResult, run_tool

SOURCE = "bandit"
MAX_FINDINGS = 100
LEVEL = {"HIGH": 4, "MEDIUM": 3, "LOW": 2}


def scan(src: str, max_time: float = 300, tick=None) -> ToolResult:
    skip = "*/.git/*,*/node_modules/*,*/.venv/*,*/venv/*,*/tests/*,*/test/*,*/migrations/*,*/test_*.py,*_test.py"
    argv = ["bandit", "-r", src, "-f", "json", "-q", "-x", skip, "-s", "B101"]    # B101 = assert: solo rumore
    return run_tool(argv, lambda path: ["-o", path], max_time, tick)


def parse(data: bytes, src: str) -> list[Finding]:
    try:
        doc = json.loads(data)
    except (json.JSONDecodeError, UnicodeDecodeError, RecursionError):
        raise ValueError("json") from None
    results = doc.get("results") if isinstance(doc, dict) else None
    if not isinstance(results, list):
        raise ValueError("json") from None
    entries = []
    for item in results[:5000]:
        if not isinstance(item, dict):
            continue
        tid = _s(item.get("test_id"), 12) or "B000"
        path = rel(_s(item.get("filename"), 300), src)
        if is_dev_path(path):
            continue
        where = f"{path}:{_s(item.get('line_number'), 8)}"
        impact = LEVEL.get(_s(item.get("issue_severity")).upper(), 2)
        prob = LEVEL.get(_s(item.get("issue_confidence")).upper(), 2)
        name = _s(item.get("test_name"), 60)
        note, signal = "", name.startswith("blacklist")
        if signal:                                        # elenco di funzioni "da guardare", non una falla certa
            impact, prob, note = min(impact, 3), min(prob, 2), " - segnale da verificare a mano"
        entries.append({
            "check": f"SAST-{tid}", "title": _s(item.get("issue_text"), 200) or tid, "where": where,
            "impact": impact, "prob": prob, "signal": signal,
            "rule": f"test bandit {tid} ({name}){note}"})
    return group(entries, SOURCE)

"""Fonte esterna: nuclei. Cerca vulnerabilità note tramite template (firme) pubblici."""

from __future__ import annotations

import json

from apernix.i18n import t
from apernix.models import Finding
from apernix.tools import ToolResult, run_tool

SOURCE = "nuclei"
MAX_LINES = 5000
# Impatto e probabilità di partenza in base alla gravità dichiarata dal template.
SEVERITY = {"critical": (5, 4), "high": (4, 4), "medium": (3, 3), "low": (2, 2)}


def build_argv(url: str, rate: float, timeout: float) -> list[str]:
    return [
        "nuclei", "-u", url, "-jsonl", "-silent", "-nc",
        "-duc",                                  # niente controllo aggiornamenti durante la scansione
        "-ni",                                   # niente interactsh: nessun dato verso server esterni
        "-as",                                   # scansione automatica: prima riconosce le tecnologie,
                                                 # poi usa solo i template che le riguardano
        "-etags", "dos,fuzz,intrusive",          # esclude template distruttivi o aggressivi
        "-rl", str(max(1, int(rate))),
        "-timeout", str(max(1, int(timeout))),
    ]


def scan(url: str, rate: float, timeout: float, max_time: float = 900, tick=None) -> ToolResult:
    return run_tool(build_argv(url, rate, timeout), lambda path: ["-o", path], max_time, tick)


def _s(value: object, limit: int = 200) -> str:
    return str(value)[:limit] if isinstance(value, (str, int, float)) else ""


def parse(data: bytes) -> tuple[list[Finding], list[str]]:
    """Restituisce (problemi, tecnologie rilevate dai template informativi)."""
    found: list[Finding] = []
    tech: list[str] = []
    seen: set[tuple[str, str]] = set()
    for i, line in enumerate(data.splitlines()):
        if i >= MAX_LINES:
            break
        try:
            item = json.loads(line)
        except (json.JSONDecodeError, UnicodeDecodeError, RecursionError):
            continue
        if not isinstance(item, dict):
            continue
        info = item.get("info") if isinstance(item.get("info"), dict) else {}
        sev = _s(info.get("severity")).lower()
        tid = _s(item.get("template-id"), 100) or "unknown"
        name = _s(info.get("name")) or tid
        where = _s(item.get("matched-at"), 300) or _s(item.get("host"), 300)
        if sev not in SEVERITY:
            matcher = _s(item.get("matcher-name"), 64)
            label = f"{name}: {matcher}" if matcher else name
            if label not in tech and len(tech) < 50:
                tech.append(label)
            continue
        if (tid, where) in seen:
            continue
        seen.add((tid, where))
        impact, prob = SEVERITY[sev]
        evidence = [f"template {tid} ({sev})", f"matched-at: {where}"]
        cls = info.get("classification") if isinstance(info.get("classification"), dict) else {}
        cves = cls.get("cve-id")
        if isinstance(cves, list):
            evidence.append("CVE: " + ", ".join(_s(c, 20) for c in cves[:5]))
        extracted = item.get("extracted-results")
        if isinstance(extracted, list) and extracted:
            evidence.append("estratto: " + ", ".join(_s(x, 80) for x in extracted[:3]))
        found.append(Finding(
            check=f"NUC-{tid}"[:64], title=name, element=where or "?", impact=impact, probability=prob,
            source=SOURCE, evidence=evidence, remediation=t("NUC.fix"),
            pt="confirmed",       # il template ha trovato la risposta attesa nella risposta del sito
        ))
    return found, tech

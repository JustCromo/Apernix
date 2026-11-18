"""Report: JSON stabile (per altri tool e per la suite) e Markdown leggibile."""

from __future__ import annotations

import json
import os
from datetime import datetime, timezone

from apernix import __version__
from apernix.i18n import t
from apernix.models import LEVELS, Finding
from apernix.term import clean

SCHEMA = "apernix-report/1"
MAX_REPORT_BYTES = 20 * 1024 * 1024
MAX_FINDINGS = 5000


class ReportError(Exception):
    def __init__(self, code: str) -> None:
        super().__init__(code)
        self.code = code


def _tree(value: object, depth: int = 0) -> object:
    """Copia ripulita di dati annidati non fidati: solo str/int/bool/list/dict, con limiti fissi."""
    if depth > 4:
        return None
    if isinstance(value, bool) or (isinstance(value, int) and -10**9 < value < 10**9):
        return value
    if isinstance(value, str):
        return clean(value, 300)
    if isinstance(value, list):
        return [x for x in (_tree(v, depth + 1) for v in value[:200]) if x is not None]
    if isinstance(value, dict):
        return {clean(k, 64): v for k, v in ((k, _tree(v, depth + 1)) for k, v in list(value.items())[:100])
                if isinstance(k, str) and v is not None}
    return None


def build(targets: list[str], findings: list[Finding], requests_made: int = 0, extra: dict | None = None) -> dict:
    ordered = sorted(findings, key=lambda f: (-f.risk, f.check, f.element))
    summary = {lvl: 0 for lvl in LEVELS}
    for f in ordered:
        summary[f.level] += 1
    return {
        "schema": SCHEMA,
        "tool": "apernix",
        "version": __version__,
        "generated": datetime.now(timezone.utc).replace(microsecond=0).isoformat(),
        "targets": list(targets),
        "requests": requests_made,
        "summary": summary,
        "fingerprint": _tree((extra or {}).get("fingerprint", [])),
        "services": _tree((extra or {}).get("services", {})),
        "sources": _tree((extra or {}).get("sources", [])),
        "findings": [f.to_dict() for f in ordered],
    }


def load(path: str) -> dict:
    """Legge un report.json trattandolo come dato non fidato."""
    try:
        st = os.stat(path)
    except OSError as exc:
        raise ReportError("err.report_missing") from exc
    if st.st_size > MAX_REPORT_BYTES:
        raise ReportError("err.report_invalid")
    try:
        with open(path, encoding="utf-8") as fh:
            doc = json.loads(fh.read(MAX_REPORT_BYTES + 1))
    except (OSError, UnicodeDecodeError, json.JSONDecodeError, RecursionError) as exc:
        raise ReportError("err.report_invalid") from exc
    if not isinstance(doc, dict) or doc.get("schema") != SCHEMA:
        raise ReportError("err.report_invalid")
    raw = doc.get("findings")
    targets = doc.get("targets")
    if not isinstance(raw, list) or len(raw) > MAX_FINDINGS or not isinstance(targets, list):
        raise ReportError("err.report_invalid")
    try:
        findings = [Finding.from_dict(x) for x in raw]
    except (ValueError, TypeError) as exc:
        raise ReportError("err.report_invalid") from exc
    clean_targets = [str(x)[:2048] for x in targets if isinstance(x, str)][:64]
    extra = {k: doc.get(k) for k in ("fingerprint", "services", "sources")}
    extra = {k: v for k, v in extra.items() if isinstance(v, (list, dict))}
    rebuilt = build(clean_targets, findings, 0, extra)
    gen = doc.get("generated")
    if isinstance(gen, str) and len(gen) <= 40:
        rebuilt["generated"] = gen
    req = doc.get("requests")
    if isinstance(req, int) and not isinstance(req, bool) and 0 <= req <= 10**7:
        rebuilt["requests"] = req
    return rebuilt


def _md(text: object) -> str:
    """Testo sicuro dentro una tabella Markdown (anche se GitHub la mostra come HTML)."""
    s = str(text)
    for a, b in (("&", "&amp;"), ("<", "&lt;"), (">", "&gt;"), ("|", "\\|"), ("`", "\\`"),
                 ("[", "\\["), ("]", "\\]"), ("*", "\\*"), ("_", "\\_")):
        s = s.replace(a, b)
    return s.replace("\r", " ").replace("\n", "<br>")


def to_markdown(doc: dict) -> str:
    lines = [f"# {t('report.title')}", "",
             t("report.generated", when=_md(doc["generated"]), version=_md(doc["version"])), "",
             f"## {t('report.targets')}", ""]
    lines += [f"- {_md(x)}" for x in doc["targets"]]
    lines += ["", f"## {t('report.summary')}", "", t("report.formula"), ""]
    lines += [f"| {t('table.risk')} | # |", "|---|---|"]
    lines += [f"| {t('level.' + lvl)} | {doc['summary'][lvl]} |" for lvl in reversed(LEVELS)]
    lines += _context_md(doc)
    lines += ["", f"## {t('report.findings')}", ""]
    if not doc["findings"]:
        lines += [t("report.none"), ""]
        return "\n".join(lines)
    head = ["#", "table.element", "table.problem", "table.evidence", "table.pt",
            "table.impact", "table.probability", "table.risk", "table.source"]
    lines.append("| " + " | ".join(h if h == "#" else t(h) for h in head) + " |")
    lines.append("|" + "---|" * len(head))
    for i, f in enumerate(doc["findings"], 1):
        ev = "<br>".join(_md(e) for e in f["evidence"])
        risk = f"**{f['risk']}** ({t('level.' + f['level'])})"
        lines.append("| " + " | ".join([
            str(i), _md(f["element"]), f"{_md(f['title'])} ({_md(f['check'])})", ev,
            t("pt." + f["pt"]), str(f["impact"]), str(f["probability"]), risk, _md(f["source"]),
        ]) + " |")
    lines += ["", f"## {t('report.details')}", ""]
    for i, f in enumerate(doc["findings"], 1):
        lines += [f"### {i}. {_md(f['title'])}", "",
                  f"- **{t('table.element')}:** {_md(f['element'])}",
                  f"- **{t('table.risk')}:** {f['impact']} × {f['probability']} = {f['risk']}"
                  f" ({t('level.' + f['level'])})",
                  f"- **{t('table.remediation')}:** {_md(f['remediation'])}", ""]
    return "\n".join(lines)


def _context_md(doc: dict) -> list[str]:
    lines: list[str] = []
    fps = [x for x in doc.get("fingerprint", []) if isinstance(x, dict)]
    if fps:
        lines += ["", f"## {t('report.fingerprint')}", ""]
        for fp in fps:
            tech = ", ".join(_md(x) for x in fp.get("technologies", []) if isinstance(x, str)) or "-"
            lines.append(f"- {_md(fp.get('url', ''))}: {tech}")
    services = doc.get("services", {})
    if isinstance(services, dict) and services:
        lines += ["", f"## {t('report.services')}", ""]
        for host, items in services.items():
            if isinstance(items, list):
                text = "; ".join(_md(x) for x in items if isinstance(x, str)) or t("report.no_ports")
                lines.append(f"- **{_md(host)}**: {text}")
    sources = [x for x in doc.get("sources", []) if isinstance(x, dict)]
    if sources:
        lines += ["", f"## {t('report.sources')}", ""]
        for src in sources:
            status = src.get("status", "")
            label = t("source." + status) if isinstance(status, str) and status.replace("_", "").isalpha() else "?"
            lines.append(f"- {_md(src.get('name', '?'))}: {_md(label)}")
    return lines


def _write_private(path: str, text: str) -> None:
    flags = os.O_WRONLY | os.O_CREAT | os.O_TRUNC | getattr(os, "O_NOFOLLOW", 0)
    fd = os.open(path, flags, 0o600)
    with os.fdopen(fd, "w", encoding="utf-8") as fh:
        fh.write(text)


def save(doc: dict, out_dir: str) -> str:
    """Salva report.json e report.md in una sottocartella privata (0700, file 0600)."""
    stamp = datetime.now().strftime("%Y%m%d-%H%M%S")
    try:
        os.makedirs(out_dir, mode=0o700, exist_ok=True)
        folder = os.path.join(out_dir, stamp)
        n = 1
        while os.path.exists(folder):
            n += 1
            folder = os.path.join(out_dir, f"{stamp}-{n}")
        os.mkdir(folder, 0o700)
        _write_private(os.path.join(folder, "report.json"), json.dumps(doc, ensure_ascii=False, indent=2))
        _write_private(os.path.join(folder, "report.md"), to_markdown(doc))
    except OSError as exc:
        raise ReportError("err.output_dir") from exc
    return folder

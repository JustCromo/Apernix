"""Filtri comuni per l'analisi del codice: meno rumore, più problemi veri.

Un report con 60 falsi allarmi nasconde i 3 problemi reali. Qui si scartano i segnali che non riguardano
l'applicazione in produzione (script di sviluppo) o il suo framework (regole Django su un'app Flask).
"""

from __future__ import annotations

import os
import re

# Cartelle di primo livello che contengono strumenti di sviluppo, non l'applicazione in produzione.
DEV_DIRS = frozenset({"tools", "scripts", "script", "docs", "doc", "examples", "example", "samples",
                      "demo", "fixtures", "build", "dist", "vendor", "benchmarks"})
_MANIFESTS = ("requirements.txt", "requirements-prod.txt", "pyproject.toml", "Pipfile", "setup.py", "manage.py")


def is_dev_path(path: str) -> bool:
    parts = [p for p in path.replace("\\", "/").split("/") if p and p != "."]
    return len(parts) > 1 and parts[0].lower() in DEV_DIRS


def uses_django(src: str, max_depth: int = 3) -> bool:
    """True se il progetto dichiara Django (manage.py o dipendenza): altrimenti le sue regole sono falsi allarmi."""
    base = os.path.abspath(src)
    for root, dirs, files in os.walk(base):
        depth = root[len(base):].count(os.sep)
        dirs[:] = [d for d in dirs if not d.startswith(".") and d not in ("node_modules", "venv", ".venv")]
        if depth >= max_depth:
            dirs[:] = []
        for name in files:
            if name == "manage.py":
                return True
            if name in _MANIFESTS or (name.startswith("requirements") and name.endswith(".txt")):
                try:
                    with open(os.path.join(root, name), "rb") as fh:
                        if b"django" in fh.read(200_000).lower():
                            return True
                except OSError:
                    continue
    return False


def is_audit_rule(rule_id: str) -> bool:
    """Le regole 'audit' segnalano un punto da guardare, non una vulnerabilità confermata."""
    return ".audit." in rule_id


_SUPPRESS = re.compile(r"(#|//)\s*(nosec|nosem(grep)?)\b", re.I)
MAX_SOURCE_BYTES = 1_000_000


class Suppressions:
    """Rispetta `# nosec` e `# nosemgrep`: se lo sviluppatore ha annotato il punto dopo averlo valutato,
    segnalarlo di nuovo è rumore. Legge solo file dentro la cartella analizzata."""

    def __init__(self, src: str):
        self.root = os.path.realpath(src)
        self.cache: dict[str, list[str]] = {}

    def _lines(self, rel_path: str) -> list[str]:
        if rel_path in self.cache:
            return self.cache[rel_path]
        lines: list[str] = []
        full = os.path.realpath(os.path.join(self.root, rel_path))
        if full.startswith(self.root + os.sep):
            try:
                with open(full, "rb") as fh:
                    lines = fh.read(MAX_SOURCE_BYTES).decode("utf-8", "replace").splitlines()
            except OSError:
                lines = []
        self.cache[rel_path] = lines
        return lines

    def covers(self, rel_path: str, start: int, end: int | None = None) -> bool:
        lines = self._lines(rel_path)
        if not lines or start < 1:
            return False
        last = min(max(end or start, start), start + 8)
        if any(_SUPPRESS.search(line) for line in lines[start - 1:last]):          # sul punto stesso
            return True
        # la riga sopra conta solo se è un commento a sé: un'annotazione in fondo a un'altra istruzione non si estende
        above = lines[start - 2].strip() if start >= 2 and start - 2 < len(lines) else ""
        return above.startswith(("#", "//")) and bool(_SUPPRESS.search(above))

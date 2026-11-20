"""Filtri comuni per l'analisi del codice: meno rumore, più problemi veri.

Un report con 60 falsi allarmi nasconde i 3 problemi reali. Qui si scartano i segnali che non riguardano
l'applicazione in produzione (script di sviluppo) o il suo framework (regole Django su un'app Flask).
"""

from __future__ import annotations

import os

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

"""Configurazione automatica dell'analisi interna per le app che girano in Docker su questa macchina.

Da una porta pubblicata da un container risale al progetto Docker Compose e ricava da solo:
cartella del codice, container dell'app e, se c'è PostgreSQL, il suo utente e nome (da `docker inspect`:
le password non vengono mai lette né salvate).
Guarda SOLO questa macchina: per un'app su un'altra macchina l'[internal] con ssh resta da scrivere a mano.
"""

from __future__ import annotations

import json
import re

from apernix.discover import _DOCKER_PORT, local_ip
from apernix.scope import parse_internal, parse_target_url
from apernix.term import clean
from apernix.tools import run_capture

_COMPOSE = "com.docker.compose."
MAX_CONTAINERS = 16


def _labels(raw: object) -> dict[str, str]:
    out = {}
    for part in str(raw).split(","):
        key, _, value = part.partition("=")
        if key.startswith(_COMPOSE):
            out[key] = value
    return out


def _docker_ps(*extra: str) -> list[dict]:
    res = run_capture(["docker", "ps", *extra, "--format", "{{json .}}"], timeout=10)
    if not res.ok:
        return []
    rows = []
    for line in res.output.decode("utf-8", "replace").splitlines()[:200]:
        try:
            item = json.loads(line)
        except json.JSONDecodeError:
            continue
        if isinstance(item, dict):
            rows.append(item)
    return rows


def _inspect(names: list[str]) -> list[dict]:
    res = run_capture(["docker", "inspect", "--type", "container", *names], timeout=15)
    if not res.ok:
        return []
    try:
        data = json.loads(res.output)
    except (json.JSONDecodeError, UnicodeDecodeError, RecursionError):
        return []
    return [d for d in data if isinstance(d, dict)] if isinstance(data, list) else []


def _env(info: dict) -> dict[str, str]:
    cfg = info.get("Config") if isinstance(info.get("Config"), dict) else {}
    env = {}
    for item in cfg.get("Env") or []:
        key, _, value = str(item).partition("=")
        env[key] = value
    return env


def detect_internal(url: str) -> dict | None:
    """Dizionario per la sezione [internal] (transport local) oppure None se non si riconosce nulla."""
    try:
        tg = parse_target_url(url)
    except ValueError:
        return None
    if not (tg.host == "localhost" or tg.host.startswith("127.") or tg.host == local_ip()):
        return None
    project = ""
    folder = ""
    for item in _docker_ps():
        for _bind, port in _DOCKER_PORT.findall(str(item.get("Ports", ""))):
            if int(port) == tg.port:
                lab = _labels(item.get("Labels", ""))
                project = lab.get(_COMPOSE + "project", "")
                folder = lab.get(_COMPOSE + "project.working_dir", "")
    if not project or not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_.-]{0,63}", project):
        return None
    rows = _docker_ps("--filter", f"label={_COMPOSE}project={project}")
    names = [str(r.get("Names", "")) for r in rows if str(r.get("Names", ""))][:MAX_CONTAINERS]
    if not names:
        return None
    db_container = db_user = db_name = ""
    for info in _inspect(names):
        cfg = info.get("Config") if isinstance(info.get("Config"), dict) else {}
        env = _env(info)
        if "postgres" in str(cfg.get("Image", "")).lower() or "POSTGRES_DB" in env or "POSTGRES_USER" in env:
            db_container = str(info.get("Name", "")).lstrip("/")
            db_user = env.get("POSTGRES_USER") or "postgres"
            db_name = env.get("POSTGRES_DB") or db_user
            break
    cand = {"transport": "local", "path": folder, "containers": names}
    if db_container:
        cand.update(db_container=db_container, db_user=db_user, db_name=db_name)
    try:
        parse_internal(cand)
    except Exception:
        cand.pop("path", None)         # cartella con caratteri strani: si analizza il resto
        try:
            parse_internal(cand)
        except Exception:
            return None
    cand["project"] = clean(project, 60)
    return cand


def internal_lines(found: dict) -> list[str]:
    """Descrizione breve da mostrare all'utente prima di attivare l'analisi interna."""
    lines = [f"app: {found.get('project', '?')}", f"container: {', '.join(found['containers'])}"]
    if found.get("path"):
        lines.append(f"codice: {found['path']}")
    if found.get("db_container"):
        lines.append(f"database: PostgreSQL {found['db_name']} (utente {found['db_user']}) in {found['db_container']}")
    return lines

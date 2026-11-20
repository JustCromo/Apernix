"""Controlli sui container Docker dell'app: privilegi, utente, mount pericolosi, porte, password deboli."""

from __future__ import annotations

import json
import re

from apernix.i18n import t
from apernix.inside.transport import Transport
from apernix.models import Finding

SOURCE = "docker"
DB_PORTS = {"5432": "PostgreSQL", "3306": "MySQL/MariaDB", "6379": "Redis", "27017": "MongoDB", "9200": "Elasticsearch"}
WEAK = {"password", "passw0rd", "admin", "123456", "12345678", "postgres", "root", "changeme", "secret", "test",
        "default", "qwerty", "toor", "letmein"}
_SECRET_NAME = re.compile(r"(PASS(WORD|WD)?|SECRET|TOKEN|API_?KEY)", re.I)
DANGEROUS_CAPS = {"SYS_ADMIN", "NET_ADMIN", "SYS_PTRACE", "SYS_MODULE", "DAC_READ_SEARCH", "ALL"}


def _f(check: str, element: str, impact: int, prob: int, evidence: list[str]) -> Finding:
    return Finding(check=check, title=t(f"{check}.title"), element=element, impact=impact, probability=prob,
                   source=SOURCE, evidence=evidence, pt="confirmed", remediation=t(f"{check}.fix"))


def inspect(tr: Transport, names: tuple[str, ...]):
    """Restituisce (lista di dict di `docker inspect`, motivo dell'errore o '')."""
    res = tr.run(["docker", "inspect", "--type", "container", *names], timeout=30)
    if not res.ok:
        return [], res.reason or "failed"
    try:
        data = json.loads(res.output)
    except (json.JSONDecodeError, UnicodeDecodeError, RecursionError):
        return [], "unparsable"
    if not isinstance(data, list):
        return [], "unparsable"
    return [d for d in data if isinstance(d, dict)], ""


def _dict(v: object) -> dict:
    return v if isinstance(v, dict) else {}


def _list(v: object) -> list:
    return v if isinstance(v, list) else []


def analyze(info: dict) -> list[Finding]:
    name = str(info.get("Name", "")).lstrip("/")[:64] or "?"
    host, cfg = _dict(info.get("HostConfig")), _dict(info.get("Config"))
    out: list[Finding] = []
    if host.get("Privileged") is True:
        out.append(_f("CTR-PRIVILEGED", name, 5, 3, [t("ev.ctr.privileged")]))
    if host.get("NetworkMode") == "host":
        out.append(_f("CTR-HOSTNET", name, 3, 3, [t("ev.ctr.hostnet")]))
    if host.get("PidMode") == "host":
        out.append(_f("CTR-HOSTPID", name, 4, 3, [t("ev.ctr.hostpid")]))
    caps = sorted({str(c).upper().removeprefix("CAP_") for c in _list(host.get("CapAdd"))} & DANGEROUS_CAPS)
    if caps:
        out.append(_f("CTR-CAPS", name, 4, 3, [", ".join(caps)]))
    if any("unconfined" in str(o) for o in _list(host.get("SecurityOpt"))):
        out.append(_f("CTR-UNCONFINED", name, 3, 2, [t("ev.ctr.unconfined")]))
    for m in _list(info.get("Mounts")):
        src = str(_dict(m).get("Source", ""))
        if src.endswith("docker.sock"):
            out.append(_f("CTR-DOCKERSOCK", name, 5, 3, [f"mount: {src}"]))
        elif src == "/":
            out.append(_f("CTR-ROOTFS", name, 5, 3, ["mount: /"]))
    user = str(cfg.get("User", "")).strip()
    if user in ("", "0", "root") or user.startswith(("0:", "root:")):
        out.append(_f("CTR-ROOT", name, 3, 2, [t("ev.ctr.root")]))
    for port, binds in _dict(host.get("PortBindings")).items():
        number = str(port).split("/")[0]
        for b in _list(binds):
            if str(_dict(b).get("HostIp", "")) in ("", "0.0.0.0", "::") and number in DB_PORTS:
                out.append(_f("CTR-DB-PUBLISHED", f"{name}:{number}", 4, 3,
                              [t("ev.ctr.db_published", service=DB_PORTS[number], port=number)]))
    weak = []
    for env in _list(cfg.get("Env")):
        key, _, value = str(env).partition("=")
        if _SECRET_NAME.search(key) and value.strip().lower() in WEAK:
            weak.append(key[:60])
    if weak:
        ev = [t("ev.ctr.weakpass", names=", ".join(weak[:5])), t("SEC.value_hidden")]
        out.append(_f("CTR-WEAKPASS", name, 5, 4, ev))
    return out


def run(tr: Transport, names: tuple[str, ...]):
    """Restituisce (problemi, motivo dell'errore o '')."""
    infos, reason = inspect(tr, names)
    if reason:
        return [], reason
    out: list[Finding] = []
    for info in infos:
        out += analyze(info)
    return out, ""

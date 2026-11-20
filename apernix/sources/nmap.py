"""Fonte esterna: nmap. Trova porte aperte e servizi sugli host dei bersagli."""

from __future__ import annotations

import xml.etree.ElementTree as ET

from apernix.i18n import t
from apernix.models import Finding
from apernix.tools import ToolResult, run_tool

SOURCE = "nmap"
DB_SERVICES = {"postgresql": 5432, "mysql": 3306, "mongodb": 27017, "redis": 6379,
               "elasticsearch": 9200, "memcached": 11211, "ms-sql-s": 1433, "couchdb": 5984}
CLEARTEXT = {"telnet": 23, "ftp": 21, "pop3": 110, "imap": 143}
DOCKER_API = {2375}


def port_args(spec: str) -> list[str]:
    if spec == "top100":
        return ["--top-ports", "100"]
    if spec == "top1000":
        return ["--top-ports", "1000"]
    if spec == "all":
        return ["-p-"]
    return ["-p", spec]


def build_argv(host: str, spec: str) -> list[str]:
    # -sV: versioni dei servizi; -Pn: niente ping (molti host lo bloccano);
    # come utente normale nmap usa la connect scan, senza bisogno di root.
    # L'host arriva dallo scope già validato (mai un valore che inizia con '-').
    return ["nmap", "-sV", "-Pn", "-T3", "--max-retries", "2", "--host-timeout", "15m",
            *port_args(spec), host]


def scan(host: str, spec: str, timeout: float = 1200, tick=None) -> ToolResult:
    # nmap vuole le opzioni prima del bersaglio: -oX va quindi inserito prima dell'host.
    argv = build_argv(host, spec)
    return run_tool(argv[:-1], lambda path: ["-oX", path, argv[-1]], timeout, tick)


def parse(xml_data: bytes) -> list[dict]:
    """Restituisce le porte aperte: [{port, proto, service, product, version}]."""
    if b"<!ENTITY" in xml_data or b"<!entity" in xml_data:
        raise ValueError("xml con entità non ammesso")
    root = ET.fromstring(xml_data)
    out = []
    for host in root.iter("host"):
        for port in host.iter("port"):
            state = port.find("state")
            if state is None or state.get("state") != "open":
                continue
            svc = port.find("service")
            try:
                num = int(port.get("portid", "0"))
            except ValueError:
                continue
            out.append({
                "port": num,
                "proto": (port.get("protocol") or "tcp")[:8],
                "service": ((svc.get("name") if svc is not None else "") or "")[:64],
                "product": ((svc.get("product") if svc is not None else "") or "")[:128],
                "version": ((svc.get("version") if svc is not None else "") or "")[:64],
            })
            if len(out) >= 2000:
                return out
    return out


def _f(check: str, element: str, impact: int, prob: int, evidence: list[str], scored: bool = True) -> Finding:
    return Finding(check=check, title=t(f"{check}.title"), element=element, impact=impact,
                   probability=prob, source=SOURCE, evidence=evidence, scored=scored,
                   pt="confirmed",       # la porta ha risposto davvero a nmap
                   remediation=t(f"{check}.fix"))


def describe(p: dict) -> str:
    extra = " ".join(x for x in (p["product"], p["version"]) if x)
    return f"{p['port']}/{p['proto']} {p['service']}" + (f" ({extra})" if extra else "")


def findings(host: str, ports: list[dict], web_ports: list[int]) -> list[Finding]:
    out: list[Finding] = []
    for p in ports:
        el = f"{host}:{p['port']}"
        name = p["service"].lower()
        if p["port"] in DOCKER_API or name == "docker":
            out.append(_f("NET-DOCKER-API", el, 5, 5, [describe(p)]))
        elif name in DB_SERVICES or p["port"] in DB_SERVICES.values():
            out.append(_f("NET-DB-EXPOSED", el, 5, 4, [describe(p)]))
        elif name in CLEARTEXT or p["port"] in CLEARTEXT.values():
            out.append(_f("NET-CLEARTEXT", el, 4, 3, [describe(p)]))
    same_site = 443 in web_ports            # la porta 80 di chi serve HTTPS su 443 è lo stesso server web
    others = [describe(p) for p in ports if p["port"] not in web_ports
              and not (same_site and p["port"] == 80 and p["service"].lower().startswith("http"))]
    if others:
        # Servizi della macchina (SSH, ecc.): vanno guardati, ma sono compito di Erinix/Vulpnix e non pesano sul voto.
        out.append(_f("NET-SURFACE", host, 2, 2, others, scored=False))
    return out

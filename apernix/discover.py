"""Scoperta automatica delle web application sulla macchina dove gira Apernix.

Guarda SOLO questa macchina (porte pubblicate da Docker e porte in ascolto), mai la rete
degli altri. Per ogni porta prova una GET a "/" senza credenziali, solo per capire se è un
sito e come si chiama: è l'unico punto dove il certificato non viene verificato, perché
non si invia nulla di sensibile. La fiducia vera nel certificato arriva dopo (TOFU).
"""

from __future__ import annotations

import json
import re
import socket
import warnings
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass

import requests
import urllib3

from apernix.term import clean
from apernix.tools import run_capture

NOT_WEB = {21, 22, 23, 25, 53, 110, 111, 143, 389, 445, 631, 993, 995, 1433, 3306, 5353, 5432,
           6379, 9200, 11211, 27017, 2375, 2376}
MAX_PORTS = 40
_DOCKER_PORT = re.compile(r"(?:(\d{1,3}(?:\.\d{1,3}){3}|\[[0-9a-fA-F:]*\]):)?(\d{1,5})->\d{1,5}/tcp")
_TITLE = re.compile(rb"<title[^>]*>([^<]{1,200})</title>", re.I)


@dataclass
class Candidate:
    url: str
    name: str
    title: str
    via: str


def local_ip() -> str:
    """IP della macchina nella rete locale (nessun pacchetto viene inviato)."""
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        s.connect(("192.0.2.1", 9))
        return s.getsockname()[0]
    except OSError:
        return "127.0.0.1"
    finally:
        s.close()


def _host_for(bind: str | None, lan: str) -> str | None:
    if bind in (None, "", "0.0.0.0", "[::]", "*", "[::1]"):
        return lan if bind != "[::1]" else None
    if bind.startswith("127."):
        return "127.0.0.1"
    if bind.startswith("["):
        return None
    return bind


def docker_ports(lan: str) -> list[tuple[str, int, str]]:
    out = run_capture(["docker", "ps", "--format", "{{json .}}"], timeout=10)
    if not out.ok:
        return []
    found = []
    for line in out.output.decode("utf-8", "replace").splitlines()[:200]:
        try:
            item = json.loads(line)
        except json.JSONDecodeError:
            continue
        if not isinstance(item, dict):
            continue
        labels = str(item.get("Labels", ""))
        project = re.search(r"com\.docker\.compose\.project=([^,]+)", labels)
        service = re.search(r"com\.docker\.compose\.service=([^,]+)", labels)
        name = f"{project.group(1)} ({service.group(1)})" if project and service else str(item.get("Names", "?"))
        for bind, port in _DOCKER_PORT.findall(str(item.get("Ports", ""))):
            host = _host_for(bind, lan)
            if host:
                found.append((host, int(port), clean(name, 60)))
    return found


def listening_ports(lan: str) -> list[tuple[str, int, str]]:
    out = run_capture(["ss", "-ltnH"], timeout=10)
    if not out.ok:
        return []
    found = []
    for line in out.output.decode("utf-8", "replace").splitlines()[:500]:
        cols = line.split()
        if len(cols) < 4 or ":" not in cols[3]:
            continue
        bind, _, port = cols[3].rpartition(":")
        if not port.isdigit():
            continue
        host = _host_for(bind.split("%")[0], lan)
        if host:
            found.append((host, int(port), ""))
    return found


# La scoperta prova i siti anche con certificati privati o scaduti (verify=False, volutamente): l'avviso di urllib3 non
# serve e, scritto sullo schermo mentre la dashboard è aperta, lo rovina. catch_warnings non è thread-safe:
# qui il filtro è globale.
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)


def probe(host: str, port: int, timeout: float = 2.0) -> tuple[str, str, bool] | None:
    """(schema, titolo, reindirizza_a_https) se sulla porta risponde un sito, altrimenti None."""
    netloc = f"{host}:{port}"
    with warnings.catch_warnings():
        warnings.simplefilter("ignore")
        for scheme in ("https", "http"):
            try:
                r = requests.get(f"{scheme}://{netloc}/", timeout=timeout, verify=False, allow_redirects=False,
                                 stream=True, headers={"User-Agent": "Apernix-discovery"})
                body = r.raw.read(65536, decode_content=False) or b""
                r.close()
            except (requests.RequestException, OSError, ValueError):
                continue
            m = _TITLE.search(body)
            title = clean(m.group(1).decode("utf-8", "replace").strip(), 80) if m else ""
            loc = r.headers.get("location", "")
            return scheme, title, scheme == "http" and r.status_code in (301, 302, 307, 308) and \
                loc.lower().startswith("https://")
    return None


def discover() -> list[Candidate]:
    lan = local_ip()
    seen: dict[tuple[str, int], str] = {}
    for host, port, name in docker_ports(lan) + listening_ports(lan):
        if port in NOT_WEB or not 0 < port < 65536:
            continue
        if (host, port) not in seen or (name and not seen[(host, port)]):
            seen[(host, port)] = name
        if len(seen) >= MAX_PORTS:
            break
    items = sorted(seen.items(), key=lambda x: x[0][1])
    with ThreadPoolExecutor(max_workers=8) as pool:      # sonde in parallelo: al massimo pochi secondi
        hits = list(pool.map(lambda item: probe(*item[0]), items))
    result = []
    for ((host, port), name), hit in zip(items, hits, strict=True):
        if hit is None:
            continue
        scheme, title, redirects = hit
        if redirects:
            continue      # porta HTTP che manda solo a HTTPS: basta proporre quella HTTPS
        result.append(Candidate(f"{scheme}://{host}:{port}/", name or title or host, title,
                                "docker" if name else "porta locale"))
    return result

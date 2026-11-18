"""Scope: l'elenco dei bersagli che si è autorizzati ad analizzare.

Apernix non manda una sola richiesta a un indirizzo che non sia nello scope:
è la regola base di un tool offensivo, e protegge da errori di battitura e redirect.
"""

from __future__ import annotations

import ipaddress
import os
import re
import ssl
import stat
import tomllib
from dataclasses import dataclass
from urllib.parse import urlsplit

MAX_SCOPE_BYTES = 64 * 1024
MAX_TARGETS = 32
MAX_URL_LEN = 2048
LIMITS_DEFAULT = {"rate": 5.0, "max_requests": 300, "timeout": 10.0}
LIMITS_RANGE = {"rate": (0.1, 50.0), "max_requests": (1, 10000), "timeout": (1.0, 120.0)}
PORT_SCAN_MODES = ("none", "top100", "top1000", "all")
_HOSTNAME = re.compile(r"^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?(?:\.[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?)*$")
_PORTS = re.compile(r"^\d{1,5}(?:-\d{1,5})?(?:,\d{1,5}(?:-\d{1,5})?){0,63}$")


class ScopeError(Exception):
    """Errore nello scope. `code` è la chiave del messaggio, `params` i dettagli."""

    def __init__(self, code: str, **params: object) -> None:
        super().__init__(code)
        self.code = code
        self.params = params


@dataclass(frozen=True)
class Target:
    url: str          # URL normalizzato
    scheme: str
    host: str
    port: int
    path: str         # prefisso di percorso autorizzato, finisce con /
    name: str
    ca_file: str = ""  # CA privata di cui fidarsi per questo bersaglio (es. quella di Caddy)


def _bad(text: str) -> bool:
    return any(ord(c) < 0x21 or c in "\x7f\\" for c in text)


def valid_host(host: str) -> bool:
    """Hostname o indirizzo IP validi. Mai un valore che inizia con '-' (sarebbe un'opzione per nmap)."""
    if not host or len(host) > 253 or host.startswith("-"):
        return False
    try:
        ipaddress.ip_address(host)
        return True
    except ValueError:
        return bool(_HOSTNAME.match(host))


_NAME_OK = re.compile(r"[^A-Za-z0-9 _.\-]")


def clean_name(name: str) -> str:
    """Nome leggibile del bersaglio: solo lettere, numeri, spazio e . _ - (max 64)."""
    return _NAME_OK.sub("", name)[:64].strip()


def valid_port_spec(spec: object) -> bool:
    if not isinstance(spec, str):
        return False
    if spec in PORT_SCAN_MODES:
        return True
    if not _PORTS.match(spec):
        return False
    for part in spec.split(","):
        nums = [int(x) for x in part.split("-")]
        if any(n < 1 or n > 65535 for n in nums) or nums != sorted(nums):
            return False
    return True


def parse_target_url(raw: object) -> Target:
    if not isinstance(raw, str) or not raw or len(raw) > MAX_URL_LEN or _bad(raw):
        raise ValueError("url")
    parts = urlsplit(raw)
    scheme = parts.scheme.lower()
    if scheme not in ("http", "https"):
        raise ValueError("scheme")
    if parts.username is not None or parts.password is not None:
        raise ValueError("credenziali nell'URL")
    if parts.fragment or parts.query:
        raise ValueError("query o frammento")
    host = (parts.hostname or "").lower().rstrip(".")
    if not valid_host(host):
        raise ValueError("host")
    try:
        port = parts.port or (443 if scheme == "https" else 80)
    except ValueError as exc:
        raise ValueError("porta") from exc
    path = parts.path or "/"
    if ".." in path.split("/"):
        raise ValueError("percorso")
    if not path.endswith("/"):
        path += "/"
    netloc = f"[{host}]" if ":" in host else host
    url = f"{scheme}://{netloc}:{port}{path}"
    return Target(url=url, scheme=scheme, host=host, port=port, path=path, name="")


@dataclass(frozen=True)
class Scope:
    targets: tuple[Target, ...]
    rate: float
    max_requests: int
    timeout: float
    owner: str
    ports: str = "none"       # porte da far controllare a nmap sugli host dei bersagli

    def allows(self, url: str) -> bool:
        """True solo se `url` cade dentro uno dei bersagli autorizzati."""
        return self.target_for(url) is not None

    def target_for(self, url: str) -> "Target | None":
        """Il bersaglio autorizzato a cui appartiene `url`, oppure None."""
        if not isinstance(url, str) or len(url) > MAX_URL_LEN or _bad(url):
            return None
        try:
            parts = urlsplit(url)
            scheme = parts.scheme.lower()
            host = (parts.hostname or "").lower().rstrip(".")
            port = parts.port or (443 if scheme == "https" else 80)
        except ValueError:
            return None
        if parts.username is not None or parts.password is not None:
            return None
        path = parts.path or "/"
        if ".." in path.split("/"):
            return None
        for tg in self.targets:
            if (scheme, host, port) != (tg.scheme, tg.host, tg.port):
                continue
            if (path if path.endswith("/") else path + "/").startswith(tg.path):
                return tg
        return None


def _limit(limits: dict, name: str):
    lo, hi = LIMITS_RANGE[name]
    value = limits.get(name, LIMITS_DEFAULT[name])
    if isinstance(value, bool) or not isinstance(value, (int, float)) or not lo <= value <= hi:
        raise ScopeError("err.scope_invalid", reason_key="scope.reason.bad_limit", name=name)
    return int(value) if name == "max_requests" else float(value)


def load_scope(path: str) -> Scope:
    return scope_from_dict(read_scope_doc(path), os.path.dirname(os.path.abspath(path)))


def read_scope_doc(path: str) -> dict:
    """Legge il TOML dello scope con i controlli di sicurezza (file normale, permessi, dimensione)."""
    try:
        fd = os.open(path, os.O_RDONLY)
    except FileNotFoundError as exc:
        raise ScopeError("err.scope_missing") from exc
    except OSError as exc:
        raise ScopeError("err.scope_missing") from exc
    try:
        st = os.fstat(fd)
        if not stat.S_ISREG(st.st_mode):
            raise ScopeError("err.scope_missing")
        if st.st_mode & 0o022:
            raise ScopeError("err.scope_unsafe_file")
        if st.st_size > MAX_SCOPE_BYTES:
            raise ScopeError("err.scope_invalid", reason_key="scope.reason.too_big")
        data = os.read(fd, MAX_SCOPE_BYTES + 1)
    finally:
        os.close(fd)
    if len(data) > MAX_SCOPE_BYTES:
        raise ScopeError("err.scope_invalid", reason_key="scope.reason.too_big")
    try:
        doc = tomllib.loads(data.decode("utf-8"))
    except (UnicodeDecodeError, tomllib.TOMLDecodeError) as exc:
        raise ScopeError("err.scope_invalid", reason_key="scope.reason.not_toml") from exc
    return doc


MAX_CA_BYTES = 1024 * 1024


def _ca_path(raw: object, base_dir: str) -> str:
    """Percorso della CA privata: file normale, leggibile, piccolo, in formato PEM."""
    if raw in (None, ""):
        return ""
    if not isinstance(raw, str) or len(raw) > 4096 or "\x00" in raw:
        raise ValueError("ca_file")
    path = os.path.normpath(os.path.join(base_dir, os.path.expanduser(raw)))
    try:
        st = os.stat(path)
        if not stat.S_ISREG(st.st_mode) or st.st_size > MAX_CA_BYTES:
            raise ValueError("ca_file")
        with open(path, "rb") as fh:
            head = fh.read(MAX_CA_BYTES)
    except OSError as exc:
        raise ValueError("ca_file") from exc
    if b"-----BEGIN CERTIFICATE-----" not in head:
        raise ValueError("ca_file")
    try:
        ssl.create_default_context(cafile=path)     # deve essere un certificato vero, non solo sembrarlo
    except (ssl.SSLError, ValueError, OSError) as exc:
        raise ValueError("ca_file") from exc
    return path


def scope_from_dict(doc: dict, base_dir: str = ".") -> Scope:
    auth = doc.get("authorization")
    if not isinstance(auth, dict) or auth.get("confirmed") is not True:
        raise ScopeError("err.scope_not_confirmed")
    owner = auth.get("owner", "")
    owner = owner if isinstance(owner, str) else ""
    raw_targets = doc.get("target")
    if not isinstance(raw_targets, list) or not raw_targets:
        raise ScopeError("err.scope_invalid", reason_key="scope.reason.no_targets")
    if len(raw_targets) > MAX_TARGETS:
        raise ScopeError("err.scope_invalid", reason_key="scope.reason.too_many_targets", max=MAX_TARGETS)
    targets = []
    for item in raw_targets:
        url = item.get("url") if isinstance(item, dict) else None
        try:
            tg = parse_target_url(url)
        except ValueError as exc:
            shown = url if isinstance(url, str) else "?"
            raise ScopeError("err.scope_invalid", reason_key="scope.reason.bad_url", url=shown) from exc
        name = item.get("name", "")
        name = name if isinstance(name, str) else ""
        try:
            ca = _ca_path(item.get("ca_file"), base_dir)
        except ValueError as exc:
            raise ScopeError("err.scope_invalid", reason_key="scope.reason.bad_ca") from exc
        targets.append(Target(tg.url, tg.scheme, tg.host, tg.port, tg.path, clean_name(name), ca))
    limits = doc.get("limits", {})
    if not isinstance(limits, dict):
        limits = {}
    network = doc.get("network", {})
    if not isinstance(network, dict):
        network = {}
    ports = network.get("ports", "none")
    if not valid_port_spec(ports):
        raise ScopeError("err.scope_invalid", reason_key="scope.reason.bad_ports")
    return Scope(
        targets=tuple(targets),
        rate=_limit(limits, "rate"),
        max_requests=_limit(limits, "max_requests"),
        timeout=_limit(limits, "timeout"),
        owner=owner[:128],
        ports=ports,
    )

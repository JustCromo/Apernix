"""Client HTTP prudente: solo bersagli nello scope, limiti fissi a richieste, tempo e memoria."""

from __future__ import annotations

import threading
import time
from dataclasses import dataclass, field
from urllib.parse import urljoin

import requests

from apernix import __version__
from apernix.scope import Scope

MAX_BODY = 2 * 1024 * 1024   # oltre i 2 MB il corpo della risposta viene troncato
MAX_REDIRECTS = 5
USER_AGENT = f"Apernix/{__version__} (+security assessment)"


class OutOfScope(Exception):
    pass


class BudgetExceeded(Exception):
    pass


@dataclass
class Response:
    url: str
    status: int
    headers: dict[str, str]                       # nomi in minuscolo
    set_cookies: list[str] = field(default_factory=list)
    body: bytes = b""
    truncated: bool = False
    redirects: list[str] = field(default_factory=list)


class SafeClient:
    def __init__(self, scope: Scope, session: requests.Session | None = None) -> None:
        self.scope = scope
        self.session = session or requests.Session()
        self.session.headers["User-Agent"] = USER_AGENT
        # Niente compressione: il limite di memoria vale sui byte veri (difesa da "zip bomb").
        self.session.headers["Accept-Encoding"] = "identity"
        self.session.trust_env = False   # niente proxy o credenziali presi dall'ambiente
        self._lock = threading.Lock()
        self._count = 0
        self._last = 0.0

    @property
    def requests_made(self) -> int:
        return self._count

    def _wait_turn(self) -> None:
        with self._lock:
            if self._count >= self.scope.max_requests:
                raise BudgetExceeded()
            gap = 1.0 / self.scope.rate
            now = time.monotonic()
            if now - self._last < gap:
                time.sleep(gap - (now - self._last))
            self._last = time.monotonic()
            self._count += 1

    def request(self, method: str, url: str, **kwargs) -> Response:
        if method not in ("GET", "HEAD", "POST", "OPTIONS"):
            raise ValueError("metodo non ammesso")
        chain: list[str] = []
        current = url
        for _ in range(MAX_REDIRECTS + 1):
            if not self.scope.allows(current):
                raise OutOfScope(current)
            self._wait_turn()
            resp = self.session.request(
                method, current, allow_redirects=False, stream=True,
                timeout=(min(5.0, self.scope.timeout), self.scope.timeout), **kwargs,
            )
            try:
                body, truncated = _read_limited(resp)
                headers = {k.lower(): v for k, v in resp.headers.items()}
                try:
                    cookies = list(resp.raw.headers.getlist("Set-Cookie"))
                except AttributeError:
                    cookies = [headers["set-cookie"]] if "set-cookie" in headers else []
                status = resp.status_code
            finally:
                resp.close()
            location = headers.get("location")
            if status in (301, 302, 303, 307, 308) and location:
                nxt = urljoin(current, location)
                chain.append(nxt)
                if not self.scope.allows(nxt):
                    # Il redirect esce dallo scope: ci si ferma qui e si restituisce la risposta.
                    return Response(current, status, headers, cookies, body, truncated, chain)
                current = nxt
                if status == 303:
                    method, kwargs = "GET", {k: v for k, v in kwargs.items() if k not in ("data", "json")}
                continue
            return Response(current, status, headers, cookies, body, truncated, chain)
        return Response(current, status, headers, cookies, body, truncated, chain)

    def get(self, url: str, **kwargs) -> Response:
        return self.request("GET", url, **kwargs)


def _read_limited(resp: requests.Response) -> tuple[bytes, bool]:
    chunks: list[bytes] = []
    size = 0
    for chunk in resp.iter_content(chunk_size=65536):
        if not chunk:
            continue
        if size + len(chunk) > MAX_BODY:
            chunks.append(chunk[: MAX_BODY - size])
            return b"".join(chunks), True
        chunks.append(chunk)
        size += len(chunk)
    return b"".join(chunks), False

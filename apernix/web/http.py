"""Client HTTP prudente: solo bersagli nello scope, limiti fissi a richieste, tempo e memoria."""

from __future__ import annotations

import threading
import time
from dataclasses import dataclass, field
from urllib.parse import urljoin

import requests
from requests.adapters import HTTPAdapter

from apernix import __version__
from apernix.scope import Scope
from apernix.tlsinfo import pinned_context

MAX_BODY = 2 * 1024 * 1024   # oltre i 2 MB il corpo della risposta viene troncato
MAX_REDIRECTS = 5
USER_AGENT = f"Apernix/{__version__} (+security assessment)"


class _PinnedAdapter(HTTPAdapter):
    """Adapter HTTPS che usa un contesto TLS dedicato (CA privata o certificato accettato)."""

    def __init__(self, context, **kw) -> None:
        self._context = context
        super().__init__(**kw)

    def init_poolmanager(self, *args, **kw):
        kw["ssl_context"] = self._context
        return super().init_poolmanager(*args, **kw)


class OutOfScope(Exception):
    pass


class BudgetExceeded(Exception):
    pass


class Cancelled(Exception):
    """L'utente ha fermato l'analisi."""


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
        for tg in scope.targets:
            if tg.ca_file and tg.scheme == "https":
                netloc = f"[{tg.host}]" if ":" in tg.host else tg.host
                self.session.mount(f"https://{netloc}:{tg.port}/", _PinnedAdapter(pinned_context(tg.ca_file)))
        self.cancel = None        # threading.Event: se impostato, l'analisi si ferma alla prossima richiesta
        self.observer = None      # funzione(metodo, url, stato) chiamata dopo ogni richiesta
        self._lock = threading.Lock()
        self._count = 0
        self._last = 0.0

    @property
    def requests_made(self) -> int:
        return self._count

    def _wait_turn(self) -> None:
        if self.cancel is not None and self.cancel.is_set():
            raise Cancelled()
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
            target = self.scope.target_for(current)
            self._wait_turn()
            try:
                resp = self.session.request(
                    method, current, allow_redirects=False, stream=True,
                    timeout=(min(5.0, self.scope.timeout), self.scope.timeout),
                    verify=(target.ca_file if target and target.ca_file else True), **kwargs,
                )
            except requests.RequestException:
                self._notify(method, current, None)
                raise
            self._notify(method, current, resp.status_code)
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

    def _notify(self, method: str, url: str, status) -> None:
        if self.observer is not None:
            self.observer(method, url, status)

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

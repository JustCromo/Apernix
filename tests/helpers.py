"""Server HTTP locale per i test: nessun test tocca la rete esterna o i file veri."""

from __future__ import annotations

import os
import tempfile
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

from apernix.scope import scope_from_dict


class Handler(BaseHTTPRequestHandler):
    routes: dict = {}

    def log_message(self, *args):  # silenzioso
        pass

    def do_GET(self):
        status, headers, body = self.routes.get(self.path, (404, [], b"not found"))
        self.send_response(status)
        for k, v in headers:
            self.send_header(k, v)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)


class LocalServer:
    def __init__(self, routes: dict) -> None:
        handler = type("H", (Handler,), {"routes": routes})
        self.httpd = ThreadingHTTPServer(("127.0.0.1", 0), handler)
        self.port = self.httpd.server_address[1]
        self.base = f"http://127.0.0.1:{self.port}"
        self.thread = threading.Thread(target=self.httpd.serve_forever, daemon=True)

    def __enter__(self):
        self.thread.start()
        return self

    def __exit__(self, *exc):
        self.httpd.shutdown()
        self.httpd.server_close()


def make_scope(url: str, **limits):
    lim = {"rate": 50, "max_requests": 100, "timeout": 5}
    lim.update(limits)
    return scope_from_dict({"authorization": {"confirmed": True}, "target": [{"url": url}], "limits": lim})


def scope_file(tmp: str, url: str, mode: int = 0o600, confirmed: bool = True) -> str:
    path = os.path.join(tmp, "scope.toml")
    with open(path, "w") as fh:
        fh.write(f'[authorization]\nconfirmed = {"true" if confirmed else "false"}\n'
                 f'[[target]]\nurl = "{url}"\n[limits]\nrate = 50\n')
    os.chmod(path, mode)
    return path


def tmpdir():
    return tempfile.TemporaryDirectory(prefix="apernix-test-")

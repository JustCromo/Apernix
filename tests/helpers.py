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
        route = self.routes.get(self.path, self.routes.get("*", (404, [], b"not found")))
        status, headers, body = route(self) if callable(route) else route
        self.send_response(status)
        for k, v in headers:
            self.send_header(k, v)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        if self.command != "HEAD":
            self.wfile.write(body)

    def do_OPTIONS(self):
        route = self.routes.get(("OPTIONS", self.path), (405, [], b""))
        status, headers, body = route
        self.send_response(status)
        for k, v in headers:
            self.send_header(k, v)
        self.send_header("Content-Length", "0")
        self.end_headers()


class LocalServer:
    def __init__(self, routes: dict) -> None:
        handler = type("H", (Handler,), {"routes": routes})
        self.httpd = ThreadingHTTPServer(("127.0.0.1", 0), handler)
        self.httpd.handle_error = lambda *a: None   # connessioni chiuse a metà (es. solo handshake TLS)
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


def fake_tool(bindir: str, name: str, script: str) -> None:
    """Crea un finto tool eseguibile (script sh) per provare l'integrazione senza quello vero."""
    path = os.path.join(bindir, name)
    with open(path, "w") as fh:
        fh.write("#!/bin/sh\n" + script + "\n")
    os.chmod(path, 0o755)


def scope_file(tmp: str, url: str, mode: int = 0o600, confirmed: bool = True) -> str:
    path = os.path.join(tmp, "scope.toml")
    with open(path, "w") as fh:
        fh.write(f'[authorization]\nconfirmed = {"true" if confirmed else "false"}\n'
                 f'[[target]]\nurl = "{url}"\n[limits]\nrate = 50\n')
    os.chmod(path, mode)
    return path


def tmpdir():
    return tempfile.TemporaryDirectory(prefix="apernix-test-")


def make_tls_fixture(folder: str):
    """Crea con openssl una CA finta e un certificato per 127.0.0.1 (solo per i test).
    Restituisce (ca.crt, srv.crt, srv.key) oppure None se openssl manca."""
    import shutil
    import subprocess
    if shutil.which("openssl") is None:
        return None
    ca_key, ca_crt = os.path.join(folder, "ca.key"), os.path.join(folder, "ca.crt")
    key, csr, crt, ext = (os.path.join(folder, n) for n in ("srv.key", "srv.csr", "srv.crt", "ext"))
    with open(ext, "w") as fh:
        fh.write("subjectAltName=IP:127.0.0.1\nbasicConstraints=CA:FALSE\n"
                 "authorityKeyIdentifier=keyid\nsubjectKeyIdentifier=hash\n")
    q = {"stdout": subprocess.DEVNULL, "stderr": subprocess.DEVNULL, "check": True}
    ec = ["-newkey", "ec", "-pkeyopt", "ec_paramgen_curve:prime256v1", "-nodes"]
    subprocess.run(["openssl", "req", "-x509", *ec, "-keyout", ca_key, "-out", ca_crt, "-days", "2",
                    "-subj", "/CN=Apernix Test CA", "-addext", "basicConstraints=critical,CA:TRUE",
                    "-addext", "keyUsage=critical,keyCertSign,cRLSign"], **q)
    subprocess.run(["openssl", "req", *ec, "-keyout", key, "-out", csr, "-subj", "/CN=127.0.0.1"], **q)
    subprocess.run(["openssl", "x509", "-req", "-in", csr, "-CA", ca_crt, "-CAkey", ca_key,
                    "-CAcreateserial", "-out", crt, "-days", "2", "-extfile", ext], **q)
    return ca_crt, crt, key


class TLSServer(LocalServer):
    def __init__(self, routes: dict, crt: str, key: str) -> None:
        import ssl
        super().__init__(routes)
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        ctx.load_cert_chain(crt, key)
        self.httpd.socket = ctx.wrap_socket(self.httpd.socket, server_side=True)
        self.base = f"https://127.0.0.1:{self.port}"

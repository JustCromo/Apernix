"""Come arrivare ai dati dell'app: sulla stessa macchina (local) o su un'altra via SSH (ssh).

Regole di sicurezza:
- ssh solo con chiave (mai password), host già noto in known_hosts (nessun "fidati al primo colpo"),
  nessun inoltro di agent, porte o X11
- nessuna shell locale: i comandi sono liste di argomenti; quelli remoti sono costruiti con shlex.join
  a partire da argomenti già validati
- il codice dell'app viene solo letto (copia temporanea locale con ssh, nessuna scrittura sulla macchina remota)
"""

from __future__ import annotations

import os
import shlex
import subprocess
import tarfile
import tempfile
import time

from apernix.scope import Internal
from apernix.tools import SAFE_ENV_KEYS, ToolResult, run_capture, which

MAX_SNAPSHOT = 200 * 1024 * 1024        # byte del codice copiato via ssh
MAX_MEMBERS = 50000
EXCLUDED = (".git", "node_modules", ".venv", "venv", "__pycache__", ".cache")


class Transport:
    kind = ""

    def run(self, argv: list[str], timeout: float = 30, max_bytes: int = 2 * 1024 * 1024,
            merge_stderr: bool = False) -> ToolResult:
        raise NotImplementedError

    def check(self) -> ToolResult:
        return self.run(["true"], timeout=15)

    def source(self, tmp: str) -> tuple[str, str]:
        """Restituisce (cartella locale col codice, motivo dell'errore o '')."""
        raise NotImplementedError


class LocalTransport(Transport):
    kind = "local"

    def __init__(self, cfg: Internal) -> None:
        self.cfg = cfg

    def run(self, argv, timeout=30, max_bytes=2 * 1024 * 1024, merge_stderr=False) -> ToolResult:
        return run_capture(argv, timeout, max_bytes, merge_stderr)

    def source(self, tmp: str) -> tuple[str, str]:
        if not self.cfg.path:
            return "", "no_path"
        if not os.path.isdir(self.cfg.path):
            return "", "no_path"
        return self.cfg.path, ""


class SshTransport(Transport):
    kind = "ssh"

    def __init__(self, cfg: Internal) -> None:
        self.cfg = cfg

    def _base(self) -> list[str]:
        c = self.cfg
        return ["ssh", "-o", "BatchMode=yes", "-o", "PasswordAuthentication=no",
                "-o", "StrictHostKeyChecking=yes", "-o", "IdentitiesOnly=yes",
                "-o", "ConnectTimeout=10", "-o", "ForwardAgent=no", "-o", "ForwardX11=no",
                "-o", "ClearAllForwardings=yes", "-i", c.key, "-p", str(c.port), f"{c.user}@{c.host}"]

    def run(self, argv, timeout=30, max_bytes=2 * 1024 * 1024, merge_stderr=False) -> ToolResult:
        cmd = shlex.join(argv) + (" 2>&1" if merge_stderr else "")
        return run_capture([*self._base(), cmd], timeout, max_bytes)

    def source(self, tmp: str) -> tuple[str, str]:
        if not self.cfg.path:
            return "", "no_path"
        if which("ssh") is None:
            return "", "missing"
        excl = [f"--exclude={name}" for name in EXCLUDED]
        cmd = shlex.join(["tar", "-C", self.cfg.path, *excl, "-cf", "-", "."])
        archive = os.path.join(tmp, "src.tar")
        env = {k: os.environ[k] for k in SAFE_ENV_KEYS if k in os.environ}
        with open(archive, "wb") as fh:
            try:
                proc = subprocess.Popen([which("ssh"), *self._base(), cmd[:8000]], stdin=subprocess.DEVNULL,
                                        stdout=fh, stderr=subprocess.DEVNULL, env=env)
            except OSError:
                return "", "failed"
            start = time.monotonic()
            while proc.poll() is None:
                time.sleep(0.2)
                if os.path.getsize(archive) > MAX_SNAPSHOT:
                    proc.kill()
                    proc.wait()
                    return "", "too_big"
                if time.monotonic() - start > 300:
                    proc.kill()
                    proc.wait()
                    return "", "timeout"
        if proc.returncode != 0:
            return "", "failed"
        dest = os.path.join(tmp, "src")
        os.mkdir(dest, 0o700)
        try:
            with tarfile.open(archive) as tf:
                members = tf.getmembers()
                if len(members) > MAX_MEMBERS or sum(m.size for m in members) > 2 * MAX_SNAPSHOT:
                    return "", "too_big"
                tf.extractall(dest, members=members, filter="data")    # niente percorsi fuori, link strani, device
        except (tarfile.TarError, OSError):
            return "", "failed"
        finally:
            try:
                os.unlink(archive)
            except OSError:
                pass
        return dest, ""


def make_transport(cfg: Internal) -> Transport:
    return SshTransport(cfg) if cfg.transport == "ssh" else LocalTransport(cfg)


def private_tmp() -> tempfile.TemporaryDirectory:
    tmp = tempfile.TemporaryDirectory(prefix="apernix-src-")
    os.chmod(tmp.name, 0o700)
    return tmp

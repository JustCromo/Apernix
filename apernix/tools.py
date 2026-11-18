"""Esecuzione dei tool di terze parti (nmap, nuclei, ...) in modo prudente.

- mai una shell: argomenti passati come lista, niente iniezione di comandi
- ambiente ridotto: il tool non eredita variabili e segreti della sessione
- uscita scritta in un file temporaneo privato, letto solo se sotto un limite fisso
- tempo massimo: oltre, il tool viene fermato
"""

from __future__ import annotations

import os
import shutil
import subprocess
import tempfile
from dataclasses import dataclass

MAX_OUTPUT = 20 * 1024 * 1024
SAFE_ENV_KEYS = ("PATH", "HOME", "LANG", "LC_ALL", "USER", "LOGNAME", "TMPDIR", "XDG_CONFIG_HOME", "XDG_CACHE_HOME")


@dataclass
class ToolResult:
    ok: bool
    output: bytes = b""
    reason: str = ""      # missing | timeout | too_big | failed


def which(name: str) -> str | None:
    return shutil.which(name)


def run_tool(argv: list[str], out_flag_builder, timeout: float) -> ToolResult:
    """Lancia `argv` aggiungendo gli argomenti per scrivere su file (`out_flag_builder(path)`)."""
    exe = which(argv[0])
    if exe is None:
        return ToolResult(False, reason="missing")
    env = {k: os.environ[k] for k in SAFE_ENV_KEYS if k in os.environ}
    env["NO_COLOR"] = "1"
    with tempfile.TemporaryDirectory(prefix="apernix-") as tmp:
        os.chmod(tmp, 0o700)
        out_path = os.path.join(tmp, "out")
        cmd = [exe, *argv[1:], *out_flag_builder(out_path)]
        try:
            proc = subprocess.run(cmd, stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL,
                                  stderr=subprocess.DEVNULL, env=env, timeout=timeout, check=False)
        except subprocess.TimeoutExpired:
            return ToolResult(False, reason="timeout")
        except OSError:
            return ToolResult(False, reason="failed")
        try:
            st = os.lstat(out_path)
        except FileNotFoundError:
            return ToolResult(proc.returncode == 0, b"", "" if proc.returncode == 0 else "failed")
        if not os.path.isfile(out_path) or os.path.islink(out_path):
            return ToolResult(False, reason="failed")
        if st.st_size > MAX_OUTPUT:
            return ToolResult(False, reason="too_big")
        with open(out_path, "rb") as fh:
            data = fh.read(MAX_OUTPUT + 1)
        if len(data) > MAX_OUTPUT:
            return ToolResult(False, reason="too_big")
        return ToolResult(True, data)

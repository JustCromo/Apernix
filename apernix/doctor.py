"""`apernix doctor`: controlla cosa è installato e dice, per la distro in uso, come installare ciò che manca."""

from __future__ import annotations

import sys

from apernix.tools import which

# nome, a cosa serve, obbligatorio?, pacchetto (arch, debian, fedora, suse) oppure suggerimento libero
TOOLS = (
    ("nmap", "doctor.use.nmap", False, ("nmap", "nmap", "nmap", "nmap")),
    ("nuclei", "doctor.use.nuclei", False, "doctor.hint.nuclei"),
    ("semgrep", "doctor.use.semgrep", False, "doctor.hint.pip"),
    ("bandit", "doctor.use.bandit", False, "doctor.hint.pip"),
    ("trivy", "doctor.use.trivy", False, "doctor.hint.trivy"),
    ("docker", "doctor.use.docker", False, ("docker", "docker.io", "docker", "docker")),
    ("ssh", "doctor.use.ssh", False, ("openssh", "openssh-client", "openssh-clients", "openssh")),
)
INSTALL = {"arch": "sudo pacman -S {p}", "debian": "sudo apt install {p}", "fedora": "sudo dnf install {p}",
           "suse": "sudo zypper install {p}"}
FAMILIES = {"arch": ("arch", "manjaro", "endeavouros"), "debian": ("debian", "ubuntu", "raspbian", "linuxmint"),
            "fedora": ("fedora", "rhel", "centos", "rocky", "almalinux"), "suse": ("suse", "opensuse")}


def distro_family(os_release: str = "/etc/os-release") -> str:
    ids: list[str] = []
    try:
        with open(os_release, encoding="utf-8", errors="replace") as fh:
            for line in fh.read(8192).splitlines():
                key, _, value = line.partition("=")
                if key in ("ID", "ID_LIKE"):
                    ids += value.strip().strip('"').lower().split()
    except OSError:
        return ""
    for family, names in FAMILIES.items():
        if any(i in names or any(i.startswith(n) for n in names) for i in ids):
            return family
    return ""


def check(os_release: str = "/etc/os-release") -> list[dict]:
    family = distro_family(os_release)
    rows = []
    for name, use, required, pkg in TOOLS:
        found = which(name) is not None
        hint = ""
        if not found:
            if isinstance(pkg, tuple):
                idx = ("arch", "debian", "fedora", "suse").index(family) if family else -1
                hint = INSTALL[family].format(p=pkg[idx]) if family else ""
            else:
                hint = pkg
        rows.append({"tool": name, "use": use, "found": found, "required": required, "hint": hint})
    return rows


def python_ok() -> bool:
    return sys.version_info >= (3, 11)

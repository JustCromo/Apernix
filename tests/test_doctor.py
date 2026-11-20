import json
import os
import subprocess
import sys
import unittest
from unittest import mock

from apernix import cli, doctor, tools
from tests.helpers import fake_tool, tmpdir

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


def os_release(d: str, text: str) -> str:
    path = os.path.join(d, "os-release")
    with open(path, "w") as fh:
        fh.write(text)
    return path


class TestDoctor(unittest.TestCase):
    def test_families(self):
        cases = {'ID=arch\n': "arch", 'ID=manjaro\nID_LIKE=arch\n': "arch",
                 'ID=ubuntu\nID_LIKE=debian\n': "debian", 'ID=raspbian\n': "debian",
                 'ID="fedora"\n': "fedora", 'ID=rocky\nID_LIKE="rhel centos fedora"\n': "fedora",
                 'ID=opensuse-tumbleweed\nID_LIKE="opensuse suse"\n': "suse", 'ID=nixos\n': "", "": ""}
        with tmpdir() as d:
            for text, family in cases.items():
                self.assertEqual(doctor.distro_family(os_release(d, text)), family, text)
            self.assertEqual(doctor.distro_family(os.path.join(d, "manca")), "")

    def test_hints_follow_distro(self):
        with tmpdir() as d, tmpdir() as empty, mock.patch.dict(os.environ, {"PATH": empty}):
            rows = {r["tool"]: r for r in doctor.check(os_release(d, "ID=debian\n"))}
            self.assertEqual(rows["nmap"]["hint"], "sudo apt install nmap")
            self.assertEqual(rows["docker"]["hint"], "sudo apt install docker.io")
            rows = {r["tool"]: r for r in doctor.check(os_release(d, "ID=arch\n"))}
            self.assertEqual(rows["ssh"]["hint"], "sudo pacman -S openssh")
            self.assertEqual(rows["nmap"]["found"], False)

    def test_found_tool_has_no_hint(self):
        with tmpdir() as b, tmpdir() as d:
            fake_tool(b, "nmap", "exit 0")
            with mock.patch.dict(os.environ, {"PATH": b}):
                row = next(r for r in doctor.check(os_release(d, "ID=arch\n")) if r["tool"] == "nmap")
            self.assertTrue(row["found"])
            self.assertEqual(row["hint"], "")

    def test_cli_json(self):
        import contextlib
        import io
        buf = io.StringIO()
        with contextlib.redirect_stdout(buf):
            code = cli.main(["doctor", "--json"])
        data = json.loads(buf.getvalue())
        self.assertEqual(code, 0)
        self.assertTrue(data["ok"])
        self.assertEqual({r["tool"] for r in data["tools"]},
                         {"nmap", "nuclei", "semgrep", "bandit", "trivy", "docker", "ssh"})

    def test_which_ignores_python_dir_outside_venv(self):
        with tmpdir() as b, tmpdir() as empty:
            fake_tool(b, "semgrep", "exit 0")
            with mock.patch.dict(os.environ, {"PATH": empty}), \
                    mock.patch.object(sys, "prefix", "/usr"), mock.patch.object(sys, "base_prefix", "/usr"), \
                    mock.patch.object(sys, "executable", os.path.join(b, "python")):
                self.assertIsNone(tools.which("semgrep"))      # fuori da un venv non si cerca accanto a Python

    def test_which_finds_tool_next_to_venv_python(self):
        with tmpdir() as b, tmpdir() as empty:
            fake_tool(b, "semgrep", "exit 0")
            with mock.patch.dict(os.environ, {"PATH": empty}), \
                    mock.patch.object(sys, "prefix", "/venv"), mock.patch.object(sys, "base_prefix", "/usr"), \
                    mock.patch.object(sys, "executable", os.path.join(b, "python")):
                self.assertEqual(tools.which("semgrep"), os.path.join(b, "semgrep"))


class TestInstaller(unittest.TestCase):
    def test_script_syntax_and_flags(self):
        script = os.path.join(REPO, "install.sh")
        self.assertTrue(os.access(script, os.X_OK))
        self.assertEqual(subprocess.run(["sh", "-n", script]).returncode, 0)
        with open(script) as fh:
            text = fh.read()
        self.assertNotIn("sudo ", text.replace("sudo apt install python3-venv", ""))     # mai sudo da solo
        self.assertIn("--uninstall", text)

    def test_uninstall_only_touches_its_own_paths(self):
        with tmpdir() as d:
            home, bin_dir = os.path.join(d, "share"), os.path.join(d, "bin")
            os.makedirs(home)
            os.makedirs(bin_dir)
            for name in ("apernix", "altro"):
                with open(os.path.join(bin_dir, name), "w"):
                    pass
            env = {"PATH": os.environ["PATH"], "HOME": d, "APERNIX_HOME": home, "APERNIX_BIN": bin_dir}
            subprocess.run(["sh", os.path.join(REPO, "install.sh"), "--uninstall"], env=env, check=True,
                           capture_output=True)
            self.assertEqual(os.listdir(bin_dir), ["altro"])
            self.assertFalse(os.path.exists(home))


if __name__ == "__main__":
    unittest.main()

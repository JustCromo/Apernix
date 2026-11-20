import json
import os
import unittest
from unittest import mock

from apernix import tools
from apernix.scope import ScopeError, parse_target_url, scope_from_dict, valid_port_spec
from apernix.sources import nmap, nuclei
from tests.helpers import fake_tool, tmpdir

NMAP_XML = b"""<?xml version="1.0"?>
<nmaprun><host><ports>
<port protocol="tcp" portid="22"><state state="open"/><service name="ssh" product="OpenSSH" version="9.6"/></port>
<port protocol="tcp" portid="8000"><state state="open"/><service name="http" product="Werkzeug"/></port>
<port protocol="tcp" portid="5432"><state state="open"/><service name="postgresql" product="PostgreSQL DB"/></port>
<port protocol="tcp" portid="2375"><state state="open"/><service name="docker"/></port>
<port protocol="tcp" portid="21"><state state="open"/><service name="ftp"/></port>
<port protocol="tcp" portid="443"><state state="closed"/><service name="https"/></port>
</ports></host></nmaprun>"""


class TestScopeNetwork(unittest.TestCase):
    def test_host_option_injection_rejected(self):
        for url in ("http://-oX/", "http://-iL/etc/passwd", "http://a_b/", "http://exa mple/"):
            with self.assertRaises(ValueError, msg=url):
                parse_target_url(url)

    def test_port_specs(self):
        for ok in ("none", "top100", "top1000", "all", "22", "22,80,8000-8100"):
            self.assertTrue(valid_port_spec(ok), ok)
        for bad in ("", "0", "70000", "80-22", "22;rm -rf", "-p-", "22, 80", 22, None, "1," * 100):
            self.assertFalse(valid_port_spec(bad), bad)

    def test_bad_ports_in_scope(self):
        with self.assertRaises(ScopeError):
            scope_from_dict({"authorization": {"confirmed": True}, "target": [{"url": "http://x/"}],
                             "network": {"ports": "--script=evil"}})


class TestRunner(unittest.TestCase):
    def setUp(self):
        self.tmp = tmpdir()
        self.bin = self.tmp.name
        self.env = mock.patch.dict(os.environ, {"PATH": self.bin, "APERNIX_SECRET_TEST": "s3cret"})
        self.env.start()

    def tearDown(self):
        self.env.stop()
        self.tmp.cleanup()

    def test_missing(self):
        r = tools.run_tool(["nonexistent-tool"], lambda p: [], 5)
        self.assertEqual((r.ok, r.reason), (False, "missing"))

    def test_env_not_leaked_and_args_literal(self):
        fake_tool(self.bin, "faketool", 'out="$3"; printf "%s|%s" "$APERNIX_SECRET_TEST" "$1" > "$out"')
        r = tools.run_tool(["faketool", "$(touch /tmp/apernix-pwned);x"], lambda p: ["-o", p], 5)
        # argomento passato così com'è, nessuna shell lo interpreta; il segreto non arriva al tool
        self.assertTrue(r.ok)
        self.assertEqual(r.output, b"|$(touch /tmp/apernix-pwned);x")
        self.assertFalse(os.path.exists("/tmp/apernix-pwned"))

    def test_timeout(self):
        fake_tool(self.bin, "slowtool", "exec /bin/sleep 5")
        r = tools.run_tool(["slowtool"], lambda p: [], 0.5)
        self.assertEqual(r.reason, "timeout")

    def test_too_big(self):
        fake_tool(self.bin, "bigtool", '/usr/bin/head -c 21000000 /dev/zero > "$2"')
        r = tools.run_tool(["bigtool"], lambda p: ["-o", p], 20)
        self.assertEqual(r.reason, "too_big")

    def test_symlink_output_rejected(self):
        fake_tool(self.bin, "linktool", '/bin/ln -s /etc/passwd "$2"')
        r = tools.run_tool(["linktool"], lambda p: ["-o", p], 5)
        self.assertFalse(r.ok)


class TestNmap(unittest.TestCase):
    def test_argv(self):
        argv = nmap.build_argv("192.168.1.10", "top1000")
        self.assertEqual(argv[0], "nmap")
        self.assertEqual(argv[-1], "192.168.1.10")
        self.assertIn("--top-ports", argv)
        self.assertEqual(nmap.port_args("22,80"), ["-p", "22,80"])

    def test_output_flag_before_host(self):
        with tmpdir() as b, mock.patch.dict(os.environ, {"PATH": b}):
            fake_tool(b, "nmap", 'for a; do last="$a"; done; while [ "$1" != "-oX" ]; do shift; done; '
                                 'printf "%s" "$last" > "$2"')
            r = nmap.scan("10.0.0.1", "top100")
            self.assertEqual(r.output, b"10.0.0.1")

    def test_parse_and_findings(self):
        ports = nmap.parse(NMAP_XML)
        self.assertEqual([p["port"] for p in ports], [22, 8000, 5432, 2375, 21])
        ids = sorted(f.check for f in nmap.findings("h", ports, [8000]))
        self.assertEqual(ids, ["NET-CLEARTEXT", "NET-DB-EXPOSED", "NET-DOCKER-API", "NET-SURFACE"])
        surface = [f for f in nmap.findings("h", ports, [8000]) if f.check == "NET-SURFACE"][0]
        self.assertFalse(any("8000/" in e for e in surface.evidence))

    def test_entities_rejected(self):
        bomb = b'<?xml version="1.0"?><!DOCTYPE x [<!ENTITY a "aaaa">]><nmaprun>&a;</nmaprun>'
        with self.assertRaises(ValueError):
            nmap.parse(bomb)

    def test_garbage(self):
        with self.assertRaises(SyntaxError):
            nmap.parse(b"<nmaprun><host>")


class TestNuclei(unittest.TestCase):
    def test_argv_is_safe(self):
        argv = nuclei.build_argv("http://x/", 5, 10)
        self.assertIn("-ni", argv)
        self.assertIn("dos,fuzz,intrusive", argv)

    def test_parse(self):
        lines = [
            {"template-id": "git-config", "info": {"name": "Git Config Disclosure", "severity": "medium"},
             "matched-at": "http://x/.git/config"},
            {"template-id": "CVE-2021-41773", "info": {"name": "Apache Path Traversal", "severity": "critical",
             "classification": {"cve-id": ["cve-2021-41773"]}}, "matched-at": "http://x/cgi-bin/"},
            {"template-id": "tech-detect", "info": {"name": "Wappalyzer", "severity": "info"},
             "matcher-name": "flask"},
        ]
        data = "\n".join(json.dumps(x) for x in lines).encode()
        data += b"\nnot json\n[1,2]\n" + b"[" * 50000 + b"\n"
        found, tech = nuclei.parse(data)
        self.assertEqual(len(found), 2)
        crit = [f for f in found if "41773" in f.check][0]
        self.assertEqual(crit.level, "critical")
        self.assertTrue(any("cve-2021-41773" in e for e in crit.evidence))
        self.assertEqual(tech, ["flask"])        # solo la tecnologia, non il nome del template

    def test_ssh_info_templates_become_low_findings(self):
        rows = [{"template-id": "ssh-password-auth", "info": {"name": "SSH Password-based Authentication",
                                                              "severity": "info"}, "matched-at": "h:22"},
                {"template-id": "ssh-auth-methods", "info": {"name": "SSH Auth Methods", "severity": "info"},
                 "matched-at": "h:22"}]
        found, tech = nuclei.parse("\n".join(json.dumps(x) for x in rows).encode())
        self.assertEqual([f.check for f in found], ["NUC-ssh-password-auth"])
        self.assertEqual(found[0].level, "low")
        self.assertEqual(tech, [])                              # i nomi dei template non sono tecnologie

    def test_duplicates_and_flood(self):
        line = json.dumps({"template-id": "x", "info": {"name": "\x1b[31mevil", "severity": "high"},
                           "matched-at": "http://x/"}).encode()
        found, _ = nuclei.parse(b"\n".join([line] * 100000))
        self.assertEqual(len(found), 1)
        self.assertNotIn("\x1b", found[0].title)


if __name__ == "__main__":
    unittest.main()

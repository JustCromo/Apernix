import json
import os
import unittest
from unittest import mock

from apernix import discover, tools
from tests.helpers import LocalServer, fake_tool, tmpdir

DOCKER = [
    {"Names": "racoonix-caddy-1", "Ports": "0.0.0.0:80->80/tcp, [::]:80->80/tcp, 0.0.0.0:443->443/tcp, 443/udp",
     "Labels": "com.docker.compose.project=racoonix,com.docker.compose.service=caddy"},
    {"Names": "racoonix-db-1", "Ports": "5432/tcp", "Labels": ""},
    {"Names": "dev\x1b[31m", "Ports": "127.0.0.1:8080->80/tcp", "Labels": ""},
]
SS = """LISTEN 0 4096 0.0.0.0:80 0.0.0.0:*
LISTEN 0 128 127.0.0.1:631 0.0.0.0:*
LISTEN 0 128 [::1]:9000 [::]:*
LISTEN 0 4096 192.168.1.187:3000 0.0.0.0:*
garbage line
"""


class TestDiscoverParsing(unittest.TestCase):
    def setUp(self):
        self.tmp = tmpdir()
        b = self.tmp.name
        with open(os.path.join(b, "docker.json"), "w") as fh:
            fh.write("\n".join(json.dumps(x) for x in DOCKER) + "\nnot json\n")
        with open(os.path.join(b, "ss.txt"), "w") as fh:
            fh.write(SS)
        fake_tool(b, "docker", f'/bin/cat "{b}/docker.json"')
        fake_tool(b, "ss", f'/bin/cat "{b}/ss.txt"')
        self.env = mock.patch.dict(os.environ, {"PATH": b})
        self.env.start()

    def tearDown(self):
        self.env.stop()
        self.tmp.cleanup()

    def test_docker(self):
        ports = discover.docker_ports("10.0.0.5")
        self.assertIn(("10.0.0.5", 443, "racoonix (caddy)"), ports)
        self.assertIn(("10.0.0.5", 80, "racoonix (caddy)"), ports)
        local = [p for p in ports if p[1] == 8080][0]
        self.assertEqual(local[0], "127.0.0.1")
        self.assertNotIn("\x1b", local[2])
        self.assertFalse(any(p[1] == 5432 for p in ports))   # porta non pubblicata

    def test_ss(self):
        ports = discover.listening_ports("10.0.0.5")
        self.assertIn(("10.0.0.5", 80, ""), ports)
        self.assertIn(("127.0.0.1", 631, ""), ports)
        self.assertIn(("192.168.1.187", 3000, ""), ports)
        self.assertFalse(any(p[1] == 9000 for p in ports))

    def test_tools_missing(self):
        with mock.patch.dict(os.environ, {"PATH": "/nonexistent"}):
            self.assertEqual(discover.docker_ports("10.0.0.5"), [])
            self.assertEqual(discover.listening_ports("10.0.0.5"), [])


class TestProbe(unittest.TestCase):
    def test_probe_title_and_redirect(self):
        routes = {"/": (200, [], b"<html><title>Racoonix \x1b[2J</title></html>")}
        with LocalServer(routes) as srv:
            scheme, title, redirect = discover.probe("127.0.0.1", srv.port)
            self.assertEqual((scheme, redirect), ("http", False))
            self.assertTrue(title.startswith("Racoonix"))
            self.assertNotIn("\x1b", title)
        with LocalServer({"/": (301, [("Location", "https://x/")], b"")}) as srv:
            self.assertTrue(discover.probe("127.0.0.1", srv.port)[2])

    def test_probe_closed_port(self):
        self.assertIsNone(discover.probe("127.0.0.1", 9, timeout=0.5))

    def test_discover_end_to_end(self):
        with LocalServer({"/": (200, [], b"<title>Lab</title>")}) as srv, \
                mock.patch.object(discover, "docker_ports", return_value=[("127.0.0.1", srv.port, "lab (web)")]), \
                mock.patch.object(discover, "listening_ports",
                                  return_value=[("127.0.0.1", srv.port, ""), ("127.0.0.1", 5432, "")]):
            found = discover.discover()
        self.assertEqual(len(found), 1)
        self.assertEqual((found[0].name, found[0].title, found[0].via), ("lab (web)", "Lab", "docker"))


class TestRunnerExtras(unittest.TestCase):
    def test_capture_limit_and_tick(self):
        with tmpdir() as b, mock.patch.dict(os.environ, {"PATH": b}):
            fake_tool(b, "flood", "/usr/bin/yes")
            self.assertEqual(tools.run_capture(["flood"], timeout=5, max_bytes=1000).reason, "too_big")
            fake_tool(b, "slow", '/bin/sleep 2; /bin/echo ok > "$2"')
            ticks = []
            r = tools.run_tool(["slow"], lambda p: ["-o", p], 10, tick=lambda e, m: ticks.append(e))
            self.assertTrue(r.ok)
            self.assertGreaterEqual(len(ticks), 1)


if __name__ == "__main__":
    unittest.main()

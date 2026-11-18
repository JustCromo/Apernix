import os
import unittest

from apernix.dashboard.app import Controller, _key_name, _xterm256
from apernix.dashboard.state import DashState
from apernix.dashboard.view import MIN_H, MIN_W, Canvas, Glyphs, draw
from apernix.discover import Candidate
from apernix.engine import Event
from apernix.models import Finding
from apernix.scope import load_scope
from apernix.scope_write import add_target
from tests.helpers import LocalServer, make_tls_fixture, tmpdir


class Grid(Canvas):
    def __init__(self, w=120, h=32):
        super().__init__(w, h)
        self.g = [[" "] * w for _ in range(h)]

    def put(self, y, x, text, role="text"):
        assert 0 <= y < self.h, y
        assert "\x1b" not in text and "\n" not in text
        for i, ch in enumerate(text):
            assert x + i < self.w, (y, x, text)      # mai oltre il bordo
            self.g[y][x + i] = ch

    def dump(self):
        return "\n".join("".join(r) for r in self.g)


def finding(risk_i=4, risk_p=5, title="Titolo"):
    return Finding(check="X", title=title, element="http://x/", impact=risk_i, probability=risk_p, source="t",
                   evidence=["e"])


class FakeTLS:
    def __init__(self, folder):
        self.folder = folder

    def publicly_trusted(self, host, port):
        return False

    def fetch_chain(self, host, port):
        return [b"x"]

    def describe(self, der):
        return {"subject": "s", "issuer": "Caddy Local Authority", "not_after": "-", "sha256": "AA"}

    def save_pin(self, base, host, port, der):
        import shutil
        shutil.copy(os.path.join(self.folder, "ca.crt"), os.path.join(base, "pin.pem"))
        return "pin.pem"


class TestState(unittest.TestCase):
    def test_events_update_state(self):
        s = DashState()
        s.reset_run("http://x/", ("web",))
        self.assertEqual(s.phases["nmap"].state, "skip")
        s.apply(Event("phase", {"id": "web", "state": "start"}))
        s.apply(Event("progress", {"id": "web", "frac": 0.5, "label": "x"}))
        s.apply(Event("action", {"text": "GET / → 200"}))
        s.apply(Event("finding", {"finding": finding(1, 1, "basso")}))
        s.apply(Event("finding", {"finding": finding(5, 5, "critico")}))
        self.assertEqual(s.phases["web"].frac, 0.5)
        self.assertEqual(s.requests, 1)
        self.assertEqual([f.title for f in s.findings], ["critico", "basso"])
        self.assertEqual(s.counts()["critical"], 1)
        self.assertTrue(0 < s.overall() < 1)

    def test_hostile_event_data(self):
        s = DashState()
        s.reset_run("http://x/", ("web",))
        s.apply(Event("action", {"text": "\x1b]0;pwn\x07" + "A" * 10000}))
        s.apply(Event("progress", {"id": "web", "frac": 99}))
        s.apply(Event("phase", {"id": "nonexistent", "state": "start"}))
        s.apply(Event("finding", {"finding": "not a finding"}))
        s.apply(Event("tech", {"items": ["\x1b[2J"] * 500}))
        self.assertNotIn("\x1b", s.action)
        self.assertLessEqual(len(s.action), 300)
        self.assertEqual(len(s.tech), 30)
        self.assertEqual(s.findings, [])

    def test_live_bounded(self):
        s = DashState()
        for i in range(5000):
            s.log(f"riga {i}")
        self.assertEqual(len(s.live), 300)


class TestView(unittest.TestCase):
    def render(self, s, w=120, h=32, uni=True):
        g = Grid(w, h)
        draw(g, s, Glyphs(uni))
        return g.dump()

    def test_idle_and_running(self):
        s = DashState()
        self.assertIn("Bersagli", self.render(s))
        s.reset_run("http://x/", ("web", "nuclei", "nmap"))
        s.apply(Event("action", {"text": "GET /.git/HEAD → 404"}))
        for i in range(40):
            s.apply(Event("finding", {"finding": finding(title=f"Problema {i} " + "x" * 200)}))
        out = self.render(s)
        self.assertIn("a caccia", out)
        self.assertIn("GET /.git/HEAD → 404", out)
        self.assertIn("Problemi 40", out)

    def test_small_terminal_and_ascii(self):
        s = DashState()
        self.assertIn("troppo piccola", self.render(s, MIN_W - 1, MIN_H))
        out = self.render(s, 100, 30, uni=False)
        self.assertNotIn("─", out)
        for w, h in ((MIN_W, MIN_H), (300, 80)):
            self.render(s, w, h)

    def test_modal(self):
        s = DashState()
        c = Controller("/nonexistent/scope.toml", "/tmp", spawn=lambda fn: fn(), finder=lambda: [])
        c.state = s
        c.handle_key("?")
        self.assertIn("Guida", self.render(s))
        c.handle_key("ENTER")
        self.assertIsNone(s.modal)


class TestController(unittest.TestCase):
    def ctrl(self, d, found=(), tls=None):
        c = Controller(os.path.join(d, "scope.toml"), os.path.join(d, "out"), spawn=lambda fn: fn(),
                       finder=lambda: list(found), tls=tls or FakeTLS(d), probe=lambda h, p: ("http", "Lab", False))
        c.reload_targets()
        c.start_discovery()
        c.pump()
        return c

    def test_discover_authorize_and_scan(self):
        with tmpdir() as d, LocalServer({"/": (200, [], b"<title>Lab</title>")}) as srv:
            c = self.ctrl(d, [Candidate(srv.base + "/", "lab (web)", "Lab", "docker")])
            self.assertEqual(len(c.state.targets), 1)
            self.assertFalse(c.state.targets[0].authorized)
            c.state.profile = 0                      # rapida: niente nmap/nuclei nei test
            c.handle_key("ENTER")
            self.assertEqual(c.state.modal.title, "Autorizzazione")
            c.handle_key("s")
            c.pump()
            self.assertTrue(load_scope(c.scope_path).targets[0].url.startswith(srv.base))
            self.assertFalse(c.state.running)
            self.assertIn("completata", c.state.status)
            self.assertTrue(c.state.findings)
            self.assertTrue(os.path.isdir(c.state.report))
            self.assertEqual(c.state.phases["report"].state, "done")

    def test_authorization_refused(self):
        with tmpdir() as d:
            c = self.ctrl(d, [Candidate("http://127.0.0.1:9/", "x", "", "docker")])
            c.handle_key("ENTER")
            c.handle_key("n")
            self.assertFalse(os.path.exists(c.scope_path))
            self.assertFalse(c.state.running)

    def test_private_cert_flow(self):
        with tmpdir() as d:
            if make_tls_fixture(d) is None:
                self.skipTest("openssl non disponibile")
            c = self.ctrl(d)
            started = []
            c.start_scan = started.append
            c.handle_key("a")
            for ch in "https://192.168.1.187/":
                c.handle_key(ch)
            c.handle_key("ENTER")
            self.assertIn("Caddy Local Authority", "\n".join(c.state.modal.lines))
            c.handle_key("s")
            self.assertEqual(c.state.modal.title, "Autorizzazione")
            c.handle_key("s")
            self.assertEqual(load_scope(c.scope_path).targets[0].ca_file, os.path.join(d, "pin.pem"))
            self.assertEqual(started, ["https://192.168.1.187:443/"])

    def test_bad_url_input(self):
        with tmpdir() as d:
            c = self.ctrl(d)
            c.handle_key("a")
            for ch in "file:///etc/passwd":
                c.handle_key(ch)
            c.handle_key("ENTER")
            self.assertEqual(c.state.modal.kind, "info")
            self.assertFalse(os.path.exists(c.scope_path))

    def test_input_editing_and_escape(self):
        with tmpdir() as d:
            c = self.ctrl(d)
            c.handle_key("a")
            for k in ("x", "y", "BACKSPACE", "z", "UP"):
                c.handle_key(k)
            self.assertEqual(c.state.modal.text, "xz")
            c.handle_key("ESC")
            self.assertIsNone(c.state.modal)

    def test_quit_confirm_while_running_and_cancel(self):
        with tmpdir() as d:
            c = self.ctrl(d)
            c.state.running = True
            c.handle_key("q")
            self.assertFalse(c.quit)
            c.handle_key("n")
            self.assertFalse(c.quit)
            c.handle_key("x")
            self.assertTrue(c.cancel.is_set())
            c.handle_key("q")
            c.handle_key("s")
            self.assertTrue(c.quit)

    def test_cancelled_run_marks_phases(self):
        import apernix.dashboard.app as app
        real = app.run_scan

        def cancelled_run(sc, client, phases, emit=None, cancel=None):
            cancel.set()          # come se l'utente premesse x appena partita l'analisi
            return real(sc, client, phases, emit=emit, cancel=cancel)
        with tmpdir() as d, LocalServer({"/": (200, [], b"ok")}) as srv:
            add_target(os.path.join(d, "scope.toml"), srv.base + "/", "lab", ports="none")
            c = self.ctrl(d)
            c.state.profile = 0
            app.run_scan = cancelled_run
            try:
                c.start_scan(srv.base + "/")
                c.pump()
            finally:
                app.run_scan = real
            self.assertIn("fermata", c.state.status)
            self.assertTrue(all(p.state != "run" for p in c.state.phases.values()))

    def test_finding_detail_and_navigation(self):
        with tmpdir() as d:
            c = self.ctrl(d)
            for i in range(3):
                c.state.findings.append(finding(title=f"P{i}"))
            c.handle_key("4")
            c.handle_key("DOWN")
            c.handle_key("ENTER")
            self.assertEqual(c.state.modal.title, "P1")

    def test_broken_scope_does_not_crash(self):
        with tmpdir() as d:
            path = os.path.join(d, "scope.toml")
            with open(path, "w") as fh:
                fh.write("[[[[")
            os.chmod(path, 0o600)
            c = self.ctrl(d)
            self.assertIn("non valido", c.state.status)

    def test_discovery_errors_swallowed(self):
        with tmpdir() as d:
            def boom():
                raise RuntimeError("x")
            c = Controller(os.path.join(d, "s.toml"), d, spawn=lambda fn: fn(), finder=boom)
            c.start_discovery()
            c.pump()
            self.assertFalse(c.state.discovering)


class TestHelpers(unittest.TestCase):
    def test_to_ascii_keeps_length(self):
        from apernix.dashboard.app import to_ascii
        for text in ("Vulnerabilità note", "GET / → 200", "4 × 5", "日本"):
            out = to_ascii(text)
            self.assertEqual(len(out), len(text))
            self.assertTrue(out.isascii())
        self.assertEqual(to_ascii("Vulnerabilità"), "Vulnerabilita")

    def test_keys_and_colors(self):
        import curses
        self.assertEqual(_key_name("\t", curses), "TAB")
        self.assertEqual(_key_name(curses.KEY_UP, curses), "UP")
        self.assertEqual(_key_name("a", curses), "a")
        self.assertEqual(_xterm256("#000000"), 16)
        self.assertEqual(_xterm256("#FFFFFF"), 231)


if __name__ == "__main__":
    unittest.main()

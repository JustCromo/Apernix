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

    def test_guide_is_full_page(self):
        s = DashState()
        c = Controller("/nonexistent/scope.toml", "/tmp", spawn=lambda fn: fn(), finder=lambda: [])
        c.state = s
        c.handle_key("?")
        self.assertIsNotNone(s.detail)
        self.assertIn("Navigazione", self.render(s))
        c.handle_key("q")                        # q in un dettaglio torna indietro, non esce
        self.assertIsNone(s.detail)
        self.assertFalse(c.quit)

    def test_every_panel_zoomed_and_detail(self):
        from apernix.dashboard.app import finding_detail, phase_detail
        s = DashState()
        s.reset_run("http://x/", ("web", "nuclei", "nmap"))
        s.apply(Event("finding", {"finding": finding()}))
        s.apply(Event("services", {"host": "h", "items": ["22/tcp ssh"]}))
        for z in range(5):
            s.zoom = z
            out = self.render(s)
            self.assertIn(f"{z + 1} ", out)
        s.zoom = None
        s.detail = finding_detail(s.findings[0])
        self.assertIn("Come risolvere", self.render(s))
        s.detail = phase_detail(s, "nuclei")
        self.assertIn("ProjectDiscovery", self.render(s))

    def test_tabs_and_footer_are_contextual(self):
        from apernix.dashboard.view import footer_keys
        s = DashState()
        self.assertIn("1 Bersagli", self.render(s))
        self.assertIn("apri", dict(footer_keys(s)).values())
        s.zoom = 0
        self.assertIn("analizza", dict(footer_keys(s)).values())
        s.zoom = None
        s.focus = 3
        self.assertIn("apri", dict(footer_keys(s)).values())
        s.zoom = 3
        self.assertIn("dettagli", dict(footer_keys(s)).values())
        s.running = True
        self.assertEqual(footer_keys(s)[0][0], "x")

    def test_http_segments(self):
        from apernix.dashboard.state import http_segments
        segs = http_segments("GET /.git/HEAD → 404")
        self.assertEqual([r for _, r in segs], ["accent", "text", "faint", "muted"])
        self.assertEqual(http_segments("GET / → 200")[-1][1], "ok")
        self.assertEqual(http_segments("GET / → 500")[-1][1], "warn")
        self.assertEqual(http_segments("GET / → nessuna risposta")[-1][1], "alert")
        self.assertEqual(http_segments("testo normale"), [("testo normale", "text")])


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
            c.handle_key("ENTER")                    # vista d'insieme: apre la sezione Bersagli
            self.assertEqual(c.state.zoom, 0)
            c.handle_key("ENTER")                    # sezione aperta: agisce sulla riga
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
            c.handle_key("4")                     # ingrandisce i Problemi e li mette a fuoco
            self.assertEqual((c.state.zoom, c.state.focus), (3, 3))
            c.handle_key("DOWN")
            c.handle_key("ENTER")
            self.assertEqual(c.state.detail.title, "P1")
            c.handle_key("DOWN")
            c.handle_key("ESC")
            self.assertIsNone(c.state.detail)
            c.handle_key("4")                     # stesso numero: torna alla vista d'insieme
            self.assertIsNone(c.state.zoom)
            c.handle_key("2")
            c.handle_key("ESC")
            self.assertIsNone(c.state.zoom)
            c.handle_key("q")                     # q senza zoom e senza analisi: esce
            self.assertTrue(c.quit)

    def test_enter_opens_section_on_same_row(self):
        with tmpdir() as d:
            c = self.ctrl(d)
            for i in range(5):
                c.state.findings.append(finding(title=f"P{i}"))
            c.state.focus = 3
            c.handle_key("DOWN")
            c.handle_key("DOWN")                  # nella vista d'insieme scendo sulla riga 3
            c.handle_key("ENTER")                 # Invio apre la sezione...
            self.assertEqual((c.state.zoom, c.state.finding_sel), (3, 2))   # ...con il cursore lì
            self.assertIsNone(c.state.detail)
            c.handle_key("ENTER")                 # Invio nella sezione aperta: dettaglio di quella riga
            self.assertEqual(c.state.detail.title, "P2")

    def test_tab_works_from_detail(self):
        with tmpdir() as d:
            c = self.ctrl(d)
            c.state.findings.append(finding(title="P0"))
            c.handle_key("4")
            c.handle_key("ENTER")
            self.assertIsNotNone(c.state.detail)
            c.handle_key("TAB")                   # dal dettaglio si passa alla sezione successiva
            self.assertIsNone(c.state.detail)
            self.assertEqual((c.state.focus, c.state.zoom), (4, 4))
            c.handle_key("ENTER")                 # Superficie aperta: Invio non apre pagine vuote
            self.assertIsNone(c.state.detail)
            c.handle_key("2")
            self.assertEqual((c.state.focus, c.state.zoom), (1, 1))

    def test_tab_cycles_all_panels(self):
        with tmpdir() as d:
            c = self.ctrl(d)
            seen = []
            for _ in range(5):
                c.handle_key("TAB")
                seen.append(c.state.focus)
            self.assertEqual(sorted(seen), [0, 1, 2, 3, 4])
            c.handle_key("BTAB")
            self.assertEqual(c.state.focus, 4)

    def test_live_scroll_and_follow(self):
        with tmpdir() as d:
            c = self.ctrl(d)
            for i in range(50):
                c.state.log(f"riga {i}")
            c.state.focus = 1
            c.handle_key("UP")
            c.handle_key("UP")
            self.assertEqual(c.state.live_scroll, 2)
            c.state.log("nuova")                   # chi sta leggendo non viene spostato
            self.assertEqual(c.state.live_scroll, 3)
            c.handle_key("END")
            self.assertEqual(c.state.live_scroll, 0)

    def test_focus_moves_intelligently(self):
        with tmpdir() as d, LocalServer({"/": (200, [], b"ok")}) as srv:
            add_target(os.path.join(d, "scope.toml"), srv.base + "/", "lab", ports="none")
            c = self.ctrl(d)
            c.state.profile = 0
            seen = []
            orig = c.state.reset_run

            def spy(url, phases):
                orig(url, phases)
                seen.append(c.state.focus)
            c.state.reset_run = spy
            c.handle_key("ENTER")
            c.handle_key("ENTER")
            c.pump()
            self.assertEqual(seen, [1])                 # durante l'analisi: Live
            self.assertEqual(c.state.focus, 3)          # alla fine: Problemi, il più grave selezionato
            self.assertEqual(c.state.finding_sel, 0)

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

    def test_escape_sequences(self):
        import curses

        from apernix.dashboard.app import _read_escape

        class Win:
            def __init__(self, chars):
                self.chars = list(chars)

            def nodelay(self, flag):
                pass

            def timeout(self, ms):
                pass

            def get_wch(self):
                if not self.chars:
                    raise curses.error()
                return self.chars.pop(0)
        self.assertEqual(_read_escape(Win("[B"), curses), "DOWN")
        self.assertEqual(_read_escape(Win("OA"), curses), "UP")
        self.assertEqual(_read_escape(Win("[6~"), curses), "PGDN")
        self.assertEqual(_read_escape(Win(""), curses), "ESC")
        self.assertEqual(_read_escape(Win("[99X"), curses), "")      # sequenza sconosciuta: ignorata

    def test_keys_and_colors(self):
        import curses
        self.assertEqual(_key_name("\t", curses), "TAB")
        self.assertEqual(_key_name(curses.KEY_UP, curses), "UP")
        self.assertEqual(_key_name("a", curses), "a")
        self.assertEqual(_xterm256("#000000"), 16)
        self.assertEqual(_xterm256("#FFFFFF"), 231)


if __name__ == "__main__":
    unittest.main()

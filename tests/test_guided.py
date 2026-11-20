import os
import stat
import tomllib
import unittest
from unittest import mock

import requests

from apernix import cli
from apernix.discover import Candidate
from apernix.guided import Guided
from apernix.scope import ScopeError, load_scope, scope_from_dict
from apernix.scope_write import add_target
from apernix.web.http import SafeClient
from tests.helpers import TLSServer, make_tls_fixture, scope_file, tmpdir

PEM = "-----BEGIN CERTIFICATE-----\nMIIB\n-----END CERTIFICATE-----\n"   # sembra un certificato ma non lo è


def scripted(answers):
    it = iter(answers)

    def ask(_prompt):
        value = next(it)
        if isinstance(value, BaseException) or (isinstance(value, type) and issubclass(value, BaseException)):
            raise value
        return value
    return ask


class TestScopeWrite(unittest.TestCase):
    def test_create_private_and_valid(self):
        with tmpdir() as d:
            path = os.path.join(d, "scope.toml")
            sc = add_target(path, "http://192.168.1.10:8000/", "Racoonix", ports="top100")
            self.assertEqual(stat.S_IMODE(os.stat(path).st_mode), 0o600)
            self.assertEqual(sc.targets[0].url, "http://192.168.1.10:8000/")
            self.assertEqual(load_scope(path).ports, "top100")

    def test_append_without_duplicates_and_keep_limits(self):
        with tmpdir() as d:
            path = scope_file(d, "http://127.0.0.1:9/")
            add_target(path, "http://127.0.0.1:9", "")
            add_target(path, "http://127.0.0.2/", "due")
            sc = load_scope(path)
            self.assertEqual([x.url for x in sc.targets], ["http://127.0.0.1:9/", "http://127.0.0.2:80/"])
            self.assertEqual(sc.rate, 50.0)

    def test_toml_injection_neutralized(self):
        with tmpdir() as d:
            path = os.path.join(d, "scope.toml")
            evil_name = 'x"\n[authorization]\nconfirmed = false\n#'
            add_target(path, 'http://h/a"b/', evil_name)
            with open(path, "rb") as fh:
                doc = tomllib.load(fh)
            self.assertIs(doc["authorization"]["confirmed"], True)
            self.assertEqual(len(doc["target"]), 1)
            self.assertNotIn("\n", doc["target"][0]["name"])
            self.assertEqual(doc["target"][0]["url"], 'http://h:80/a"b/')

    def test_bad_url_and_symlink_refused(self):
        with tmpdir() as d:
            path = os.path.join(d, "scope.toml")
            with self.assertRaises(ScopeError):
                add_target(path, "file:///etc/passwd")
            self.assertFalse(os.path.exists(path))
            victim = os.path.join(d, "victim.toml")
            add_target(victim, "http://h/")
            os.symlink(victim, path)
            with self.assertRaises(ScopeError):
                add_target(path, "http://h2/")

    def test_ca_file(self):
        with tmpdir() as d:
            if make_tls_fixture(d) is None:
                self.skipTest("openssl non disponibile")
            with open(os.path.join(d, "bad.crt"), "w") as fh:
                fh.write("not a cert")
            with open(os.path.join(d, "fake.crt"), "w") as fh:
                fh.write(PEM)
            base = {"authorization": {"confirmed": True}}
            sc = scope_from_dict(dict(base, target=[{"url": "https://h/", "ca_file": "ca.crt"}]), d)
            self.assertEqual(sc.targets[0].ca_file, os.path.join(d, "ca.crt"))
            for bad in ("bad.crt", "fake.crt", "missing.crt", d, 5, "/dev/zero"):
                with self.assertRaises(ScopeError, msg=bad):
                    scope_from_dict(dict(base, target=[{"url": "https://h/", "ca_file": bad}]), d)

    def test_client_uses_ca_file(self):
        with tmpdir() as d:
            if make_tls_fixture(d) is None:
                self.skipTest("openssl non disponibile")
            sc = scope_from_dict({"authorization": {"confirmed": True},
                                  "target": [{"url": "https://h/", "ca_file": "ca.crt"}, {"url": "https://k/"}]}, d)
            c = SafeClient(sc)
            seen = []

            def fake(method, url, **kw):
                seen.append(kw["verify"])
                raise requests.ConnectionError()
            c.session.request = fake
            for url in ("https://h/", "https://k/"):
                with self.assertRaises(requests.ConnectionError):
                    c.get(url)
            self.assertEqual(seen, [os.path.join(d, "ca.crt"), True])


class FakeTLS:
    """Finto modulo TLS: certificato non pubblico, catena [foglia, emittente]."""

    def __init__(self, folder, public=False):
        self.folder, self.public, self.pins = folder, public, 0

    def publicly_trusted(self, host, port):
        return self.public

    def fetch_chain(self, host, port):
        return [b"leaf", b"top"]

    def describe(self, der):
        return {"subject": "srv", "issuer": "Caddy Local Authority", "not_after": "domani", "sha256": "AA:BB"}

    def save_pin(self, base, host, port, der):
        import shutil
        self.pins += 1
        shutil.copy(os.path.join(self.folder, "ca.crt"), os.path.join(base, "pin.pem"))
        return "pin.pem"


class TestGuided(unittest.TestCase):
    def make(self, d, answers, runner=None, found=(), tls=None, detector=lambda url: None):
        said = []
        g = Guided(os.path.join(d, "scope.toml"), os.path.join(d, "out"), ask=scripted(answers),
                   say=said.append, runner=runner or (lambda *a: "ok"), finder=lambda: list(found),
                   tls=tls or FakeTLS(d), probe=lambda host, port: ("http", "Titolo", False), detector=detector)
        return g, said

    def test_discover_add_and_full_scan(self):
        calls = []
        cand = [Candidate("http://127.0.0.1:8000/", "racoonix (app)", "Racoonix", "docker")]
        with tmpdir() as d:
            g, said = self.make(d, ["n", "1", "si", "", "", "q"],
                                runner=lambda sc, c, ph: calls.append((sc.targets[0].name, ph)) or "ok",
                                found=cand)
            self.assertEqual(g.run(), 0)
            sc = load_scope(g.scope_path)
            self.assertEqual(sc.rate, 20.0)          # bersaglio in rete privata: ritmo più alto
            self.assertEqual(sc.ports, "top1000")
        self.assertEqual(calls, [("racoonix app", ("web", "nuclei", "nmap", "inside"))])

    def test_nothing_found(self):
        with tmpdir() as d:
            g, said = self.make(d, ["n", "q"])
            g.run()
            self.assertTrue(any("Nessuna web application" in s for s in said))

    def test_authorization_required(self):
        with tmpdir() as d:
            g, _ = self.make(d, ["u", "http://127.0.0.1:8000/", "forse", "q"])
            g.run()
            self.assertFalse(os.path.exists(g.scope_path))

    def test_bad_manual_url(self):
        with tmpdir() as d:
            g, said = self.make(d, ["u", "javascript:alert(1)", "q"])
            g.run()
            self.assertFalse(os.path.exists(g.scope_path))

    def test_private_cert_trusted(self):
        with tmpdir() as d:
            if make_tls_fixture(d) is None:
                self.skipTest("openssl non disponibile")
            tls = FakeTLS(d)
            g, said = self.make(d, ["u", "https://192.168.1.187/", "si", "si", "1", "", "q"], tls=tls)
            g.run()
            self.assertEqual(load_scope(g.scope_path).targets[0].ca_file, os.path.join(d, "pin.pem"))
            self.assertEqual(load_scope(g.scope_path).targets[0].name, "Titolo")
            self.assertTrue(any("Caddy Local Authority" in s for s in said))

    def test_private_cert_refused(self):
        with tmpdir() as d:
            g, _ = self.make(d, ["u", "https://192.168.1.187/", "no", "q"])
            g.run()
            self.assertFalse(os.path.exists(g.scope_path))

    def test_public_cert_not_asked(self):
        with tmpdir() as d:
            g, said = self.make(d, ["u", "https://example.com/", "si", "1", "", "q"], tls=FakeTLS(d, public=True))
            g.run()
            self.assertEqual(load_scope(g.scope_path).targets[0].ca_file, "")
            self.assertFalse(any("Ti fidi" in s for s in said))

    def test_changed_cert_warns_and_retrusts(self):
        with tmpdir() as d:
            if make_tls_fixture(d) is None:
                self.skipTest("openssl non disponibile")
            tls = FakeTLS(d)
            outcomes = iter(["tls", "ok"])
            g, said = self.make(d, ["u", "https://192.168.1.187/", "si", "si", "1", "si", "1", "", "q"],
                                runner=lambda *a: next(outcomes), tls=tls)
            g.run()
            self.assertEqual(tls.pins, 2)
            self.assertTrue(any("ATTENZIONE" in s for s in said))

    def test_custom_profile(self):
        calls = []
        with tmpdir() as d, mock.patch("apernix.guided.which", return_value="/usr/bin/x"):
            add_target(os.path.join(d, "scope.toml"), "http://127.0.0.1:1/", ports="top100")
            g, _ = self.make(d, ["1", "3", "2", "", "", "q"], runner=lambda sc, c, ph: calls.append(ph) or "ok")
            g.run()
        self.assertEqual(calls, [("web", "nmap")])

    def test_ctrl_c_eof_and_invalid(self):
        with tmpdir() as d:
            g, said = self.make(d, [KeyboardInterrupt, "zzz", EOFError])
            self.assertEqual(g.run(), 0)
            self.assertTrue(any("non valida" in s for s in said))

    def test_unsafe_scope_reported_not_crash(self):
        with tmpdir() as d:
            path = scope_file(d, "http://127.0.0.1:1/", mode=0o666)
            g, said = self.make(d, ["q"])
            g.scope_path = path
            self.assertEqual(g.run(), 0)
            self.assertTrue(any("scrivibile" in s for s in said))

    def test_real_tofu_end_to_end(self):
        """Server HTTPS vero con CA sconosciuta: Apernix mostra il certificato, lo salva e lo usa."""
        from apernix import tlsinfo
        with tmpdir() as d:
            fx = make_tls_fixture(d)
            if fx is None:
                self.skipTest("openssl non disponibile")
            reached = []

            def runner(sc, client, phases):
                res = cli.run_scan(sc, client, phases=("web",))
                reached.extend(res.reached)
                return "ok" if res.reached else res.errors.get(sc.targets[0].url, "net")
            with TLSServer({"/": (200, [], b"ok")}, fx[1], fx[2]) as srv:
                g, said = self.make(d, ["u", srv.base + "/", "si", "si", "1", "", "q"], runner=runner, tls=tlsinfo)
                g.run()
                pin = load_scope(g.scope_path).targets[0].ca_file
                self.assertTrue(pin.endswith(".pem"))
                self.assertEqual(stat.S_IMODE(os.stat(pin).st_mode), 0o600)
                self.assertEqual(stat.S_IMODE(os.stat(os.path.dirname(pin)).st_mode), 0o700)
            self.assertEqual(reached, [srv.base + "/"])
            self.assertTrue(any("Apernix Test CA" in s for s in said))


class TestOnlyOption(unittest.TestCase):
    def test_parse(self):
        self.assertEqual(cli.parse_opts("scan", ["--only", "nmap,web"]).only, ("web", "nmap"))
        for bad in (["--only"], ["--only", "web,evil"], ["--only", ""]):
            with self.assertRaises(cli.CliError):
                cli.parse_opts("scan", bad)


if __name__ == "__main__":
    unittest.main()

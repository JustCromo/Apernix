import os
import stat
import tomllib
import unittest
from unittest import mock

from apernix import cli
from apernix.guided import Guided
from apernix.scope import ScopeError, load_scope, scope_from_dict
from apernix.scope_write import add_target
from apernix.web.http import SafeClient
from tests.helpers import scope_file, tmpdir

PEM = "-----BEGIN CERTIFICATE-----\nMIIB\n-----END CERTIFICATE-----\n"


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
            with open(os.path.join(d, "ca.crt"), "w") as fh:
                fh.write(PEM)
            with open(os.path.join(d, "bad.crt"), "w") as fh:
                fh.write("not a cert")
            base = {"authorization": {"confirmed": True}}
            sc = scope_from_dict(dict(base, target=[{"url": "https://h/", "ca_file": "ca.crt"}]), d)
            self.assertEqual(sc.targets[0].ca_file, os.path.join(d, "ca.crt"))
            for bad in ("bad.crt", "missing.crt", d, 5, "/dev/zero"):
                with self.assertRaises(ScopeError, msg=bad):
                    scope_from_dict(dict(base, target=[{"url": "https://h/", "ca_file": bad}]), d)

    def test_client_uses_ca_file(self):
        with tmpdir() as d:
            with open(os.path.join(d, "ca.crt"), "w") as fh:
                fh.write(PEM)
            sc = scope_from_dict({"authorization": {"confirmed": True},
                                  "target": [{"url": "https://h/", "ca_file": "ca.crt"}, {"url": "https://k/"}]}, d)
            c = SafeClient(sc)
            seen = []

            def fake(method, url, **kw):
                seen.append(kw["verify"])
                raise cli.requests.ConnectionError()
            c.session.request = fake
            for url in ("https://h/", "https://k/"):
                with self.assertRaises(cli.requests.ConnectionError):
                    c.get(url)
            self.assertEqual(seen, [os.path.join(d, "ca.crt"), True])


class TestGuided(unittest.TestCase):
    def make(self, d, answers, runner=None):
        said = []
        g = Guided(os.path.join(d, "scope.toml"), os.path.join(d, "out"), ask=scripted(answers),
                   say=said.append, runner=runner)
        return g, said

    def test_add_then_quit(self):
        with tmpdir() as d:
            g, said = self.make(d, ["a", "http://127.0.0.1:8000/", "Lab", "", "si", "q"])
            self.assertEqual(g.run(), 0)
            self.assertEqual(load_scope(g.scope_path).targets[0].name, "Lab")

    def test_add_refused_without_authorization(self):
        with tmpdir() as d:
            g, said = self.make(d, ["a", "http://127.0.0.1:8000/", "", "", "forse", "q"])
            g.run()
            self.assertFalse(os.path.exists(g.scope_path))

    def test_bad_ports_refused(self):
        with tmpdir() as d:
            g, _ = self.make(d, ["a", "http://127.0.0.1:8000/", "", "--script=x", "q"])
            g.run()
            self.assertFalse(os.path.exists(g.scope_path))

    def test_scan_flow_with_phase_toggle(self):
        calls = []

        def runner(sc, client, phases):
            calls.append((sc.targets[0].url, phases, len(sc.targets)))
            return "ok"
        with tmpdir() as d, mock.patch("apernix.guided.which", return_value="/usr/bin/x"):
            add_target(os.path.join(d, "scope.toml"), "http://127.0.0.1:1/", ports="top100")
            add_target(os.path.join(d, "scope.toml"), "http://127.0.0.2:1/")
            # bersaglio 2, spengo nuclei (2), Invio, confermo, Invio, esco
            g, _ = self.make(d, ["2", "2", "", "s", "", "q"], runner)
            g.run()
        self.assertEqual(calls, [("http://127.0.0.2:1/", ("web", "nmap"), 1)])

    def test_cancel_and_ctrl_c_and_eof(self):
        with tmpdir() as d:
            add_target(os.path.join(d, "scope.toml"), "http://127.0.0.1:1/")
            g, said = self.make(d, ["1", "", "n", KeyboardInterrupt, "zzz", EOFError])
            self.assertEqual(g.run(), 0)
            self.assertTrue(any("annullata" in s for s in said))
            self.assertTrue(any("non valida" in s for s in said))

    def test_no_phase_selected(self):
        with tmpdir() as d, mock.patch("apernix.guided.which", return_value=None):
            add_target(os.path.join(d, "scope.toml"), "http://127.0.0.1:1/")
            g, said = self.make(d, ["1", "1", "", "q", "q"])
            g.run()
            self.assertTrue(any("almeno una fase" in s for s in said))

    def test_unsafe_scope_reported_not_crash(self):
        with tmpdir() as d:
            path = scope_file(d, "http://127.0.0.1:1/", mode=0o666)
            g, said = self.make(d, ["q"])
            g.scope_path = path
            self.assertEqual(g.run(), 0)
            self.assertTrue(any("scrivibile" in s for s in said))


class TestOnlyOption(unittest.TestCase):
    def test_parse(self):
        self.assertEqual(cli.parse_opts("scan", ["--only", "nmap,web"]).only, ("web", "nmap"))
        for bad in (["--only"], ["--only", "web,evil"], ["--only", ""]):
            with self.assertRaises(cli.CliError):
                cli.parse_opts("scan", bad)


if __name__ == "__main__":
    unittest.main()

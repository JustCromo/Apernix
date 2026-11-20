import json
import os
import unittest
from unittest import mock

from apernix import autoconf
from apernix.guided import Guided
from apernix.scope import ScopeError, load_scope
from apernix.scope_write import add_target, set_internal
from tests.helpers import LocalServer, fake_tool, tmpdir
from tests.test_dashboard import FakeTLS
from tests.test_guided import scripted

PS_ALL = [
    {"Names": "racoonix-caddy-1", "Ports": "0.0.0.0:8443->443/tcp",
     "Labels": "com.docker.compose.project=racoonix,"
               "com.docker.compose.project.working_dir=/home/ivan/Projects/Racoonix"},
    {"Names": "racoonix-db-1", "Ports": "5432/tcp", "Labels": "com.docker.compose.project=racoonix"},
    {"Names": "altro-web-1", "Ports": "0.0.0.0:9000->80/tcp", "Labels": "com.docker.compose.project=altro"},
]
INSPECT = [{"Name": "/racoonix-db-1", "Config": {"Image": "postgres:16", "Env": [
    "POSTGRES_USER=racoonix", "POSTGRES_DB=racoonix", "POSTGRES_PASSWORD=SEGRETISSIMA"]}},
    {"Name": "/racoonix-caddy-1", "Config": {"Image": "caddy:2", "Env": ["X=1"]}}]


def fake_docker(bindir: str, ps=PS_ALL, inspect=INSPECT) -> None:
    """Finto `docker`: ps (con --filter label=...project=X) e inspect rispondono con i dati dati."""
    data = os.path.join(bindir, "docker-data.json")
    with open(data, "w") as fh:
        json.dump({"ps": ps, "inspect": inspect}, fh)
    fake_tool(bindir, "docker", f"""exec python3 -I - "$@" <<'PY'
import json, sys
d = json.load(open({data!r}))
a = sys.argv[1:]
if a[0] == "ps":
    rows = d["ps"]
    want = [x.split("project=")[1] for x in a if x.startswith("label=") and "project=" in x]
    if want:
        proj = lambda r: r["Labels"].split("com.docker.compose.project=")[1].split(",")[0]
        rows = [r for r in rows if proj(r) == want[0]]
    for r in rows:
        print(json.dumps(r))
elif a[0] == "inspect":
    print(json.dumps(d["inspect"]))
PY""")


class TestDetect(unittest.TestCase):
    def run_detect(self, url, **kw):
        with tmpdir() as b:
            fake_docker(b, **kw)
            with mock.patch.dict(os.environ, {"PATH": b + os.pathsep + os.environ["PATH"]}):
                return autoconf.detect_internal(url)

    def test_finds_project_db_and_folder(self):
        found = self.run_detect("https://127.0.0.1:8443/")
        self.assertEqual(found["project"], "racoonix")
        self.assertEqual(found["path"], "/home/ivan/Projects/Racoonix")
        self.assertEqual(found["containers"], ["racoonix-caddy-1", "racoonix-db-1"])
        self.assertEqual((found["db_container"], found["db_user"], found["db_name"]),
                         ("racoonix-db-1", "racoonix", "racoonix"))

    def test_password_never_read_into_result(self):
        self.assertNotIn("SEGRETISSIMA", json.dumps(self.run_detect("https://127.0.0.1:8443/")))

    def test_other_projects_not_mixed(self):
        found = self.run_detect("http://127.0.0.1:9000/")
        self.assertEqual(found["project"], "altro")
        self.assertNotIn("racoonix-db-1", found["containers"])

    def test_unknown_port_and_remote_host(self):
        self.assertIsNone(self.run_detect("http://127.0.0.1:1234/"))
        self.assertIsNone(self.run_detect("https://8.8.8.8:8443/"))      # mai macchine che non sono questa

    def test_no_docker(self):
        with tmpdir() as b, mock.patch.dict(os.environ, {"PATH": b}):
            self.assertIsNone(autoconf.detect_internal("http://127.0.0.1:8443/"))

    def test_hostile_labels_and_names_rejected(self):
        evil = [{"Names": "x;rm -rf /", "Ports": "0.0.0.0:8443->443/tcp",
                 "Labels": "com.docker.compose.project=bad name; id"}]
        self.assertIsNone(self.run_detect("https://127.0.0.1:8443/", ps=evil))
        weird_path = [{"Names": "web-1", "Ports": "0.0.0.0:8443->443/tcp",
                       "Labels": "com.docker.compose.project=p,com.docker.compose.project.working_dir=/tmp/a b;$(id)"}]
        found = self.run_detect("https://127.0.0.1:8443/", ps=weird_path, inspect=[])
        self.assertEqual(found["containers"], ["web-1"])    # nessuna shell: un percorso strano è solo testo


class TestSetInternal(unittest.TestCase):
    FOUND = {"transport": "local", "path": "/srv/app", "containers": ["web-1", "db-1"], "project": "x",
             "db_container": "db-1", "db_user": "app", "db_name": "appdb"}

    def test_roundtrip_and_preserved_by_add_target(self):
        with tmpdir() as d:
            path = os.path.join(d, "scope.toml")
            add_target(path, "http://127.0.0.1:8000/", "App")
            sc = set_internal(path, self.FOUND)
            self.assertEqual(sc.internal.containers, ("web-1", "db-1"))
            add_target(path, "http://127.0.0.1:8001/", "Altra")             # non deve perdere [internal]
            again = load_scope(path)
            self.assertEqual(again.internal.db_name, "appdb")
            self.assertEqual(len(again.targets), 2)
            self.assertEqual(oct(os.stat(path).st_mode & 0o777), "0o600")
            with open(path) as fh:
                self.assertNotIn("project", fh.read())

    def test_invalid_internal_not_written(self):
        with tmpdir() as d:
            path = os.path.join(d, "scope.toml")
            add_target(path, "http://127.0.0.1:8000/", "App")
            with open(path) as fh:
                before = fh.read()
            with self.assertRaises(ScopeError):
                set_internal(path, {**self.FOUND, "containers": ["ok", "-v/:/x"]})
            with open(path) as fh:
                self.assertEqual(fh.read(), before)


class TestFlows(unittest.TestCase):
    FOUND = TestSetInternal.FOUND

    def guided(self, d, answers, detector):
        said = []
        runner_calls = []
        g = Guided(os.path.join(d, "scope.toml"), os.path.join(d, "out"), ask=scripted(answers), say=said.append,
                   runner=lambda sc, client, phases: runner_calls.append(sc.internal) or "ok",
                   finder=lambda: [], tls=FakeTLS(d), probe=lambda h, p: ("http", "T", False), detector=detector)
        return g, said, runner_calls

    def test_guided_accepts(self):
        with tmpdir() as d, LocalServer({"*": (200, [], b"ok")}) as srv:
            add_target(os.path.join(d, "scope.toml"), srv.base + "/", "App")
            g, said, calls = self.guided(d, ["1", "si", "1", "", "q"], lambda url: dict(self.FOUND))
            g.run()
            self.assertEqual(calls[0].db_container, "db-1")
            self.assertEqual(load_scope(g.scope_path).internal.path, "/srv/app")

    def test_guided_refuses(self):
        with tmpdir() as d, LocalServer({"*": (200, [], b"ok")}) as srv:
            add_target(os.path.join(d, "scope.toml"), srv.base + "/", "App")
            g, said, calls = self.guided(d, ["1", "no", "1", "", "q"], lambda url: dict(self.FOUND))
            g.run()
            self.assertIsNone(calls[0])
            self.assertIsNone(load_scope(g.scope_path).internal)

    def test_guided_detector_crash_is_harmless(self):
        def boom(url):
            raise RuntimeError("x")
        with tmpdir() as d, LocalServer({"*": (200, [], b"ok")}) as srv:
            add_target(os.path.join(d, "scope.toml"), srv.base + "/", "App")
            g, said, calls = self.guided(d, ["1", "1", "", "q"], boom)
            g.run()
            self.assertEqual(len(calls), 1)

    def test_dashboard_offer(self):
        from apernix.dashboard.app import Controller
        with tmpdir() as d, LocalServer({"/": (200, [], b"<title>Lab</title>")}) as srv:
            path = os.path.join(d, "scope.toml")
            add_target(path, srv.base + "/", "Lab")
            c = Controller(path, os.path.join(d, "out"), spawn=lambda fn: fn(), finder=lambda: [],
                           tls=FakeTLS(d), probe=lambda h, p: ("http", "Lab", False),
                           detector=lambda url: dict(self.FOUND))
            c.state.profile = 0
            c.start_scan(srv.base + "/")
            self.assertEqual(c.state.modal.title, "Analisi interna")
            self.assertTrue(any("db-1" in line for line in c.state.modal.lines))
            c.handle_key("s")
            c.pump()
            self.assertEqual(load_scope(path).internal.db_container, "db-1")
            self.assertFalse(c.state.running)
            # una seconda volta nella stessa sessione non richiede di nuovo
            c.start_scan(srv.base + "/")
            self.assertIsNone(c.state.modal)

    def test_dashboard_decline_still_scans(self):
        from apernix.dashboard.app import Controller
        with tmpdir() as d, LocalServer({"/": (200, [], b"<title>Lab</title>")}) as srv:
            path = os.path.join(d, "scope.toml")
            add_target(path, srv.base + "/", "Lab")
            c = Controller(path, os.path.join(d, "out"), spawn=lambda fn: fn(), finder=lambda: [],
                           tls=FakeTLS(d), probe=lambda h, p: ("http", "Lab", False),
                           detector=lambda url: dict(self.FOUND))
            c.state.profile = 0
            c.start_scan(srv.base + "/")
            c.handle_key("n")
            c.pump()
            self.assertIsNone(load_scope(path).internal)
            self.assertIn("completata", c.state.status)


if __name__ == "__main__":
    unittest.main()

import io
import json
import os
import tarfile
import unittest
from unittest import mock

from apernix import correlate
from apernix.engine import run_scan
from apernix.inside import containers, database, logs
from apernix.inside.transport import LocalTransport, SshTransport, make_transport
from apernix.models import Finding
from apernix.scope import ScopeError, parse_internal, scope_from_dict
from apernix.sources import bandit, semgrep, trivy
from apernix.tools import ToolResult
from apernix.web.http import SafeClient
from tests.helpers import LocalServer, fake_tool, tmpdir


def make_key(d: str, mode: int = 0o600) -> str:
    path = os.path.join(d, "id_test")
    with open(path, "w") as fh:
        fh.write("not a real key")
    os.chmod(path, mode)
    return path


class TestInternalConfig(unittest.TestCase):
    def test_local_ok(self):
        c = parse_internal({"transport": "local", "path": "/srv/app", "containers": ["web", "db"],
                            "db_container": "db", "db_user": "app", "db_name": "appdb"})
        self.assertEqual((c.transport, c.path, c.containers), ("local", "/srv/app", ("web", "db")))

    def test_none_when_missing(self):
        self.assertIsNone(parse_internal(None))

    def test_ssh_ok_and_key_must_be_private(self):
        with tmpdir() as d:
            c = parse_internal({"transport": "ssh", "host": "10.0.0.5", "user": "pi", "key": make_key(d),
                                "path": "/home/pi/app"}, d)
            self.assertEqual((c.host, c.user, c.port), ("10.0.0.5", "pi", 22))
            with self.assertRaises(ScopeError):
                parse_internal({"transport": "ssh", "host": "10.0.0.5", "user": "pi",
                                "key": make_key(d, 0o644), "path": "/x"}, d)

    def test_abuse_rejected(self):
        with tmpdir() as d:
            key = make_key(d)
            ssh = {"transport": "ssh", "host": "h.example", "user": "pi", "key": key, "path": "/srv/app"}
            bad = [
                {**ssh, "host": "-oProxyCommand=evil"},
                {**ssh, "host": "a b"},
                {**ssh, "user": "root;reboot"},
                {**ssh, "user": "-oFoo"},
                {**ssh, "port": 70000},
                {**ssh, "port": True},
                {**ssh, "path": "relative/path"},
                {**ssh, "path": "/srv/../etc"},
                {**ssh, "path": "/srv/app; rm -rf /"},
                {**ssh, "key": "/nonexistent"},
                {**ssh, "containers": ["ok", "-v/:/host"]},
                {**ssh, "containers": ["a;b"]},
                {**ssh, "containers": ["x"] * 17},
                {**ssh, "db_container": "db"},                                  # mancano utente e nome
                {**ssh, "db_container": "db", "db_user": "a'; DROP", "db_name": "d"},
                {**ssh, "db_container": "db", "db_user": "a", "db_name": "d;x"},
                {"transport": "telnet", "path": "/x"},
                {"transport": "local"},                                         # niente da analizzare
                "stringa",
            ]
            for item in bad:
                with self.assertRaises(ScopeError, msg=str(item)):
                    parse_internal(item, d)

    def test_in_scope_file(self):
        doc = {"authorization": {"confirmed": True}, "target": [{"url": "http://127.0.0.1:9/"}],
               "internal": {"transport": "local", "path": "/srv/app"}}
        self.assertEqual(scope_from_dict(doc).internal.path, "/srv/app")
        doc.pop("internal")
        self.assertIsNone(scope_from_dict(doc).internal)


SEMGREP = {"results": [
    {"check_id": "python.flask.security.injection.sql", "path": "/src/app/db.py", "start": {"line": 12},
     "extra": {"severity": "ERROR", "message": "SQL costruita da input"}},
    {"check_id": "python.flask.security.injection.sql", "path": "/src/app/db.py", "start": {"line": 12},
     "extra": {"severity": "ERROR", "message": "doppione"}},
    "spazzatura", {"extra": 5},
]}
BANDIT = {"results": [
    {"test_id": "B602", "test_name": "subprocess_popen_with_shell_equals_true", "filename": "/src/run.py",
     "line_number": 7, "issue_severity": "HIGH", "issue_confidence": "MEDIUM", "issue_text": "shell=True"},
]}
TRIVY = {"Results": [
    {"Target": "requirements.txt", "Vulnerabilities": [
        {"VulnerabilityID": "CVE-2024-0001", "PkgName": "flask", "InstalledVersion": "1.0", "FixedVersion": "2.3",
         "Severity": "HIGH", "Title": "bug grave"},
        {"VulnerabilityID": "CVE-1", "PkgName": "x", "InstalledVersion": "1", "Severity": "UNKNOWN"}]},
    {"Target": ".env", "Secrets": [{"RuleID": "aws-key", "Title": "AWS key", "StartLine": 3,
                                    "Match": "AKIAIOSFODNN7EXAMPLE", "Code": {"Lines": "SEGRETISSIMO"}}]},
    {"Target": "Dockerfile", "Misconfigurations": [
        {"ID": "DS002", "Title": "Utente root", "Severity": "HIGH", "Message": "manca USER",
         "Resolution": "metti USER"},
        {"ID": "DS003", "Title": "ok", "Severity": "LOW", "Status": "PASS"}]},
]}


class TestSources(unittest.TestCase):
    def test_semgrep(self):
        found = semgrep.parse(json.dumps(SEMGREP).encode(), "/src")
        self.assertEqual(len(found), 1)
        f = found[0]
        self.assertEqual((f.element, f.impact, f.probability, f.source), ("app/db.py:12", 4, 3, "semgrep"))
        self.assertTrue(f.check.startswith("SAST-"))

    def test_bandit(self):
        f = bandit.parse(json.dumps(BANDIT).encode(), "/src")[0]
        self.assertEqual((f.check, f.element, f.impact, f.probability), ("SAST-B602", "run.py:7", 4, 3))

    def test_trivy(self):
        found = trivy.parse(json.dumps(TRIVY).encode())
        checks = {f.check for f in found}
        self.assertEqual(checks, {"DEP-CVE-2024-0001", "SEC-aws-key", "CFG-DS002"})
        blob = json.dumps([f.to_dict() for f in found])
        self.assertNotIn("AKIAIOSFODNN7EXAMPLE", blob)      # il valore del segreto non deve mai finire nel report
        self.assertNotIn("SEGRETISSIMO", blob)
        dep = next(f for f in found if f.check.startswith("DEP-"))
        self.assertIn("2.3", dep.remediation)

    def test_garbage(self):
        for mod, args in ((semgrep, ("/s",)), (bandit, ("/s",)), (trivy, ())):
            for data in (b"", b"non json", b"[]", b'{"results": 5}', b"\xff\xfe"):
                if mod is trivy and data in (b'{"results": 5}',):
                    continue
                with self.assertRaises(ValueError, msg=f"{mod.__name__} {data!r}"):
                    mod.parse(data, *args)

    def test_repeated_rule_is_one_finding(self):
        rows = [{"check_id": "python.flask.no-csrf", "path": f"/src/t/{i}.html", "start": {"line": i},
                 "extra": {"severity": "WARNING", "message": "Manca csrf_token. Altro testo lungo."}}
                for i in range(61)]
        found = semgrep.parse(json.dumps({"results": rows}).encode(), "/src")
        self.assertEqual(len(found), 1)
        self.assertIn("+60 altri punti", found[0].element)
        self.assertEqual(found[0].title, "Manca csrf_token.")
        self.assertLessEqual(len(found[0].evidence), 10)

    def test_noise_filtered(self):
        def row(rule, path, sev="WARNING"):
            return {"check_id": rule, "path": path, "start": {"line": 1}, "extra": {"severity": sev, "message": "m."}}
        rows = [row("python.django.security.django-no-csrf-token", "/src/app/t.html"),       # app non Django
                row("python.lang.security.audit.dynamic-urllib-use-detected", "/src/tools/x.py"),   # script di sviluppo
                row("python.lang.security.audit.dynamic-urllib-use-detected", "/src/app/a.py", "ERROR"),
                row("python.flask.security.injection.tainted-url-host", "/src/app/b.py", "ERROR")]
        found = {f.check: f for f in semgrep.parse(json.dumps({"results": rows}).encode(), "/src")}
        self.assertEqual(set(found), {"SAST-dynamic-urllib-use-detected", "SAST-tainted-url-host"})
        audit = found["SAST-dynamic-urllib-use-detected"]
        self.assertLessEqual(audit.risk, 6)                       # "audit" = da verificare, non vulnerabilità
        self.assertNotIn("tools", audit.element)
        self.assertEqual(found["SAST-tainted-url-host"].risk, 12)
        self.assertEqual(audit.pt, "not_tested")

    def test_django_rules_kept_for_django_projects(self):
        with tmpdir() as d:
            with open(os.path.join(d, "manage.py"), "w") as fh:
                fh.write("# django")
            rows = [{"check_id": "python.django.security.django-no-csrf-token", "path": os.path.join(d, "a.html"),
                     "start": {"line": 1}, "extra": {"severity": "WARNING", "message": "m."}}]
            self.assertEqual(len(semgrep.parse(json.dumps({"results": rows}).encode(), d)), 1)

    def test_bandit_blacklist_lowered_and_dev_dirs_skipped(self):
        rows = [{"test_id": "B310", "test_name": "blacklist", "issue_text": "url open", "issue_severity": "MEDIUM",
                 "issue_confidence": "HIGH", "filename": "/src/app/a.py", "line_number": 3},
                {"test_id": "B310", "test_name": "blacklist", "issue_text": "url open", "issue_severity": "MEDIUM",
                 "issue_confidence": "HIGH", "filename": "/src/tools/a.py", "line_number": 3}]
        found = bandit.parse(json.dumps({"results": rows}).encode(), "/src")
        self.assertEqual(len(found), 1)
        self.assertLessEqual(found[0].risk, 6)
        self.assertEqual(found[0].element, "app/a.py:3")

    def test_root_duplicates_merged(self):
        def ctr(name):
            return Finding(check="CTR-ROOT", title="root", element=name, impact=3, probability=2, source="docker",
                           evidence=["nessun utente"], remediation="x")
        cfg = Finding(check="CFG-DS-0002", title="USER", element="db/Dockerfile (+ altri file)", impact=4,
                      probability=2, source="trivy", remediation="x",
                      evidence=["m", "file: db/Dockerfile", "file: tools/altro/Dockerfile"])
        caddy, db = ctr("racoonix-caddy-1"), ctr("racoonix-db-1")
        out = correlate.simplify([caddy, db, cfg])
        self.assertTrue(any("db/Dockerfile" in e for e in db.evidence))
        self.assertFalse(any("Dockerfile" in e for e in caddy.evidence))     # niente evidenze sul container sbagliato
        left = [f for f in out if f.check == "CFG-DS-0002"]                   # resta solo il Dockerfile senza container
        self.assertEqual(len(left), 1)
        self.assertEqual(left[0].element, "tools/altro/Dockerfile")
        only = Finding(check="CFG-DS-0002", title="USER", element="db/Dockerfile", impact=4, probability=2,
                       source="trivy", evidence=["m", "file: db/Dockerfile"], remediation="x")
        self.assertEqual([f.check for f in correlate.simplify([ctr("racoonix-db-1"), only])], ["CTR-ROOT"])
        self.assertEqual(len(correlate.simplify([only])), 1)              # senza container resta il Dockerfile

    def test_non_security_rules_ignored(self):
        rows = [{"check_id": "x.batch-import", "path": "/src/a.py", "start": {"line": 1},
                 "extra": {"severity": "WARNING", "message": "performance", "metadata": {"category": "performance"}}},
                {"check_id": "x.sqli", "path": "/src/a.py", "start": {"line": 2},
                 "extra": {"severity": "ERROR", "message": "sql", "metadata": {"category": "security"}}}]
        found = semgrep.parse(json.dumps({"results": rows}).encode(), "/src")
        self.assertEqual([f.check for f in found], ["SAST-sqli"])

    def test_tests_and_asserts_excluded_from_scans(self):
        argv = semgrep.build_argv("/src")
        self.assertIn("tests", argv)
        self.assertEqual(argv[-1], "/src")
        captured = {}
        with mock.patch.object(bandit, "run_tool", lambda a, b, c, d=None: captured.setdefault("argv", a)):
            bandit.scan("/src")
        self.assertIn("B101", captured["argv"])
        self.assertTrue(any("tests" in x for x in captured["argv"]))

    def test_trivy_same_misconfig_on_many_files_is_one(self):
        doc = {"Results": [{"Target": f"svc{i}/Dockerfile", "Misconfigurations": [
            {"ID": "DS026", "Title": "Nessun HEALTHCHECK", "Severity": "LOW", "Message": "m"}]} for i in range(4)]}
        found = trivy.parse(json.dumps(doc).encode())
        self.assertEqual(len(found), 1)
        self.assertIn("altri file", found[0].element)

    def test_flood_is_capped(self):
        many = {"results": [{"check_id": f"r{i}", "path": "a.py", "start": {"line": i},
                             "extra": {"severity": "INFO", "message": "m"}} for i in range(500)]}   # 500 regole diverse
        self.assertEqual(len(semgrep.parse(json.dumps(many).encode(), "/")), semgrep.MAX_FINDINGS)


def inspect_doc(**over) -> dict:
    d = {"Name": "/web", "HostConfig": {"Privileged": False, "NetworkMode": "bridge", "PortBindings": {}},
         "Config": {"User": "app", "Env": ["A=1"]}, "Mounts": []}
    for k, v in over.items():
        if isinstance(v, dict) and isinstance(d.get(k), dict):
            d[k] = {**d[k], **v}
        else:
            d[k] = v
    return d


class TestContainers(unittest.TestCase):
    def checks(self, info):
        return {f.check for f in containers.analyze(info)}

    def test_clean(self):
        self.assertEqual(self.checks(inspect_doc()), set())

    def test_issues(self):
        info = inspect_doc(
            HostConfig={"Privileged": True, "NetworkMode": "host", "PidMode": "host", "CapAdd": ["SYS_ADMIN"],
                        "SecurityOpt": ["seccomp=unconfined"],
                        "PortBindings": {"5432/tcp": [{"HostIp": "0.0.0.0", "HostPort": "5432"}]}},
            Config={"User": "", "Env": ["POSTGRES_PASSWORD=postgres", "TOKEN=Zx9!long-random-value"]},
            Mounts=[{"Source": "/var/run/docker.sock"}, {"Source": "/"}])
        self.assertEqual(self.checks(info), {
            "CTR-PRIVILEGED", "CTR-HOSTNET", "CTR-HOSTPID", "CTR-CAPS", "CTR-UNCONFINED", "CTR-DOCKERSOCK",
            "CTR-ROOTFS", "CTR-ROOT", "CTR-DB-PUBLISHED", "CTR-WEAKPASS"})

    def test_weak_password_value_never_shown(self):
        found = containers.analyze(inspect_doc(Config={"User": "app", "Env": ["DB_PASSWORD=changeme"]}))
        blob = json.dumps([f.to_dict() for f in found])
        self.assertIn("DB_PASSWORD", blob)
        self.assertNotIn("changeme", blob)

    def test_localhost_binding_is_fine(self):
        info = inspect_doc(HostConfig={"PortBindings": {"5432/tcp": [{"HostIp": "127.0.0.1", "HostPort": "5432"}]}})
        self.assertEqual(self.checks(info), set())

    def test_hostile_json_shapes(self):
        for info in ({}, {"HostConfig": 5, "Config": [], "Mounts": "x"}, {"HostConfig": {"PortBindings": {"a": 5}}},
                     {"Mounts": [5, None], "Config": {"Env": [None, 5]}}):
            containers.analyze(info)      # non deve sollevare eccezioni


class FakeTransport:
    def __init__(self, answers):
        self.answers = answers
        self.calls = []

    def run(self, argv, timeout=30, max_bytes=0, merge_stderr=False):
        self.calls.append(argv)
        for key, out in self.answers.items():
            if key in " ".join(argv):
                return out if isinstance(out, ToolResult) else ToolResult(True, out.encode())
        return ToolResult(False, reason="failed")


class TestDatabase(unittest.TestCase):
    cfg = parse_internal({"transport": "local", "path": "/x", "db_container": "db", "db_user": "app",
                          "db_name": "appdb"})
    S = "\x1f"

    def tr(self, **over):
        answers = {
            "FROM pg_roles": f"app{self.S}t{self.S}f{self.S}f{self.S}f{self.S}t\n"
                             f"admin{self.S}t{self.S}f{self.S}f{self.S}f{self.S}t\n"
                             f"nologin{self.S}t{self.S}f{self.S}f{self.S}f{self.S}f\n",
            "listen_addresses": "*\n",
            "password_encryption": "md5\n",
            "pg_hba_file_rules": f"host{self.S}all{self.S}all{self.S}0.0.0.0/0{self.S}trust\n"
                                 f"local{self.S}all{self.S}all{self.S}{self.S}trust\n",
        }
        answers.update(over)
        return FakeTransport(answers)

    def test_all_issues(self):
        found, reason = database.run(self.tr(), self.cfg)
        self.assertEqual(reason, "")
        self.assertEqual({f.check for f in found}, {"DB-APP-SUPERUSER", "DB-OTHER-SUPERUSER", "DB-LISTEN-ALL",
                                                   "DB-PWENC-MD5", "DB-HBA-TRUST"})

    def test_clean_db(self):
        tr = self.tr(**{"FROM pg_roles": f"app{self.S}f{self.S}f{self.S}f{self.S}f{self.S}t\n",
                        "listen_addresses": "localhost\n", "password_encryption": "scram-sha-256\n",
                        "pg_hba_file_rules": f"local{self.S}all{self.S}all{self.S}{self.S}trust\n"})
        self.assertEqual(database.run(tr, self.cfg), ([], ""))

    def test_unreachable(self):
        self.assertEqual(database.run(FakeTransport({}), self.cfg), ([], "failed"))

    def test_command_is_literal_argv(self):
        tr = self.tr()
        database.run(tr, self.cfg)
        argv = tr.calls[0]
        self.assertEqual(argv[:3], ["docker", "exec", "db"])
        self.assertIn("app", argv)
        self.assertIn("-X", argv)                       # niente ~/.psqlrc

    def test_trust_only_on_loopback_is_not_reported(self):
        tr = self.tr(**{"pg_hba_file_rules": f"host{self.S}all{self.S}all{self.S}127.0.0.1{self.S}trust\n"
                                              f"host{self.S}all{self.S}all{self.S}::1{self.S}trust\n"
                                              f"host{self.S}all{self.S}all{self.S}all{self.S}scram-sha-256\n"})
        found, _ = database.run(tr, self.cfg)
        self.assertNotIn("DB-HBA-TRUST", {f.check for f in found})
        tr = self.tr(**{"pg_hba_file_rules": f"host{self.S}all{self.S}all{self.S}172.18.0.0/16{self.S}trust\n"})
        found, _ = database.run(tr, self.cfg)
        self.assertIn("DB-HBA-TRUST", {f.check for f in found})

    def test_garbage_rows(self):
        found, _ = database.run(self.tr(**{"FROM pg_roles": "riga\ncorta|\n\n"}), self.cfg)
        self.assertNotIn("DB-APP-SUPERUSER", {f.check for f in found})


class TestLogs(unittest.TestCase):
    def test_issues_without_values(self):
        text = "\n".join(["ok"] * 5 + ["password=SuperSegreta123", "Traceback (most recent call last):"]
                         + ["login failed for user x"] * 12)
        found = logs.analyze("web", text)
        self.assertEqual({f.check for f in found}, {"LOG-SECRETS", "LOG-TRACES", "LOG-AUTHFAIL"})
        self.assertNotIn("SuperSegreta123", json.dumps([f.to_dict() for f in found]))

    def test_clean_and_masked(self):
        self.assertEqual(logs.analyze("web", "GET / 200\npassword=*** hidden\ntoken: [redacted]"), [])

    def test_few_failures_ok(self):
        self.assertEqual(logs.analyze("web", "login failed\n" * 3), [])

    def test_run_uses_merged_stderr(self):
        tr = FakeTransport({"docker logs": "ok\n"})
        self.assertEqual(logs.run(tr, ("web",)), ([], ""))
        self.assertEqual(logs.run(FakeTransport({}), ("web",)), ([], "failed"))


class TestSsh(unittest.TestCase):
    def cfg(self, d):
        return parse_internal({"transport": "ssh", "host": "10.1.2.3", "user": "pi", "key": make_key(d), "port": 2222,
                               "path": "/srv/app"}, d)

    def test_options_are_safe(self):
        with tmpdir() as d:
            argv = SshTransport(self.cfg(d))._base()
            line = " ".join(argv)
            for opt in ("BatchMode=yes", "PasswordAuthentication=no", "StrictHostKeyChecking=yes",
                        "ForwardAgent=no", "ClearAllForwardings=yes", "IdentitiesOnly=yes"):
                self.assertIn(opt, line)
            self.assertNotIn("StrictHostKeyChecking=no", line)
            self.assertEqual(argv[-1], "pi@10.1.2.3")
            self.assertEqual(argv[argv.index("-p") + 1], "2222")

    def test_remote_command_is_one_quoted_string(self):
        with tmpdir() as d, tmpdir() as b:
            fake_tool(b, "ssh", 'for a in "$@"; do last="$a"; done; printf "%s" "$last"')
            tr = SshTransport(self.cfg(d))
            with mock.patch.dict(os.environ, {"PATH": b + os.pathsep + os.environ["PATH"]}):
                res = tr.run(["docker", "logs", "--tail", "5", "we ird;$(id)"], merge_stderr=True)
            self.assertTrue(res.ok)
            self.assertEqual(res.output.decode(), "docker logs --tail 5 'we ird;$(id)' 2>&1")

    def test_connection_failure(self):
        with tmpdir() as d, tmpdir() as b:
            fake_tool(b, "ssh", "exit 255")
            with mock.patch.dict(os.environ, {"PATH": b + os.pathsep + os.environ["PATH"]}):
                self.assertFalse(SshTransport(self.cfg(d)).check().ok)

    def test_snapshot_ok(self):
        with tmpdir() as d, tmpdir() as b, tmpdir() as work:
            src = os.path.join(d, "app")
            os.mkdir(src)
            with open(os.path.join(src, "main.py"), "w") as fh:
                fh.write("print(1)\n")
            fake_tool(b, "ssh", f'tar -C "{src}" -cf - .')
            with mock.patch.dict(os.environ, {"PATH": b + os.pathsep + os.environ["PATH"]}):
                path, reason = SshTransport(self.cfg(d)).source(work)
            self.assertEqual(reason, "")
            self.assertTrue(os.path.isfile(os.path.join(path, "main.py")))

    def test_snapshot_path_traversal_blocked(self):
        with tmpdir() as d, tmpdir() as b, tmpdir() as work:
            evil = os.path.join(d, "evil.tar")
            with tarfile.open(evil, "w") as tf:
                data = b"pwned"
                info = tarfile.TarInfo("../../escaped.txt")
                info.size = len(data)
                tf.addfile(info, io.BytesIO(data))
                link = tarfile.TarInfo("lnk")
                link.type = tarfile.SYMTYPE
                link.linkname = "/etc/passwd"
                tf.addfile(link)
            fake_tool(b, "ssh", f'cat "{evil}"')
            with mock.patch.dict(os.environ, {"PATH": b + os.pathsep + os.environ["PATH"]}):
                path, reason = SshTransport(self.cfg(d)).source(work)
            self.assertEqual(path, "")
            self.assertEqual(reason, "failed")
            self.assertFalse(os.path.exists(os.path.join(os.path.dirname(work), "escaped.txt")))
            self.assertFalse(os.path.exists(os.path.join(work, "src", "lnk")))

    def test_snapshot_too_big(self):
        with tmpdir() as d, tmpdir() as b, tmpdir() as work:
            fake_tool(b, "ssh", "head -c 2000000 /dev/zero")
            with mock.patch.dict(os.environ, {"PATH": b + os.pathsep + os.environ["PATH"]}):
                with mock.patch("apernix.inside.transport.MAX_SNAPSHOT", 1000):
                    self.assertEqual(SshTransport(self.cfg(d)).source(work)[1], "too_big")

    def test_make_transport(self):
        self.assertIsInstance(make_transport(parse_internal({"transport": "local", "path": "/x"})), LocalTransport)


class TestCorrelate(unittest.TestCase):
    def F(self, check, source="x"):
        return Finding(check, "t", "e", 3, 3, source)

    def test_db_chain(self):
        out = correlate.correlate([self.F("NET-DB-EXPOSED", "nmap"), self.F("DB-APP-SUPERUSER", "postgres")])
        self.assertEqual([f.check for f in out], ["CHAIN-DB-EXPOSED"])
        self.assertEqual(out[0].risk, 20)

    def test_secret_chain(self):
        out = correlate.correlate([self.F("WEB-EXP-ENV"), self.F("SEC-aws-key")])
        self.assertEqual([f.check for f in out], ["CHAIN-SECRET-EXPOSED"])

    def test_no_chain_with_one_side_only(self):
        self.assertEqual(correlate.correlate([self.F("NET-DB-EXPOSED")]), [])
        self.assertEqual(correlate.correlate([self.F("DB-APP-SUPERUSER")]), [])


FAKE_DOCKER = r'''
case "$1" in
  inspect) echo '[{"Name":"/web","HostConfig":{"Privileged":true},"Config":{"User":"","Env":["X=1"]},"Mounts":[]}]' ;;
  exec) case "$*" in
          *pg_roles*) printf 'app\037t\037f\037f\037f\037t\n' ;;
          *listen_addresses*) echo localhost ;;
          *password_encryption*) echo scram-sha-256 ;;
          *) exit 1 ;;
        esac ;;
  logs) echo "password=Segretissima99" ;;
esac
'''
def fake_output_tool(bindir: str, name: str, payload: dict) -> None:
    """Finto tool che scrive `payload` (JSON) nel file indicato da --output, come fanno semgrep e trivy."""
    data = os.path.join(bindir, name + ".json")
    with open(data, "w") as fh:
        json.dump(payload, fh)
    script = 'out=""\nwhile [ $# -gt 0 ]; do [ "$1" = "--output" ] && out="$2"; shift; done\n'
    fake_tool(bindir, name, script + f'cat "{data}" > "$out"')


class TestEnginePhase(unittest.TestCase):
    def test_full_internal_phase_with_fake_tools(self):
        with tmpdir() as d, tmpdir() as b, LocalServer({"/": (200, [], b"ok"), "*": (404, [], b"")}) as srv:
            app = os.path.join(d, "app")
            os.mkdir(app)
            with open(os.path.join(app, "main.py"), "w") as fh:
                fh.write("x = 1\n")
            fake_output_tool(b, "semgrep", SEMGREP)
            fake_output_tool(b, "trivy", TRIVY)
            fake_tool(b, "docker", FAKE_DOCKER)
            sc = scope_from_dict({
                "authorization": {"confirmed": True}, "target": [{"url": srv.base + "/"}],
                "limits": {"rate": 50, "max_requests": 100, "timeout": 5},
                "internal": {"transport": "local", "path": app, "containers": ["web"], "db_container": "db",
                             "db_user": "app", "db_name": "appdb"}})
            events = []
            with mock.patch.dict(os.environ, {"PATH": b + os.pathsep + os.environ["PATH"]}):
                res = run_scan(sc, SafeClient(sc), phases=("inside",), emit=events.append)
            checks = {f.check for f in res.findings}
            self.assertTrue({"SAST-sql", "DEP-CVE-2024-0001", "SEC-aws-key", "CFG-DS002", "CTR-PRIVILEGED", "CTR-ROOT",
                             "DB-APP-SUPERUSER", "LOG-SECRETS"} <= checks, checks)
            self.assertEqual(res.sources["semgrep"], "ok")
            self.assertEqual(res.sources["bandit"], "missing")      # c'è main.py ma bandit non è installato qui
            self.assertEqual(res.sources["postgres"], "ok")
            blob = json.dumps([f.to_dict() for f in res.findings])
            self.assertNotIn("Segretissima99", blob)
            self.assertNotIn("AKIAIOSFODNN7EXAMPLE", blob)
            states = [e.data["state"] for e in events if e.kind == "phase" and e.data["id"] == "inside"]
            self.assertEqual(states[0], "start")
            self.assertEqual(states[-1], "done")

    def test_not_configured_is_skipped(self):
        with LocalServer({"*": (200, [], b"ok")}) as srv:
            sc = scope_from_dict({"authorization": {"confirmed": True}, "target": [{"url": srv.base + "/"}],
                                  "limits": {"rate": 50, "max_requests": 100, "timeout": 5}})
            events = []
            run_scan(sc, SafeClient(sc), phases=("inside",), emit=events.append)
            self.assertEqual([e.data["state"] for e in events if e.kind == "phase" and e.data["id"] == "inside"],
                             ["skip"])

    def test_missing_tools_and_docker_reported(self):
        with tmpdir() as d, tmpdir() as b, LocalServer({"*": (200, [], b"ok")}) as srv:
            sc = scope_from_dict({
                "authorization": {"confirmed": True}, "target": [{"url": srv.base + "/"}],
                "limits": {"rate": 50, "max_requests": 100, "timeout": 5},
                "internal": {"transport": "local", "path": d, "containers": ["web"]}})
            with mock.patch.dict(os.environ, {"PATH": b}):          # PATH vuoto: nessun tool installato
                res = run_scan(sc, SafeClient(sc), phases=("inside",))
            self.assertEqual(res.sources["semgrep"], "missing")
            self.assertEqual(res.sources["trivy"], "missing")
            self.assertEqual(res.sources["docker"], "missing")

    def test_ssh_unreachable(self):
        with tmpdir() as d, tmpdir() as b, LocalServer({"*": (200, [], b"ok")}) as srv:
            fake_tool(b, "ssh", "exit 255")
            doc = {"authorization": {"confirmed": True}, "target": [{"url": srv.base + "/"}],
                   "limits": {"rate": 50, "max_requests": 100, "timeout": 5},
                   "internal": {"transport": "ssh", "host": "10.9.9.9", "user": "pi", "key": make_key(d),
                                "path": "/srv/app"}}
            sc = scope_from_dict(doc, d)
            events = []
            with mock.patch.dict(os.environ, {"PATH": b + os.pathsep + os.environ["PATH"]}):
                res = run_scan(sc, SafeClient(sc), phases=("inside",), emit=events.append)
            self.assertEqual(res.sources["ssh"], "failed")
            self.assertEqual([e.data["state"] for e in events if e.kind == "phase" and e.data["id"] == "inside"][-1],
                             "fail")


if __name__ == "__main__":
    unittest.main()

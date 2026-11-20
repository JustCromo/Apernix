"""Un report veritiero: quale ruolo usa davvero l'app, quale processo gira davvero, cosa pesa sul voto."""

import json
import os
import unittest

from apernix import correlate
from apernix import report as rpt
from apernix.inside import containers, database
from apernix.models import Finding
from apernix.report_html import score, to_html
from apernix.scope import parse_internal
from apernix.sources import bandit, nmap, nuclei, semgrep
from apernix.sources.filters import Suppressions
from tests.helpers import tmpdir
from tests.test_inside import FakeTransport, inspect_doc

S = "\x1f"


def role(name, sup=False, login=True):
    return f"{name}{S}{'t' if sup else 'f'}{S}f{S}f{S}f{S}{'t' if login else 'f'}\n"


class TestRealAppRole(unittest.TestCase):
    cfg = parse_internal({"transport": "local", "path": "/x", "db_container": "db", "db_user": "owner",
                          "db_name": "appdb"})

    def tr(self, activity):
        return FakeTransport({"FROM pg_roles": role("owner", sup=True) + role("owner_app"),
                              "pg_stat_activity": activity, "listen_addresses": "localhost\n",
                              "password_encryption": "scram-sha-256\n", "pg_hba_file_rules": ""})

    def test_app_connected_with_minimal_role_is_not_superuser(self):
        found, _ = database.run(self.tr("owner_app\n"), self.cfg)
        checks = {f.check: f for f in found}
        self.assertNotIn("DB-APP-SUPERUSER", checks)               # il proprietario non è il ruolo dell'app
        other = checks["DB-OTHER-SUPERUSER"]
        self.assertLessEqual(other.risk, 4)
        self.assertTrue(any("non è connessa" in e for e in other.evidence))

    def test_app_really_connected_as_superuser(self):
        found, _ = database.run(self.tr("owner\n"), self.cfg)
        sup = next(f for f in found if f.check == "DB-APP-SUPERUSER")
        self.assertEqual((sup.risk, sup.pt), (15, "confirmed"))

    def test_no_visible_connection_is_not_claimed_as_certain(self):
        found, _ = database.run(self.tr(""), self.cfg)
        sup = next(f for f in found if f.check == "DB-APP-SUPERUSER")
        self.assertEqual(sup.pt, "not_tested")
        self.assertLess(sup.risk, 10)
        self.assertTrue(any("non risulta" in e for e in sup.evidence))

    def test_query_is_read_only_and_ignores_own_session(self):
        tr = self.tr("owner_app\n")
        database.run(tr, self.cfg)
        sql = next(" ".join(c) for c in tr.calls if "pg_stat_activity" in " ".join(c))
        self.assertIn("pg_backend_pid()", sql)
        self.assertNotRegex(sql.upper(), r"\b(INSERT|UPDATE|DELETE|DROP|ALTER|GRANT)\b")


class TestRunningProcess(unittest.TestCase):
    def top(self, out):
        return FakeTransport({"docker top": out})

    def test_main_uid(self):
        self.assertEqual(containers.main_uid(self.top("UID PID COMMAND\n999 1234 postgres\n999 1300 postgres\n"),
                                             "db"), 999)
        self.assertEqual(containers.main_uid(self.top("UID PID COMMAND\n0 20 caddy\n0 5 caddy-run\n"), "c"), 0)

    def test_unknown_or_shifted_uids_conclude_nothing(self):
        self.assertIsNone(containers.main_uid(self.top("UID PID COMMAND\n100000 1 x\n"), "c"))   # user namespace
        self.assertIsNone(containers.main_uid(FakeTransport({}), "c"))                          # docker top fallito
        self.assertIsNone(containers.main_uid(self.top("righe\nnon valide\n"), "c"))

    def test_image_starting_as_root_but_dropping_privileges_is_not_root(self):
        info = inspect_doc(Config={"User": ""})
        self.assertNotIn("CTR-ROOT", {f.check for f in containers.analyze(info, uid=999)})

    def test_verified_root_vs_configuration_only(self):
        info = inspect_doc(Config={"User": ""})
        verified = next(f for f in containers.analyze(info, uid=0) if f.check == "CTR-ROOT")
        self.assertEqual(verified.pt, "confirmed")
        guess = next(f for f in containers.analyze(info) if f.check == "CTR-ROOT")
        self.assertEqual(guess.pt, "not_tested")

    def test_run_asks_docker_top_only_for_root_by_config(self):
        infos = [inspect_doc(Name="/db", Config={"User": ""}), inspect_doc(Name="/app", Config={"User": "app"})]
        tr = FakeTransport({"docker inspect": json.dumps(infos), "docker top": "UID PID COMMAND\n999 1 postgres\n"})
        found, reason = containers.run(tr, ("db", "app"))
        self.assertEqual((found, reason), ([], ""))
        tops = [c for c in tr.calls if c[:2] == ["docker", "top"]]
        self.assertEqual(len(tops), 1)
        self.assertEqual(tops[0][2], "db")


class TestMitigations(unittest.TestCase):
    def test_hostnet_with_defences_is_less_likely(self):
        bare = inspect_doc(HostConfig={"NetworkMode": "host"}, Config={"User": ""})
        hardened = inspect_doc(HostConfig={"NetworkMode": "host", "CapDrop": ["ALL"], "ReadonlyRootfs": True,
                                           "SecurityOpt": ["no-new-privileges:true"]}, Config={"User": "nobody"})
        a = next(f for f in containers.analyze(bare) if f.check == "CTR-HOSTNET")
        b = next(f for f in containers.analyze(hardened) if f.check == "CTR-HOSTNET")
        self.assertEqual(a.risk, 9)
        self.assertEqual(b.risk, 3)
        self.assertTrue(any("difese già presenti" in e for e in b.evidence))

    def test_root_with_cap_drop_all(self):
        info = inspect_doc(HostConfig={"CapDrop": ["ALL"], "CapAdd": ["NET_BIND_SERVICE"]}, Config={"User": ""})
        root = next(f for f in containers.analyze(info, uid=0) if f.check == "CTR-ROOT")
        self.assertEqual(root.probability, 1)

    def test_probability_never_below_one_and_garbage_is_ignored(self):
        info = inspect_doc(HostConfig={"CapDrop": "ALL", "SecurityOpt": [5, None], "ReadonlyRootfs": "yes"},
                           Config={"User": ""})
        root = next(f for f in containers.analyze(info, uid=0) if f.check == "CTR-ROOT")
        self.assertEqual(root.probability, 2)                       # niente difese riconosciute da dati strani


class TestNosecAndSignals(unittest.TestCase):
    def test_suppression_comments(self):
        with tmpdir() as d:
            with open(os.path.join(d, "a.py"), "w") as fh:
                fh.write("x = 1\n# nosec: SVG generato dal server\ny = Markup(z)\nw = Markup(q)\n"
                         "v = Markup(r)  # nosemgrep\n")
            sup = Suppressions(d)
            self.assertTrue(sup.covers("a.py", 3))        # commento sulla riga sopra
            self.assertTrue(sup.covers("a.py", 5))        # commento sulla stessa riga
            self.assertFalse(sup.covers("a.py", 4))        # la riga 3 ha un commento sopra, la 4 no
            self.assertFalse(sup.covers("a.py", 1))
            with open(os.path.join(d, "b.py"), "w") as fh:
                fh.write("a = f(1)  # nosec\nb = g(2)\n")
            self.assertFalse(Suppressions(d).covers("b.py", 2))   # un'annotazione a fine riga non copre la successiva
            self.assertFalse(sup.covers("../../etc/passwd", 1))    # mai fuori dalla cartella analizzata
            self.assertFalse(sup.covers("manca.py", 1))

    def test_semgrep_skips_annotated_points_and_marks_audit_only_groups(self):
        with tmpdir() as d:
            with open(os.path.join(d, "a.py"), "w") as fh:
                fh.write("y = Markup(z)  # nosec\nopen(u)\nurlopen(w)\n")

            def row(rule, line, sev="WARNING"):
                return {"check_id": rule, "path": os.path.join(d, "a.py"), "start": {"line": line},
                        "end": {"line": line}, "extra": {"severity": sev, "message": "m."}}
            rows = [row("python.flask.security.xss.audit.explicit-unescape-with-markup", 1),
                    row("python.lang.security.audit.dynamic-urllib-use-detected", 3),
                    row("python.flask.security.injection.tainted-url-host", 2, "ERROR")]
            found = {f.check: f for f in semgrep.parse(json.dumps({"results": rows}).encode(), d)}
        self.assertNotIn("SAST-explicit-unescape-with-markup", found)          # annotato con # nosec
        self.assertFalse(found["SAST-dynamic-urllib-use-detected"].scored)     # solo un segnale
        self.assertTrue(found["SAST-tainted-url-host"].scored)

    def test_bandit_blacklist_is_a_signal(self):
        rows = [{"test_id": "B310", "test_name": "blacklist", "issue_text": "x", "issue_severity": "MEDIUM",
                 "issue_confidence": "HIGH", "filename": "/src/app/a.py", "line_number": 3},
                {"test_id": "B608", "test_name": "hardcoded_sql_expressions", "issue_text": "y",
                 "issue_severity": "MEDIUM", "issue_confidence": "HIGH", "filename": "/src/app/b.py",
                 "line_number": 4}]
        found = {f.check: f for f in bandit.parse(json.dumps({"results": rows}).encode(), "/src")}
        self.assertFalse(found["SAST-B310"].scored)
        self.assertTrue(found["SAST-B608"].scored)

    def test_host_services_are_not_scored(self):
        ports = [{"port": 22, "proto": "tcp", "service": "ssh", "product": "OpenSSH", "version": "10"},
                 {"port": 80, "proto": "tcp", "service": "http", "product": "Caddy", "version": ""},
                 {"port": 443, "proto": "tcp", "service": "http", "product": "Caddy", "version": ""}]
        found = nmap.findings("h", ports, [443])
        surface = next(f for f in found if f.check == "NET-SURFACE")
        self.assertFalse(surface.scored)
        self.assertEqual(len(surface.evidence), 1)                  # solo SSH: la porta 80 è lo stesso sito
        self.assertTrue(surface.evidence[0].startswith("22/tcp"))
        only_web = nmap.findings("h", ports[1:], [443])
        self.assertEqual([f.check for f in only_web], [])

    def test_ssh_findings_are_not_scored(self):
        line = json.dumps({"template-id": "ssh-password-auth", "info": {"name": "n", "severity": "info"},
                           "matched-at": "h:22"})
        found, _ = nuclei.parse(line.encode())
        self.assertEqual([(f.check, f.scored) for f in found], [("NUC-ssh-password-auth", False)])


class TestScoreAndReport(unittest.TestCase):
    def f(self, **kw):
        base = dict(check="X-1", title="t", element="e", impact=4, probability=4, source="s", evidence=["e"],
                    remediation="r")
        base.update(kw)
        return Finding(**base)

    def test_unscored_do_not_change_grade_summary_or_exit_signal(self):
        two = [self.f(check="SAST-a", scored=False), self.f(check="NET-SURFACE", scored=False)]
        doc = rpt.build(["http://x/"], two, 0, {"sources": []}, {"name": "n"})
        self.assertEqual(doc["summary"]["high"], 0)
        self.assertEqual(doc["unscored"], 2)
        self.assertEqual(score(doc["findings"])[:2], (100, "A"))
        html = to_html(doc)
        self.assertIn("non conta nel voto", html)
        self.assertIn("2 segnali sono elencati", html)
        self.assertIn("Macchina che ospita l&#x27;app", html)

    def test_scored_findings_still_count(self):
        doc = rpt.build(["http://x/"], [self.f()], 0, {"sources": []}, {"name": "n"})
        self.assertEqual(doc["summary"]["high"], 1)
        self.assertEqual(doc["unscored"], 0)
        self.assertLess(score(doc["findings"])[0], 100)

    def test_roundtrip_keeps_scored(self):
        f = self.f(scored=False)
        self.assertFalse(Finding.from_dict(f.to_dict()).scored)
        old = f.to_dict()
        del old["scored"]
        self.assertTrue(Finding.from_dict(old).scored)             # vecchi report: pesano come prima


class TestContradictions(unittest.TestCase):
    def mk(self, check, element):
        return Finding(check=check, title="t", element=element, impact=2, probability=1, source="s",
                       evidence=["e"], remediation="r")

    def test_listen_all_dropped_when_db_unreachable(self):
        listen = self.mk("DB-LISTEN-ALL", "racoonix-db-1/racoonix")
        out = correlate.drop_contradictions([listen], {"docker": "ok"})
        self.assertEqual(out, [])

    def test_listen_all_kept_when_published_or_unverified(self):
        listen = self.mk("DB-LISTEN-ALL", "racoonix-db-1/racoonix")
        pub = self.mk("CTR-DB-PUBLISHED", "racoonix-db-1:5432")
        self.assertEqual(len(correlate.drop_contradictions([listen, pub], {"docker": "ok"})), 2)
        self.assertEqual(len(correlate.drop_contradictions([listen], {"docker": "missing"})), 1)
        self.assertEqual(len(correlate.drop_contradictions([listen], None)), 1)
        host = self.mk("CTR-HOSTNET", "racoonix-db-1")
        self.assertEqual(len(correlate.drop_contradictions([listen, host], {"docker": "ok"})), 2)
        net = self.mk("NET-DB-EXPOSED", "h:5432")
        self.assertEqual(len(correlate.drop_contradictions([listen, net], {"docker": "ok"})), 2)


if __name__ == "__main__":
    unittest.main()

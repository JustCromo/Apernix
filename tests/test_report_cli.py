import contextlib
import io
import json
import os
import re
import stat
import unittest

from apernix import cli
from apernix import report as rpt
from apernix.models import Finding
from tests.helpers import LocalServer, scope_file, tmpdir


def finding(**kw):
    base = dict(check="WEB-X", title="Titolo", element="http://x/", impact=4, probability=5, source="t",
                evidence=["e1"])
    base.update(kw)
    return Finding(**base)


def run(argv):
    o, e = io.StringIO(), io.StringIO()
    with contextlib.redirect_stdout(o), contextlib.redirect_stderr(e):
        code = cli.main(argv)
    return code, o.getvalue(), e.getvalue()


class TestReport(unittest.TestCase):
    def test_save_private_and_roundtrip(self):
        doc = rpt.build(["http://x/"], [finding(), finding(impact=1, probability=1, check="WEB-Y")])
        self.assertEqual(doc["findings"][0]["risk"], 20)
        self.assertEqual(doc["summary"]["critical"], 1)
        with tmpdir() as d:
            folder = rpt.save(doc, os.path.join(d, "out"))
            self.assertEqual(stat.S_IMODE(os.stat(folder).st_mode), 0o700)
            for name in ("report.json", "report.md"):
                self.assertEqual(stat.S_IMODE(os.stat(os.path.join(folder, name)).st_mode), 0o600)
            again = rpt.load(os.path.join(folder, "report.json"))
            self.assertEqual(again["findings"], doc["findings"])

    def test_tampered_reports_rejected(self):
        good = rpt.build(["http://x/"], [finding()])
        bad_docs = [
            "not json", "[]", json.dumps({"schema": "other"}),
            json.dumps(dict(good, findings=[dict(good["findings"][0], impact=9)])),
            json.dumps(dict(good, findings=[dict(good["findings"][0], evidence="x")])),
            json.dumps(dict(good, findings="x")),
            "[" * 100000,
        ]
        with tmpdir() as d:
            path = os.path.join(d, "r.json")
            for content in bad_docs:
                with open(path, "w") as fh:
                    fh.write(content)
                with self.assertRaises(rpt.ReportError):
                    rpt.load(path)

    def test_tampered_risk_recomputed(self):
        good = rpt.build(["http://x/"], [finding(impact=1, probability=1)])
        good["findings"][0]["risk"] = 25
        good["findings"][0]["level"] = "critical"
        with tmpdir() as d:
            path = os.path.join(d, "r.json")
            with open(path, "w") as fh:
                json.dump(good, fh)
            self.assertEqual(rpt.load(path)["findings"][0]["risk"], 1)

    def test_markdown_injection_escaped(self):
        doc = rpt.build(["http://x/"], [finding(title="<script>alert(1)</script>|x", evidence=["[a](javascript:x)"])])
        md = rpt.to_markdown(doc)
        self.assertNotIn("<script>", md)
        self.assertIsNone(re.search(r"[^\\]\]\(javascript", md))
        self.assertIn("&lt;script&gt;", md)

    def test_no_symlink_overwrite(self):
        with tmpdir() as d:
            victim = os.path.join(d, "victim")
            open(victim, "w").close()
            out = os.path.join(d, "out")
            os.mkdir(out, 0o700)
            folder = rpt.save(rpt.build([], []), out)
            os.remove(os.path.join(folder, "report.md"))
            os.symlink(victim, os.path.join(folder, "report.md"))
            with self.assertRaises(OSError):
                rpt._write_private(os.path.join(folder, "report.md"), "pwned")
            with open(victim) as fh:
                self.assertEqual(fh.read(), "")


class TestCli(unittest.TestCase):
    def test_help_and_version(self):
        self.assertEqual(run(["help"])[0], 0)
        code, out, _ = run(["version", "--json"])
        self.assertEqual((code, json.loads(out)["ok"]), (0, True))

    def test_no_args_without_terminal_shows_help(self):
        code, out, _ = run([])
        self.assertEqual(code, 0)
        self.assertIn("dashboard", out)

    def test_dashboard_needs_terminal(self):
        code, _, err = run(["dashboard"])
        self.assertEqual(code, 2)
        self.assertIn("terminale interattivo", err)

    def test_unknown_command(self):
        code, _, err = run(["boh"])
        self.assertEqual(code, 2)
        self.assertIn("Suggerimento", err)

    def test_bad_options(self):
        self.assertEqual(run(["scan", "--scope"])[0], 2)
        self.assertEqual(run(["scan", "--rm-rf"])[0], 2)
        self.assertEqual(run(["report", "--format", "exe", "x"])[0], 2)

    def test_scope_missing_json(self):
        with tmpdir() as d:
            code, out, _ = run(["scope", "--scope", os.path.join(d, "x.toml"), "--json"])
            self.assertEqual(code, 2)
            self.assertEqual(json.loads(out), {"ok": False, "error": "err.scope_missing"})

    def test_scope_not_confirmed(self):
        with tmpdir() as d:
            path = scope_file(d, "http://127.0.0.1:9/", confirmed=False)
            self.assertEqual(run(["scope", "--scope", path])[0], 2)

    def test_scan_unreachable(self):
        with tmpdir() as d:
            path = scope_file(d, "http://127.0.0.1:9/")
            code, _, err = run(["scan", "--scope", path, "--out", os.path.join(d, "o")])
            self.assertEqual(code, 2)
            self.assertIn("non risponde", err)

    def test_scan_end_to_end(self):
        routes = {"/": (200, [("Server", "Evil/1.0\x1b]0;pwned"), ("Set-Cookie", "sid=1")], b"hi"),
                  "/.env": (200, [], b"SECRET_KEY=x\n")}
        with LocalServer(routes) as srv, tmpdir() as d:
            path = scope_file(d, srv.base + "/")
            code, out, _ = run(["scan", "--scope", path, "--out", os.path.join(d, "o"), "--json", "--quick"])
            self.assertEqual(code, 1)   # .env esposto = rischio critico
            doc = json.loads(out)
            ids = {f["check"] for f in doc["findings"]}
            self.assertIn("WEB-HTTP-001", ids)
            self.assertIn("WEB-DISC-001", ids)
            self.assertIn("WEB-EXP-ENV", ids)
            self.assertNotIn("\x1b", out)
            self.assertTrue(os.path.isfile(os.path.join(doc["saved"], "report.md")))
            code, md, _ = run(["report", os.path.join(doc["saved"], "report.json")])
            self.assertEqual(code, 0)
            self.assertIn("WEB-HTTP-001", md)
            code, html, _ = run(["report", os.path.join(doc["saved"], "report.json"), "--format", "html"])
            self.assertEqual(code, 0)
            self.assertIn("<!DOCTYPE html>", html)
            self.assertTrue(os.path.isfile(os.path.join(doc["saved"], "report.html")))

    def test_lang_env_path_ignored(self):
        os.environ["APERNIX_LANG"] = "../../../etc/passwd"
        try:
            self.assertEqual(run(["help"])[0], 0)
        finally:
            del os.environ["APERNIX_LANG"]


if __name__ == "__main__":
    unittest.main()

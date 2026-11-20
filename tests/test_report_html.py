import json
import os
import re
import stat
import unittest
from datetime import datetime

from apernix import report as rpt
from apernix.models import Finding
from apernix.report_html import category, effort, passed_checks, score, to_html
from tests.helpers import tmpdir

XSS = '<script>alert(1)</script><img src=x onerror=alert(2)>"\'&'


def f(check="WEB-EXP-ENV", i=5, p=5, **kw):
    base = dict(check=check, title="Titolo", element="http://x/", impact=i, probability=p, source="t",
                evidence=["e"], remediation="fai così")
    base.update(kw)
    return Finding(**base)


def doc_with(findings, sources=None, targets=("http://x/",), meta=None):
    extra = {"sources": sources or [{"name": "apernix-web", "status": "ok"}]}
    return rpt.build(list(targets), findings, 3, extra, meta or {"name": "Lab"})


LOGO_TAG = re.compile(r'<img class="logo" src="data:image/png;base64,[A-Za-z0-9+/=]+" alt="" width="\d+" height="\d+">')


def without_logo(html: str) -> str:
    """L'unica immagine ammessa è il logo di Apernix incorporato (data URI): tutto il resto deve restare testo."""
    out, n = LOGO_TAG.subn("", html)
    assert n <= 2
    return out


class TestHtmlSafety(unittest.TestCase):
    def test_hostile_text_is_escaped(self):
        d = doc_with([f(title=XSS, element=XSS, evidence=[XSS], remediation=XSS, check=XSS[:60], source=XSS)],
                     targets=[XSS], meta={"name": XSS, "profile": XSS})
        d["fingerprint"] = [{"technologies": [XSS]}]
        d["services"] = {XSS: [XSS]}
        html = to_html(d)
        self.assertIsNone(re.search(r"<\s*(script|img)", without_logo(html), re.I))   # nessun tag vero: solo testo
        self.assertNotIn('"><', html.split("</title>")[0].split("<title>")[1])
        self.assertIn("&lt;script&gt;", html)

    def test_self_contained_and_locked_down(self):
        html = to_html(doc_with([f()]))
        self.assertIn("Content-Security-Policy", html)
        self.assertIn("default-src 'none'", html)
        self.assertIsNone(re.search(r'(src|href)="(?!#)', without_logo(html)))       # niente risorse o link esterni
        self.assertNotIn("<script", html)

    def test_empty_report(self):
        html = to_html(doc_with([]))
        self.assertIn("Nessun problema trovato", html)
        self.assertIn("A", html)


class TestHtmlIntelligence(unittest.TestCase):
    def test_score_and_grade(self):
        self.assertEqual(score([]), (100, "A", "ok"))
        mediums = [{"level": "medium"}] * 8
        self.assertEqual(score(mediums)[1], "B")
        self.assertEqual(score([{"level": "critical"}] * 4)[:2], (0, "F"))

    def test_score_without_critical_is_never_f(self):
        many = [{"level": "high"}] * 50 + [{"level": "medium"}] * 50 + [{"level": "low"}] * 50
        value, letter, _ = score(many)
        self.assertEqual((value, letter), (40, "D"))
        # il caso reale: 4 alti, 8 medi, 4 bassi non devono dare 0
        real = [{"level": "high"}] * 4 + [{"level": "medium"}] * 8 + [{"level": "low"}] * 4
        self.assertGreater(score(real)[0], 40)

    def test_table_is_compact(self):
        long_ev = [f"file: app/templates/x{i}.html:{i}" for i in range(9)]
        html = to_html(doc_with([f(evidence=long_ev)]))
        table = html[html.index("<table>"):html.index("</table>")]
        self.assertIn("x0.html", table)
        self.assertIn("x1.html", table)
        self.assertNotIn("x5.html", table)               # il resto sta nel dettaglio, non nella tabella
        self.assertIn("+7 altre", table)
        self.assertIn("x5.html", html)

    def test_logo_is_embedded_and_csp_allows_only_data_images(self):
        html = to_html(doc_with([f()]))
        self.assertIn('src="data:image/png;base64,', html)
        self.assertIn("img-src data:", html)
        self.assertNotIn("http://", html.split("<main>")[0])           # nessuna risorsa esterna nell'intestazione
        self.assertNotIn("<script", html)

    def test_report_works_without_logo(self):
        from unittest import mock

        import apernix.report_html as rh
        rh.logo_uri.cache_clear()
        try:
            with mock.patch.object(rh.Path, "read_bytes", side_effect=OSError):
                html = to_html(doc_with([f()]))
        finally:
            rh.logo_uri.cache_clear()
        self.assertNotIn("data:image", html)
        self.assertIn("APERNIX", html)

    def test_verdict_plural(self):
        self.assertIn("1 problema critico", to_html(doc_with([f()])))
        self.assertIn("2 problemi critici", to_html(doc_with([f(), f(check="WEB-EXP-GIT")])))

    def test_passed_checks(self):
        d = doc_with([f(check="WEB-EXP-ENV")], sources=[{"name": "apernix-web", "status": "ok"},
                                                       {"name": "nmap", "status": "ok"},
                                                       {"name": "nuclei", "status": "missing"}])
        ok = passed_checks(d)
        self.assertNotIn("WEB-EXP-ENV", ok)
        self.assertIn("WEB-EXP-GIT", ok)
        self.assertIn("NET-DB-EXPOSED", ok)
        self.assertNotIn("WEB-HDR-HSTS", ok)          # su HTTP l'HSTS non ha senso
        self.assertNotIn("NUC", ok)                   # nuclei non eseguito: non si dichiara niente
        d2 = doc_with([], sources=[{"name": "apernix-web", "status": "skipped"}])
        self.assertEqual(passed_checks(d2), [])

    def test_categories_and_effort(self):
        self.assertEqual(category("WEB-EXP-GIT"), "exposure")
        self.assertEqual(category("WEB-CK-SECURE"), "transport")
        self.assertEqual(category("WEB-CK-HTTPONLY"), "session")
        self.assertEqual(category("NUC-cve-2021-1"), "known")
        self.assertEqual(category("BOH"), "other")
        self.assertEqual(effort("WEB-HDR-XFO"), "quick")
        self.assertEqual(effort("NUC-x"), "long")

    def test_every_check_has_explanations(self):
        from apernix.i18n import t
        from apernix.report_html import NET_CHECKS, WEB_CHECKS
        for c in WEB_CHECKS + NET_CHECKS:
            for suffix in (".why", ".ok", ".title", ".fix"):
                self.assertNotEqual(t(c + suffix), c + suffix, c + suffix)


class TestFolders(unittest.TestCase):
    def test_slug(self):
        cases = {"Racoonix": "racoonix", "racoonix (caddy)": "racoonix-caddy", "../../etc/passwd": "etc-passwd",
                 "https://192.168.1.187:443/": "192-168-1-187-443", "Città Più": "citta-piu", "": "bersaglio",
                 "///": "bersaglio", "a" * 100: "a" * 40}
        for text, expected in cases.items():
            self.assertEqual(rpt.slug(text), expected, text)

    def test_folder_name(self):
        d = doc_with([], meta={"name": "Racoonix"})
        self.assertEqual(rpt.folder_name(d, datetime(2026, 11, 19, 0, 53)), "2026-11-19_00-53_racoonix")

    def test_save_writes_three_private_files(self):
        with tmpdir() as tmp:
            d = doc_with([f()])
            folder = rpt.save(d, tmp)
            again = rpt.save(d, tmp)
            self.assertTrue(os.path.basename(folder).endswith("_lab"))
            self.assertTrue(again.endswith("-2"))
            for name in ("report.json", "report.md", "report.html"):
                self.assertEqual(stat.S_IMODE(os.stat(os.path.join(folder, name)).st_mode), 0o600)

    def test_meta_survives_reload_and_is_cleaned(self):
        with tmpdir() as tmp:
            d = doc_with([f()], meta={"name": "Lab\x1b[2J", "profile": "Completa"})
            path = os.path.join(tmp, "r.json")
            raw = dict(d, meta={"name": "Lab", "profile": 5, "evil": "x"})
            with open(path, "w") as fh:
                json.dump(raw, fh)
            meta = rpt.load(path)["meta"]
            self.assertEqual(meta, {"name": "Lab"})
            self.assertNotIn("\x1b", d["meta"]["name"])


if __name__ == "__main__":
    unittest.main()

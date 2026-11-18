import unittest

from apernix.web import checks
from apernix.web.http import MAX_BODY, BudgetExceeded, OutOfScope, Response, SafeClient
from tests.helpers import LocalServer, make_scope

GOOD_HEADERS = [
    ("Content-Security-Policy", "default-src 'self'; frame-ancestors 'none'"),
    ("X-Content-Type-Options", "nosniff"),
    ("Referrer-Policy", "no-referrer"),
    ("Server", "nginx"),
    ("Set-Cookie", "session=abc; HttpOnly; Secure; SameSite=Lax; Path=/"),
]


def resp(url="https://x/", headers=None, cookies=None):
    return Response(url=url, status=200, headers={k.lower(): v for k, v in (headers or {}).items()},
                    set_cookies=cookies or [])


class TestPassiveChecks(unittest.TestCase):
    def ids(self, findings):
        return {f.check for f in findings}

    def test_bare_https_site(self):
        ids = self.ids(checks.run_passive(resp()))
        self.assertEqual(ids, {"WEB-HDR-CSP", "WEB-HDR-XFO", "WEB-HDR-XCTO", "WEB-HDR-HSTS", "WEB-HDR-REF"})

    def test_hardened_site_no_false_alarms(self):
        h = {k: v for k, v in GOOD_HEADERS if k != "Set-Cookie"}
        h["Strict-Transport-Security"] = "max-age=31536000"
        r = resp(headers=h, cookies=["session=abc; HttpOnly; Secure; SameSite=Strict"])
        self.assertEqual(checks.run_passive(r), [])

    def test_http_flagged(self):
        self.assertIn("WEB-HTTP-001", self.ids(checks.run_passive(resp(url="http://x/"))))
        self.assertNotIn("WEB-HDR-HSTS", self.ids(checks.run_passive(resp(url="http://x/"))))

    def test_xfo_ok_via_header_or_csp(self):
        self.assertNotIn("WEB-HDR-XFO", self.ids(checks.check_headers(resp(headers={"X-Frame-Options": "DENY"}))))
        self.assertIn("WEB-HDR-XFO", self.ids(checks.check_headers(resp(headers={"X-Frame-Options": "ALLOWALL"}))))

    def test_version_disclosure(self):
        self.assertTrue(checks.check_disclosure(resp(headers={"Server": "Apache/2.4.49 (Unix)"})))
        self.assertTrue(checks.check_disclosure(resp(headers={"X-Powered-By": "PHP/7.4.3"})))
        self.assertEqual(checks.check_disclosure(resp(headers={"Server": "nginx"})), [])

    def test_cookies(self):
        ids = self.ids(checks.check_cookies(resp(cookies=["sid=1; Path=/"])))
        self.assertEqual(ids, {"WEB-CK-HTTPONLY", "WEB-CK-SECURE", "WEB-CK-SAMESITE"})
        self.assertEqual(checks.check_cookies(resp(cookies=["sid=1; httponly; secure; samesite=lax"])), [])

    def test_cookie_flood_and_malicious_name(self):
        flood = ["c\x1b[31m=1"] * 10000
        fs = checks.check_cookies(resp(cookies=flood))
        for f in fs:
            self.assertLessEqual(len(f.evidence), 10)
            self.assertFalse(any("\x1b" in e for e in f.evidence))


class TestSafeClient(unittest.TestCase):
    def test_redirect_out_of_scope_not_followed(self):
        hits = []
        routes = {"/": (302, [("Location", "http://evil.example/steal")], b"")}
        with LocalServer(routes) as srv:
            c = SafeClient(make_scope(srv.base + "/"))
            r = c.get(srv.base + "/")
            hits.append(r)
            self.assertEqual(r.status, 302)
            self.assertEqual(r.redirects, ["http://evil.example/steal"])
            self.assertEqual(c.requests_made, 1)

    def test_redirect_in_scope_followed(self):
        routes = {"/": (302, [("Location", "/home")], b""), "/home": (200, [], b"ok")}
        with LocalServer(routes) as srv:
            r = SafeClient(make_scope(srv.base + "/")).get(srv.base + "/")
            self.assertEqual((r.status, r.body), (200, b"ok"))

    def test_redirect_loop_bounded(self):
        routes = {"/a": (302, [("Location", "/b")], b""), "/b": (302, [("Location", "/a")], b"")}
        with LocalServer(routes) as srv:
            c = SafeClient(make_scope(srv.base + "/"))
            c.get(srv.base + "/a")
            self.assertLessEqual(c.requests_made, 6)

    def test_out_of_scope_refused_before_sending(self):
        c = SafeClient(make_scope("http://127.0.0.1:9/"))
        with self.assertRaises(OutOfScope):
            c.get("http://example.com/")
        self.assertEqual(c.requests_made, 0)

    def test_budget(self):
        with LocalServer({"/": (200, [], b"ok")}) as srv:
            c = SafeClient(make_scope(srv.base + "/", max_requests=2))
            c.get(srv.base + "/")
            c.get(srv.base + "/")
            with self.assertRaises(BudgetExceeded):
                c.get(srv.base + "/")

    def test_big_body_truncated(self):
        big = b"A" * (MAX_BODY + 500_000)
        with LocalServer({"/": (200, [], big)}) as srv:
            r = SafeClient(make_scope(srv.base + "/")).get(srv.base + "/")
            self.assertTrue(r.truncated)
            self.assertEqual(len(r.body), MAX_BODY)

    def test_multiple_set_cookie_kept(self):
        routes = {"/": (200, [("Set-Cookie", "a=1; HttpOnly"), ("Set-Cookie", "b=2")], b"")}
        with LocalServer(routes) as srv:
            r = SafeClient(make_scope(srv.base + "/")).get(srv.base + "/")
            self.assertEqual(len(r.set_cookies), 2)


if __name__ == "__main__":
    unittest.main()

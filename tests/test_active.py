import unittest

from apernix.web import active
from apernix.web.http import SafeClient
from tests.helpers import LocalServer, make_scope


def scan(routes):
    with LocalServer(routes) as srv:
        c = SafeClient(make_scope(srv.base + "/", max_requests=200))
        home = c.get(srv.base + "/")
        return {f.check for f in active.run_active(c, srv.base + "/", home)}, c.requests_made


class TestActive(unittest.TestCase):
    def test_clean_site_no_alarms(self):
        ids, _ = scan({"/": (200, [], b"<html>ciao</html>")})
        self.assertEqual(ids, set())

    def test_soft_404_no_false_alarms(self):
        # Un sito che risponde 200 a tutto con la stessa pagina non deve far scattare nulla.
        ids, _ = scan({"*": (200, [], b"<html>pagina generica</html>")})
        self.assertEqual(ids, set())

    def test_exposures(self):
        routes = {
            "/": (200, [], b"home"),
            "/.git/HEAD": (200, [], b"ref: refs/heads/main\n"),
            "/.env": (200, [], b"SECRET_KEY=abc\nDB_PASSWORD=x\n"),
            "/console": (200, [], b"<title>Console // Werkzeug Debugger</title> interactive console"),
        }
        ids, _ = scan(routes)
        self.assertTrue({"WEB-EXP-GIT", "WEB-EXP-ENV", "WEB-EXP-DEBUG"} <= ids)

    def test_error_disclosure(self):
        tb = b"<pre>Traceback (most recent call last):\n  File app.py</pre>"
        ids, _ = scan({"/": (200, [], b"home"), "*": (500, [], tb)})
        self.assertIn("WEB-ERR-001", ids)

    def test_cors_reflect(self):
        def reflect(h):
            origin = h.headers.get("Origin", "")
            return 200, [("Access-Control-Allow-Origin", origin), ("Access-Control-Allow-Credentials", "true")], b""
        ids, _ = scan({"/": reflect})
        self.assertIn("WEB-CORS-001", ids)

    def test_methods_and_listing(self):
        routes = {"/": (200, [], b"home"), ("OPTIONS", "/"): (200, [("Allow", "GET, PUT, DELETE")], b""),
                  "/static/": (200, [], b"<title>Index of /static</title>")}
        ids, _ = scan(routes)
        self.assertTrue({"WEB-METH-001", "WEB-LIST-001"} <= ids)

    def test_bounded_requests(self):
        _, n = scan({"/": (200, [], b"home")})
        self.assertLess(n, 30)


if __name__ == "__main__":
    unittest.main()

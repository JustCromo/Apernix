import os
import unittest

from apernix.scope import ScopeError, load_scope, parse_target_url, scope_from_dict
from tests.helpers import scope_file, tmpdir


def doc(url="http://127.0.0.1:8000/app", **extra):
    d = {"authorization": {"confirmed": True}, "target": [{"url": url}]}
    d.update(extra)
    return d


class TestParse(unittest.TestCase):
    def test_normalized(self):
        tg = parse_target_url("HTTP://LocalHost:8000/app")
        self.assertEqual(tg.url, "http://localhost:8000/app/")

    def test_rejected_urls(self):
        bad = ["ftp://x/", "javascript:alert(1)", "file:///etc/passwd", "http://user:pw@x/",
               "http://x/a b", "http://x/\nHost: evil", "http://x:99999/", "http://x/../etc",
               "http://x/?q=1", "http://x/#f", "http:///", "", None, 5, "http://" + "a" * 3000,
               "http://x\\@evil/"]
        for url in bad:
            with self.assertRaises(ValueError, msg=repr(url)):
                parse_target_url(url)


class TestScope(unittest.TestCase):
    def test_not_confirmed(self):
        for auth in ({}, {"confirmed": False}, {"confirmed": "true"}, {"confirmed": 1}):
            with self.assertRaises(ScopeError) as cm:
                scope_from_dict({"authorization": auth, "target": [{"url": "http://x/"}]})
            self.assertEqual(cm.exception.code, "err.scope_not_confirmed")

    def test_no_targets(self):
        with self.assertRaises(ScopeError):
            scope_from_dict({"authorization": {"confirmed": True}})

    def test_too_many_targets(self):
        with self.assertRaises(ScopeError):
            scope_from_dict({"authorization": {"confirmed": True},
                             "target": [{"url": f"http://h{i}/"} for i in range(40)]})

    def test_bad_limits(self):
        for limits in ({"rate": 0}, {"rate": 1000}, {"max_requests": True}, {"timeout": "5"}):
            with self.assertRaises(ScopeError):
                scope_from_dict(doc(limits=limits))

    def test_allows(self):
        sc = scope_from_dict(doc())
        self.assertTrue(sc.allows("http://127.0.0.1:8000/app"))
        self.assertTrue(sc.allows("http://127.0.0.1:8000/app/login"))
        not_allowed = [
            "http://127.0.0.1:8000/", "http://127.0.0.1:8000/apple", "http://127.0.0.1:8001/app/",
            "https://127.0.0.1:8000/app/", "http://127.0.0.2:8000/app/",
            "http://127.0.0.1:8000@evil.com/app/", "http://127.0.0.1:8000/app/../admin",
            "http://evil.com/app/?x=http://127.0.0.1:8000/app/", "http://127.0.0.1:8000/app/\n",
            "gopher://127.0.0.1:8000/app/", None,
        ]
        for url in not_allowed:
            self.assertFalse(sc.allows(url), url)

    def test_ipv6(self):
        sc = scope_from_dict(doc(url="http://[::1]:8000/"))
        self.assertTrue(sc.allows("http://[::1]:8000/x"))
        self.assertFalse(sc.allows("http://[::2]:8000/x"))


class TestScopeFile(unittest.TestCase):
    def test_ok(self):
        with tmpdir() as d:
            sc = load_scope(scope_file(d, "http://127.0.0.1:9/"))
            self.assertEqual(len(sc.targets), 1)

    def test_missing(self):
        with tmpdir() as d, self.assertRaises(ScopeError) as cm:
            load_scope(os.path.join(d, "nope.toml"))
        self.assertEqual(cm.exception.code, "err.scope_missing")

    def test_world_writable_rejected(self):
        with tmpdir() as d:
            for mode in (0o666, 0o620, 0o602):
                path = scope_file(d, "http://127.0.0.1:9/", mode=mode)
                with self.assertRaises(ScopeError) as cm:
                    load_scope(path)
                self.assertEqual(cm.exception.code, "err.scope_unsafe_file")

    def test_directory_rejected(self):
        with tmpdir() as d, self.assertRaises(ScopeError):
            load_scope(d)

    def test_garbage_and_huge(self):
        with tmpdir() as d:
            path = os.path.join(d, "s.toml")
            for content in (b"\xff\xfe\x00", b"[[[[", b"a = " + b"1" * 70000):
                with open(path, "wb") as fh:
                    fh.write(content)
                os.chmod(path, 0o600)
                with self.assertRaises(ScopeError):
                    load_scope(path)


if __name__ == "__main__":
    unittest.main()

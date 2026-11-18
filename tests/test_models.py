import unittest

from apernix.models import Finding, risk_level


def mk(**kw):
    base = dict(check="X-1", title="t", element="e", impact=3, probability=3, source="s")
    base.update(kw)
    return Finding(**base)


class TestRisk(unittest.TestCase):
    def test_formula(self):
        self.assertEqual(mk(impact=4, probability=5).risk, 20)

    def test_levels_boundaries(self):
        self.assertEqual(risk_level(4), "low")
        self.assertEqual(risk_level(5), "medium")
        self.assertEqual(risk_level(9), "medium")
        self.assertEqual(risk_level(10), "high")
        self.assertEqual(risk_level(16), "high")
        self.assertEqual(risk_level(17), "critical")
        self.assertEqual(risk_level(25), "critical")

    def test_bad_scale_rejected(self):
        for bad in (0, 6, -1, True, "3", 2.5, None):
            with self.assertRaises(ValueError):
                mk(impact=bad)
            with self.assertRaises(ValueError):
                mk(probability=bad)

    def test_bad_pt_rejected(self):
        with self.assertRaises(ValueError):
            mk(pt="hacked")


class TestAbuse(unittest.TestCase):
    def test_escape_sequences_removed(self):
        f = mk(title="ok\x1b]0;pwned\x07", element="\x1b[2J", evidence=["a\x9bb", "‮evil"])
        for text in (f.title, f.element, *f.evidence):
            self.assertNotIn("\x1b", text)
            self.assertNotIn("\x07", text)
            self.assertNotIn("\x9b", text)
            self.assertNotIn("‮", text)

    def test_evidence_flood_capped(self):
        f = mk(evidence=["x" * 10000] * 1000)
        self.assertEqual(len(f.evidence), 10)
        self.assertTrue(all(len(e) <= 300 for e in f.evidence))

    def test_roundtrip(self):
        f = mk(evidence=["a"], pt="confirmed")
        self.assertEqual(Finding.from_dict(f.to_dict()).to_dict(), f.to_dict())

    def test_from_dict_rejects_garbage(self):
        for bad in ([], {"check": 1}, dict(mk().to_dict(), evidence="x"), dict(mk().to_dict(), title=5)):
            with self.assertRaises((ValueError, TypeError)):
                Finding.from_dict(bad)


if __name__ == "__main__":
    unittest.main()

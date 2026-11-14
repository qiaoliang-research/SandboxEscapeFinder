"""Tests for SandboxEscapeFinder (Task 6) — stdlib unittest only.

Covers what the task's acceptance criteria ask for:
  * each of the 7 technique classes has a positive and a negative case;
  * the corpus has >= 10 attributed payloads, plus config-driven extras;
  * the oracle catches an intentionally-broken toy sandbox (exec with
    full builtins) and does NOT fire against the real RestrictedPython
    sandbox for the same canary payload;
  * the full corpus (catalog + custom) runs end to end: every attack
    payload is statically flagged, nothing escapes, benign controls run.
"""

import os
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "examples"))

from sandbox_escape_finder import (  # noqa: E402
    CUSTOM_PAYLOADS,
    PAYLOADS,
    DynamicProber,
    StaticAnalyzer,
    load_corpus,
)
from quickstart import make_oracle, make_sandbox_exec  # noqa: E402

POSITIVE = {
    "subclasses_traversal": "().__class__.__bases__[0].__subclasses__()",
    "dunder_class_access": "'a'.__class__",
    "globals_closure_access": "(lambda: 0).__globals__",
    "builtins_restoration": "__builtins__['eval']('1')",
    "dynamic_exec": "eval('1+1')",
    "frame_introspection": "import sys\nsys._getframe(0).f_locals",
    "format_string_access": '"{0.__class__}".format("")',
}

NEGATIVE = {
    "subclasses_traversal": "x = [i * 2 for i in range(5)]",
    "dunder_class_access": "class A:\n    pass\na = A()",
    "globals_closure_access": "def f():\n    return 1",
    "builtins_restoration": "print('hello')",
    "dynamic_exec": "x = 1 + 1",
    "frame_introspection": "import sys\nprint(sys.version)",
    "format_string_access": '"Hello {}".format(name)',
}


class TestStaticAnalyzer(unittest.TestCase):
    def setUp(self):
        self.analyzer = StaticAnalyzer({})

    def test_each_technique_has_positive_and_negative(self):
        for technique, code in POSITIVE.items():
            found = {f["technique"] for f in self.analyzer.scan(code)}
            self.assertIn(technique, found, f"{technique} not detected in: {code!r}")
        for technique, code in NEGATIVE.items():
            found = {f["technique"] for f in self.analyzer.scan(code)}
            self.assertNotIn(technique, found, f"{technique} false positive in: {code!r}")

    def test_findings_cite_location(self):
        findings = self.analyzer.scan("x = eval('1')")
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0]["technique"], "dynamic_exec")
        self.assertEqual(findings[0]["lineno"], 1)
        self.assertIn("eval", findings[0]["snippet"])

    def test_corpus_has_at_least_ten_attributed_payloads(self):
        attack = [p for p in PAYLOADS if p["technique"] != "benign"]
        self.assertGreaterEqual(len(attack), 10)
        for payload in attack:
            self.assertIn(payload["technique"], POSITIVE)

    def test_load_corpus_merges_and_validates_extras(self):
        corpus = load_corpus({"extra_payloads": CUSTOM_PAYLOADS})
        self.assertEqual(len(corpus), len(PAYLOADS) + len(CUSTOM_PAYLOADS))
        self.assertEqual([p["id"] for p in CUSTOM_PAYLOADS], ["X01", "X02", "X03"])
        with self.assertRaises(ValueError):
            load_corpus({"extra_payloads": [{"id": "BAD"}]})
        with self.assertRaises(ValueError):
            load_corpus({"extra_payloads": ["not a dict"]})

    def test_format_string_detector_needs_a_dunder(self):
        # A plain format string is not suspicious; only dunder components are.
        self.assertEqual(self.analyzer.scan('"{} {}".format(a, b)'), [])
        flagged = self.analyzer.scan('"{0.__globals__}".format(f)')
        self.assertEqual([f["technique"] for f in flagged], ["format_string_access"])


class TestDynamicProber(unittest.TestCase):
    def test_oracle_catches_intentionally_broken_sandbox(self):
        """Toy sandbox = plain exec with full builtins: must be caught."""
        with tempfile.TemporaryDirectory() as tmp:
            canary = os.path.join(tmp, "canary_outside_sandbox.txt")

            def broken_exec(code):
                exec(code, {"__builtins__": __builtins__}, {})  # noqa: S102
                return {}

            def oracle(pre, result, post):
                return os.path.exists(canary)

            prober = DynamicProber(broken_exec, oracle, {}, StaticAnalyzer({}))
            payload = {
                "id": "TOY",
                "technique": "builtins_restoration",
                "code": (
                    f"f = open({canary!r}, 'w')\n"
                    "f.write('escaped')\n"
                    "f.close()"
                ),
            }
            report = prober.run([payload])
            self.assertTrue(report[0]["escaped"], "oracle missed the toy escape")

    def test_format_string_payload_blocked_at_runtime_not_compile_time(self):
        """X03 compiles (no AST dunder node) but safer_getattr refuses
        str.format at runtime — the sandbox's second layer of defense."""
        with tempfile.TemporaryDirectory() as tmp:
            sandbox_exec = make_sandbox_exec(tmp)
            x03 = [p for p in CUSTOM_PAYLOADS if p["id"] == "X03"][0]
            with self.assertRaises(NotImplementedError):
                sandbox_exec(x03["code"])

    def test_full_corpus_end_to_end(self):
        """Every attack payload flagged, nothing escapes, benign runs."""
        with tempfile.TemporaryDirectory() as tmp:
            sandbox_exec = make_sandbox_exec(tmp)
            prober = DynamicProber(
                sandbox_exec,
                make_oracle(sandbox_exec.canary_path),
                {},
                StaticAnalyzer({}),
            )
            corpus = load_corpus({"extra_payloads": CUSTOM_PAYLOADS})
            report = prober.run(corpus)
            self.assertFalse(
                any(r["escaped"] for r in report),
                f"unexpected escape: {[r for r in report if r['escaped']]}",
            )
            by_id = {r["id"]: r for r in report}
            attack_ids = {p["id"] for p in corpus if p["technique"] != "benign"}
            flagged = {r["id"] for r in report if r["static_flagged"]}
            self.assertEqual(flagged, attack_ids, "every attack payload must flag")
            # Benign controls: not flagged, and they actually run — the
            # sandbox lets normal code through.
            for pid in ("C01", "C02"):
                self.assertFalse(by_id[pid]["static_flagged"], f"{pid} false positive")
                self.assertTrue(by_id[pid]["executed"], f"{pid} should run cleanly")


if __name__ == "__main__":
    unittest.main()

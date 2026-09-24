"""Unit tests for dangerous sink detection (Phase C — C9)."""

import unittest

from modules.analysis.sinks import SINK_PATTERNS, deduplicate_sinks, detect_sinks


class TestDetectSinks(unittest.TestCase):
    def test_detects_known_sinks(self):
        js = """
        el.innerHTML = userInput;
        eval(code);
        new Function(s)();
        setTimeout("alert(1)", 100);
        """
        sinks = {f["sink"] for f in detect_sinks(js, "a.js")}
        self.assertIn("innerHTML", sinks)
        self.assertIn("eval", sinks)
        self.assertIn("new Function", sinks)
        self.assertIn("setTimeout string", sinks)

    def test_no_false_positive_on_plain_identifiers(self):
        js = "const innerHTMLx = 1; myeval(code); // not a sink"
        sinks = {f["sink"] for f in detect_sinks(js, "a.js")}
        self.assertNotIn("eval", sinks)
        self.assertNotIn("innerHTML", sinks)

    def test_findings_shape(self):
        findings = detect_sinks("el.innerHTML = x;", "bundle.js")
        self.assertEqual(len(findings), 1)
        f = findings[0]
        self.assertEqual(f["sink"], "innerHTML")
        self.assertIn(f["severity"], ("LOW", "MEDIUM", "HIGH", "CRITICAL"))
        self.assertTrue(f["description"])
        self.assertEqual(f["source"], "bundle.js")
        self.assertGreaterEqual(f["count"], 1)


class TestPrototypePollutionSinks(unittest.TestCase):
    def test_proto_assignment(self):
        js = 'obj["__proto__"] = {polluted: 1};'
        sinks = {f["sink"] for f in detect_sinks(js, "x.js")}
        self.assertIn("__proto__ assignment", sinks)

    def test_constructor_prototype_write(self):
        js = 'a.constructor.prototype.isAdmin = true;'
        sinks = {f["sink"] for f in detect_sinks(js, "x.js")}
        self.assertIn("constructor.prototype", sinks)

    def test_object_assign_shared_target(self):
        js = "Object.assign(window, JSON.parse(untrusted));"
        sinks = {f["sink"] for f in detect_sinks(js, "x.js")}
        self.assertIn("Object.assign to untrusted", sinks)

    def test_recursive_merge_gadget(self):
        js = """
        function merge(t, s) {
          for (const k of Object.keys(s)) {
            if (typeof s[k] === 'object') merge(t[k] = t[k] || {}, s[k]);
            else t[k] = s[k];
          }
        }
        """
        sinks = {f["sink"] for f in detect_sinks(js, "x.js")}
        self.assertIn("recursive merge", sinks)

    def test_all_pollution_patterns_have_high_or_medium(self):
        for name in (
            "__proto__ assignment",
            "constructor.prototype",
            "Object.assign to untrusted",
            "recursive merge",
            "JSON.parse + assign key",
        ):
            self.assertIn(name, SINK_PATTERNS)
            _, severity, desc = SINK_PATTERNS[name]
            self.assertIn(severity, ("MEDIUM", "HIGH"), name)
            self.assertTrue(desc, name)


class TestDeduplicateSinks(unittest.TestCase):
    def test_merges_sources_and_counts(self):
        a = {"sink": "eval", "severity": "HIGH", "description": "d", "count": 2, "source": "a.js"}
        b = {"sink": "eval", "severity": "HIGH", "description": "d", "count": 3, "source": "b.js"}
        c = {"sink": "eval", "severity": "HIGH", "description": "d", "count": 1, "source": "a.js"}
        out = deduplicate_sinks([a, b, c])
        self.assertEqual(len(out), 1)
        self.assertEqual(out[0]["count"], 6)
        self.assertEqual(out[0]["sources"], ["a.js", "b.js"])
        self.assertNotIn("source", out[0])

    def test_separate_severities_not_merged(self):
        a = {"sink": "x", "severity": "HIGH", "description": "d", "count": 1, "source": "a.js"}
        b = {"sink": "x", "severity": "LOW", "description": "d", "count": 1, "source": "b.js"}
        self.assertEqual(len(deduplicate_sinks([a, b])), 2)


if __name__ == "__main__":
    unittest.main()

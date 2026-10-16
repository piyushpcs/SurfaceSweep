"""
Static validation of the composite GitHub Action and example workflow.

Guards against the most common packaging mistakes: a non-composite action, a
`run` step without a required `shell`, missing inputs/outputs, or an example
workflow that forgets the `security-events: write` permission needed for SARIF
upload.
"""

import os
import unittest

import yaml

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
ACTION_PATH = os.path.join(ROOT, "action.yml")
EXAMPLE_PATH = os.path.join(ROOT, "examples", "github-actions-scan.yml")


def _read(path):
    with open(path, "r", encoding="utf-8") as handle:
        return handle.read()


def _load(path):
    return yaml.safe_load(_read(path))


class TestActionManifest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.action = _load(ACTION_PATH)

    def test_is_composite_action(self):
        self.assertEqual(self.action["runs"]["using"], "composite")

    def test_has_name_and_description(self):
        self.assertTrue(self.action.get("name"))
        self.assertTrue(self.action.get("description"))

    def test_description_within_marketplace_limit(self):
        # GitHub Marketplace rejects action descriptions of 125+ characters.
        desc = self.action["description"]
        self.assertLess(len(desc), 125, f"description is {len(desc)} chars: {desc!r}")

    def test_has_branding(self):
        branding = self.action.get("branding") or {}
        self.assertIn("icon", branding)
        self.assertIn("color", branding)

    def test_target_input_required(self):
        target = self.action["inputs"]["target"]
        self.assertTrue(target["required"])

    def test_expected_inputs_present(self):
        for name in ("target", "args", "output", "sarif", "upload-sarif", "fail-on"):
            self.assertIn(name, self.action["inputs"])

    def test_declared_outputs_map_to_scan_step(self):
        outputs = self.action["outputs"]
        for name in ("json", "sarif", "exit-code"):
            self.assertIn(name, outputs)
            self.assertIn("steps.scan.outputs", outputs[name]["value"])

    def test_every_run_step_declares_a_shell(self):
        # Composite actions require an explicit `shell` on every `run` step.
        for step in self.action["runs"]["steps"]:
            if "run" in step:
                self.assertIn(
                    "shell", step, f"run step missing shell: {step.get('name')}"
                )

    def test_uploads_sarif_via_codeql_action(self):
        uses = [step.get("uses", "") for step in self.action["runs"]["steps"]]
        self.assertTrue(
            any(u.startswith("github/codeql-action/upload-sarif@") for u in uses),
            uses,
        )

    def test_scan_step_emits_outputs(self):
        names = [step.get("name", "") for step in self.action["runs"]["steps"]]
        self.assertIn("Run SurfaceSweep", names)


class TestExampleWorkflow(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.doc = _load(EXAMPLE_PATH)

    def test_is_valid_yaml_with_jobs(self):
        self.assertIn("jobs", self.doc)

    def test_requests_security_events_write(self):
        permissions = self.doc.get("permissions") or {}
        self.assertEqual(permissions.get("security-events"), "write")

    def test_references_the_local_action(self):
        raw = _read(EXAMPLE_PATH)
        self.assertIn("uses: piyushpcs/SurfaceSweep@", raw)


if __name__ == "__main__":
    unittest.main()

import hashlib
import os
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "scripts"))
from merge_stage import load_sandbox_report, plan_merge, validate_verdict
from run_sandboxed import linked_dependencies


class VerdictGateTests(unittest.TestCase):
    def test_verified_requires_tier_a(self):
        self.assertIn("Tier A", validate_verdict("VERIFIED", "B", "pass", False))
        self.assertIn("Tier A", validate_verdict("VERIFIED", "C", "pass", False))
        self.assertIn("Tier A", validate_verdict("VERIFIED", "A", "fail", False))
        self.assertIsNone(validate_verdict("VERIFIED", "A", "pass", False))

    def test_partial_requires_tier_and_acknowledgement(self):
        self.assertIn("--sandbox-report", validate_verdict("PARTIAL", None, None, True))
        self.assertIn("--acknowledge-partial", validate_verdict("PARTIAL", "B", "pass", False))
        self.assertIsNone(validate_verdict("PARTIAL", "B", "pass", True))

    def test_failed_and_missing_verdict_are_rejected(self):
        self.assertIn("FAILED", validate_verdict("FAILED", "A", "pass", True))
        self.assertIn("--verdict", validate_verdict(None, None, None, False))

    def test_sandbox_report_must_be_a_sandbox_result(self):
        with tempfile.NamedTemporaryFile(mode="w", encoding="utf-8") as f:
            f.write('{"stage":"static_check","status":"pass","data":{}}')
            f.flush()
            _tier, _status, error = load_sandbox_report(f.name)
        self.assertIn("run_sandboxed", error)


class MergeIntegrityTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.project = os.path.join(self.temp.name, "project")
        self.stage = os.path.join(self.temp.name, "stage")
        os.makedirs(self.project)
        os.makedirs(self.stage)
        self.target = os.path.join(self.project, "app.py")
        self.staged = os.path.join(self.stage, "app.py")
        with open(self.target, "w", encoding="utf-8") as f:
            f.write("old\n")
        with open(self.staged, "w", encoding="utf-8") as f:
            f.write("new\n")
        self.manifest = {"changed": [{
            "path": "app.py", "action": "modify",
            "orig_sha256": self.digest(self.target), "staged_sha256": self.digest(self.staged),
        }]}

    @staticmethod
    def digest(path):
        with open(path, "rb") as f:
            return hashlib.sha256(f.read()).hexdigest()

    def test_modified_staged_file_is_rejected(self):
        with open(self.staged, "w", encoding="utf-8") as f:
            f.write("tampered\n")
        actions, problems = plan_merge(self.stage, self.project, self.manifest)
        self.assertEqual(actions, [])
        self.assertTrue(any("changed after staging" in p for p in problems))

    def test_project_drift_is_rejected(self):
        with open(self.target, "w", encoding="utf-8") as f:
            f.write("user edit\n")
        actions, problems = plan_merge(self.stage, self.project, self.manifest)
        self.assertEqual(actions, [])
        self.assertTrue(any("was edited since staging" in p for p in problems))

    def test_parent_symlink_outside_project_is_rejected(self):
        outside = os.path.join(self.temp.name, "outside")
        os.makedirs(outside)
        with open(os.path.join(outside, "secret.txt"), "w", encoding="utf-8") as f:
            f.write("secret")
        os.symlink(outside, os.path.join(self.project, "linked"))
        manifest = {"changed": [{
            "path": "linked/secret.txt", "action": "modify",
            "orig_sha256": self.digest(os.path.join(outside, "secret.txt")), "staged_sha256": "unused",
        }]}
        actions, problems = plan_merge(self.stage, self.project, manifest)
        self.assertEqual(actions, [])
        self.assertTrue(any("resolves outside the project" in p for p in problems))


class SandboxDependencyTests(unittest.TestCase):
    def test_finds_linked_dependency_directories(self):
        with tempfile.TemporaryDirectory() as root:
            stage = os.path.join(root, "stage")
            deps = os.path.join(root, "real-node-modules")
            os.makedirs(stage)
            os.makedirs(deps)
            os.symlink(deps, os.path.join(stage, "node_modules"))
            self.assertEqual(linked_dependencies(stage), ["node_modules"])


if __name__ == "__main__":
    unittest.main()

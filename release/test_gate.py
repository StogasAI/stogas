"""Release authorization rejects incomplete or misidentified qualification."""

import copy
import unittest

from gate import check_qualification


class QualificationTests(unittest.TestCase):
    def setUp(self):
        self.targets = {"linux-amd64": {"packages": ["native"]}}
        identities = [("linux-amd64", "native", name) for name in ("installed-contract", "transport-tls", "transport-e2ee")]
        identities.extend(("portable", "rust", case) for case in ("installed-contract", "transport-tls", "transport-e2ee"))
        for runtime in ("node", "node-minimum", "bun", "deno", "worker", "chromium", "firefox", "webkit"):
            identities.extend(("portable", "npm", f"{runtime}-{case}") for case in ("contract", "e2ee"))
        self.report = {
            "schema": "stogas.sdk-qualification.v1", "environment": "prod", "manifest_sha256": "a" * 64,
            "checks": [{"platform": platform, "package": package, "case": case, "runtime": "test-runtime", "outcome": "passed"} for platform, package, case in identities],
        }

    def test_all_declared_checks_are_required(self):
        check_qualification(self.report, "a" * 64, self.targets)
        for index in range(len(self.report["checks"])):
            partial = copy.deepcopy(self.report)
            del partial["checks"][index]
            with self.subTest(missing=index), self.assertRaisesRegex(ValueError, "incomplete"):
                check_qualification(partial, "a" * 64, self.targets)

    def test_skip_duplicate_unreported_runtime_and_wrong_artifact_are_rejected(self):
        changes = [
            lambda r: r.update(environment="staging"),
            lambda r: r.update(manifest_sha256="b" * 64),
            lambda r: r["checks"][0].update(outcome="skipped"),
            lambda r: r["checks"][0].update(runtime=""),
            lambda r: r["checks"].append(r["checks"][0].copy()),
            lambda r: r["checks"][0].update(platform="windows-amd64"),
        ]
        for change in changes:
            report = copy.deepcopy(self.report)
            change(report)
            with self.assertRaises(ValueError):
                check_qualification(report, "a" * 64, self.targets)


if __name__ == "__main__":
    unittest.main()

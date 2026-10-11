"""Release authorization rejects incomplete or misidentified qualification."""

import copy
import unittest

from gate import CASES, NPM_RUNTIMES, check_qualification


class QualificationTests(unittest.TestCase):
    def setUp(self):
        self.targets = {
            "linux-amd64": {"os": "linux", "packages": ["native"]},
            "android-arm64": {"os": "android", "packages": ["android"]},
            "ios-arm64": {"os": "ios", "packages": ["swift"]},
        }
        identities = [(platform, package, name) for platform, package in (("linux-amd64", "native"), ("ios-arm64", "swift")) for name in CASES]
        identities.extend(("android-arm64", "android", name) for name in ("offline", "16k", "live"))
        identities.extend(("portable", "rust", case) for case in CASES)
        for runtime in NPM_RUNTIMES:
            identities.extend(("portable", "npm", f"{runtime}-{case}") for case in CASES)
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
            lambda r: r["checks"].append({**r["checks"][0], "platform": "ios-arm64", "package": "swift"}),
        ]
        for change in changes:
            report = copy.deepcopy(self.report)
            change(report)
            with self.assertRaises(ValueError):
                check_qualification(report, "a" * 64, self.targets)


if __name__ == "__main__":
    unittest.main()

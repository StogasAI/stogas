"""Release authorization rejects incomplete or misidentified qualification."""

import copy
import io
import tarfile
import tempfile
import unittest
from pathlib import Path

from gate import CASES, CRATES, NPM_RUNTIMES, check_crates, check_qualification


class CrateTests(unittest.TestCase):
    def test_refuses_a_release_whose_crate_crates_io_would_refuse(self):
        # crates.io refused alpha.1's stogas-core for this category, after it was signed.
        directory = Path(self.enterContext(tempfile.TemporaryDirectory(prefix="stogas-gate-test-")))

        def pack(name, categories):
            manifest = f'[package]\nname = "{name}"\nversion = "1.2.3"\ncategories = {categories!r}\n'.encode().replace(b"'", b'"')
            with tarfile.open(directory / f"{name}-1.2.3.crate", "w:gz") as archive:
                entry = tarfile.TarInfo(f"{name}-1.2.3/Cargo.toml")
                entry.size = len(manifest)
                archive.addfile(entry, io.BytesIO(manifest))

        for name in CRATES:
            pack(name, ["cryptography"])
        check_crates(directory, "1.2.3")
        pack("stogas-core", ["web-programming::wasm"])
        with self.assertRaisesRegex(ValueError, "^crates.io would refuse stogas-core-1.2.3.crate: category 'web-programming::wasm'$"):
            check_crates(directory, "1.2.3")


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
        self.assertFalse(check_qualification(self.report, "a" * 64, self.targets, "0.1.0"))
        for index in range(len(self.report["checks"])):
            partial = copy.deepcopy(self.report)
            del partial["checks"][index]
            with self.subTest(missing=index), self.assertRaisesRegex(ValueError, "incomplete"):
                check_qualification(partial, "a" * 64, self.targets, "0.1.0")

    def preview(self):
        report = copy.deepcopy(self.report)
        report["checks"] = [check for check in report["checks"] if check["case"] != "live" and not check["case"].endswith("-live")]
        return report

    def test_only_a_pre_release_may_be_a_preview_of_every_offline_check(self):
        self.assertTrue(check_qualification(self.preview(), "a" * 64, self.targets, "0.1.0-alpha.1"))
        # A complete qualification of a pre-release is not a preview.
        self.assertFalse(check_qualification(self.report, "a" * 64, self.targets, "0.1.0-rc.1"))
        with self.assertRaisesRegex(ValueError, "incomplete"):
            check_qualification(self.preview(), "a" * 64, self.targets, "0.1.0")
        for index in range(len(self.preview()["checks"])):
            partial = self.preview()
            del partial["checks"][index]
            with self.subTest(missing=index), self.assertRaisesRegex(ValueError, "incomplete"):
                check_qualification(partial, "a" * 64, self.targets, "0.1.0-alpha.1")
        # Some live cases without the rest are neither complete nor a preview.
        mixed = self.preview()
        mixed["checks"].append({"platform": "linux-amd64", "package": "native", "case": "live", "runtime": "test-runtime", "outcome": "passed"})
        with self.assertRaisesRegex(ValueError, "incomplete"):
            check_qualification(mixed, "a" * 64, self.targets, "0.1.0-alpha.1")

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
                check_qualification(report, "a" * 64, self.targets, "0.1.0")


if __name__ == "__main__":
    unittest.main()

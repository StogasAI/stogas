"""Release authorization rejects incomplete or misidentified qualification."""

import copy
import io
import tarfile
import tempfile
import unittest
from pathlib import Path

from artifacts import function_names, without_names, write_json
from gate import CASES, CRATES, NPM_RUNTIMES, check_artifact_families, check_crates, check_qualification, check_wasm_debug, combine_reports, python_version, read_document
from test_artifacts import named_wasm

TARGETS = {
    "linux-amd64": {"os": "linux", "packages": ["native"]},
    "android-arm64": {"os": "android", "packages": ["android"]},
    "ios-arm64": {"os": "ios", "packages": ["swift"]},
}


def full_report():
    """A passing qualification of every case that TARGETS requires."""
    identities = [(platform, package, name) for platform, package in (("linux-amd64", "native"), ("ios-arm64", "swift")) for name in CASES]
    identities.extend(("android-arm64", "android", name) for name in ("offline", "16k", "live"))
    identities.extend(("portable", "rust", case) for case in CASES)
    for runtime in NPM_RUNTIMES:
        identities.extend(("portable", "npm", f"{runtime}-{case}") for case in CASES)
    return {
        "schema": "stogas.sdk-qualification.v1", "environment": "prod", "manifest_sha256": "a" * 64,
        "checks": [{"platform": platform, "package": package, "case": case, "runtime": "test-runtime", "outcome": "passed"} for platform, package, case in identities],
    }


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


class WasmDebugTests(unittest.TestCase):
    PREFIX = "stogas-v1.2.3-wasm32-debug"

    def check(self, modules, debug):
        """Check a release whose npm packages hold `modules` and whose debug archive holds `debug`."""
        directory = Path(self.enterContext(tempfile.TemporaryDirectory(prefix="stogas-gate-test-")))
        for archive, members in (("stogas-1.2.3.tgz", {"package/pkg/browser/stogas_bg.wasm": modules[0]}), ("stogas-sigstore-1.2.3.tgz", {"package/pkg/browser/stogas_sigstore_bg.wasm": modules[1]}), (f"{self.PREFIX}.tar.gz", debug)):
            with tarfile.open(directory / archive, "w:gz") as output:
                for name, data in members.items():
                    member = tarfile.TarInfo(name)
                    member.size = len(data)
                    output.addfile(member, io.BytesIO(data))
        check_wasm_debug(directory, "1.2.3")

    def debug(self, *named):
        files = {"LICENSE": b"license"}
        for name, module in zip(("stogas_bg.wasm", "stogas_sigstore_bg.wasm"), named):
            files |= {name: module, f"{name}.symbols": function_names(module)}
        return {f"{self.PREFIX}/{name}": data for name, data in files.items()}

    def test_npm_ships_each_named_module_of_the_debug_archive_without_names(self):
        named = [named_wasm("run"), named_wasm("run", "verify")]
        shipped = [without_names(module) for module in named]
        self.check(shipped, self.debug(*named))
        cases = {
            "npm keeps the names": (named, self.debug(*named)),
            "the debug archive has no names": (shipped, self.debug(*shipped)),
            "another module's names": (shipped, self.debug(named[1], named[0])),
            "a changed symbol map": (shipped, self.debug(*named) | {f"{self.PREFIX}/stogas_bg.wasm.symbols": b"0:other\n"}),
            "a missing symbol map": (shipped, {name: data for name, data in self.debug(*named).items() if not name.endswith("stogas_bg.wasm.symbols")}),
            "an extra file": (shipped, self.debug(*named) | {f"{self.PREFIX}/notes.txt": b"notes"}),
        }
        for case, (modules, debug) in cases.items():
            with self.subTest(case=case), self.assertRaises(ValueError):
                self.check(modules, debug)


class QualificationTests(unittest.TestCase):
    def setUp(self):
        self.targets = TARGETS
        self.report = full_report()

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


class CombineReportsTests(unittest.TestCase):
    def setUp(self):
        self.directory = Path(self.enterContext(tempfile.TemporaryDirectory(prefix="stogas-gate-test-")))
        self.report = full_report()

    def shards(self, *parts):
        paths = []
        for index, part in enumerate(parts):
            paths.append(self.directory / f"shard-{index}.json")
            write_json(paths[-1], part)
        return paths

    def test_one_sorted_report_holds_every_shard(self):
        checks = self.report["checks"]
        shards = self.shards({**self.report, "checks": checks[1::2]}, {**self.report, "checks": checks[::2]})
        self.assertFalse(combine_reports(shards, self.directory / "qualification.json", "a" * 64, TARGETS, "0.1.0"))
        combined = read_document(self.directory / "qualification.json")
        self.assertEqual(combined, {**self.report, "checks": sorted(checks, key=lambda check: (check["platform"], check["package"], check["case"]))})

    def test_refuses_another_artifact_set_or_a_missing_shard(self):
        checks = self.report["checks"]
        cases = [
            ("different artifacts", [{**self.report, "checks": checks[1::2]}, {**self.report, "manifest_sha256": "b" * 64, "checks": checks[::2]}]),
            ("different artifacts", [{**self.report, "checks": checks[1::2]}, {**self.report, "environment": "staging", "checks": checks[::2]}]),
            ("incomplete", [{**self.report, "checks": checks[1::2]}]),
            ("Duplicate", [self.report, {**self.report, "checks": checks[:1]}]),
        ]
        for message, parts in cases:
            with self.subTest(message=message, shards=len(parts)), self.assertRaisesRegex(ValueError, message):
                combine_reports(self.shards(*parts), self.directory / "qualification.json", "a" * 64, TARGETS, "0.1.0")
            self.assertFalse((self.directory / "qualification.json").exists())


class ArtifactFamilyTests(unittest.TestCase):
    VERSION = "1.2.3-rc.1"
    TARGETS = {
        "linux-musl-arm64": {"os": "linux", "arch": "arm64", "libc": "musl", "packages": ["native", "python", "ruby"], "ruby": "aarch64-linux-musl"},
        "windows-amd64": {"os": "windows", "arch": "amd64", "packages": ["native", "python", "ruby"], "ruby": "x64-mingw-ucrt"},
        "android-arm64": {"os": "android", "arch": "arm64", "packages": ["native", "android"]},
    }
    NAMES = frozenset({
        "stogas-1.2.3-rc.1.tgz", "stogas-sigstore-1.2.3-rc.1.tgz", "stogas-v1.2.3-rc.1-wasm32-debug.tar.gz", "stogas-source-v1.2.3-rc.1.tar.gz",
        "stogas-sigstore-1.2.3-rc.1.crate", "stogas-core-1.2.3-rc.1.crate", "stogas-1.2.3-rc.1.crate", "stogas-cli-1.2.3-rc.1.crate",
        "stogas-go-v1.2.3-rc.1.tar.gz", "stogas-swift-v1.2.3-rc.1.tar.gz", "stogas-xcframework-v1.2.3-rc.1.zip", "Stogas.1.2.3-rc.1.nupkg",
        "stogas-1.2.3-rc.1.jar", "stogas-1.2.3-rc.1.pom", "stogas-1.2.3-rc.1-sources.jar", "stogas-1.2.3-rc.1-javadoc.jar",
        "stogas-android-1.2.3-rc.1.aar", "stogas-android-1.2.3-rc.1.pom", "stogas-android-1.2.3-rc.1.module",
        "stogas-android-1.2.3-rc.1-sources.jar", "stogas-android-1.2.3-rc.1-javadoc.jar",
        "stogas-v1.2.3-rc.1-linux-musl-arm64.tar.gz", "stogas-v1.2.3-rc.1-linux-musl-arm64-debug.tar.gz",
        "stogas-1.2.3.rc.1-aarch64-linux-musl.gem", "stogas-1.2.3rc1-cp310-abi3-musllinux_1_2_aarch64.whl",
        "stogas-v1.2.3-rc.1-windows-amd64.zip", "stogas-v1.2.3-rc.1-windows-amd64-debug.zip",
        "stogas-1.2.3.rc.1-x64-mingw-ucrt.gem", "stogas-1.2.3rc1-cp310-abi3-win_amd64.whl",
        "stogas-v1.2.3-rc.1-android-arm64.tar.gz", "stogas-v1.2.3-rc.1-android-arm64-debug.tar.gz",
    })

    def test_a_release_holds_exactly_its_package_families(self):
        check_artifact_families(set(self.NAMES), self.TARGETS, self.VERSION)
        for name in sorted(self.NAMES):
            with self.subTest(missing=name), self.assertRaises(ValueError):
                check_artifact_families(self.NAMES - {name}, self.TARGETS, self.VERSION)
        for name in ("notes.txt", "stogas-v1.2.3-rc.1-linux-amd64.tar.gz", "stogas-1.2.3rc1-cp310-abi3-musllinux_1_2_x86_64.whl", "stogas-1.2.3rc1-cp310-abi3-win_arm64.whl", "stogas-1.2.3-cp310-abi3-win_amd64.whl"):
            with self.subTest(extra=name), self.assertRaises(ValueError):
                check_artifact_families(self.NAMES | {name}, self.TARGETS, self.VERSION)

    def test_wheels_carry_the_release_version(self):
        # PyPI takes a release's version from its wheel names.
        renamed = self.NAMES - {"stogas-1.2.3rc1-cp310-abi3-win_amd64.whl"} | {"stogas-1.2.3-cp310-abi3-win_amd64.whl"}
        with self.assertRaisesRegex(ValueError, r"^Release wheels must have version 1\.2\.3rc1$"):
            check_artifact_families(renamed, self.TARGETS, self.VERSION)
        for version, expected in (("1.2.3", "1.2.3"), ("0.1.0-alpha.1", "0.1.0a1"), ("1.0.0-beta.2", "1.0.0b2"), ("2.0.0-rc.10", "2.0.0rc10"), ("1.0.0-alpha", "1.0.0a0")):
            self.assertEqual(python_version(version), expected)
        with self.assertRaises(ValueError):
            python_version("1.0.0-preview.1")


if __name__ == "__main__":
    unittest.main()

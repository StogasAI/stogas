"""Combining builds and comparing package sets, which decide whether a rebuild matches."""

import json
import os
import shutil
import tempfile
import unittest
from pathlib import Path

from artifacts import MANIFEST, inventory, source_digest, write_json
from release import combine, compare


class CompareTests(unittest.TestCase):
    def setUp(self):
        self.root = Path(self.enterContext(tempfile.TemporaryDirectory(prefix="stogas-release-test-")))
        self.first = self.packages("first", {"a.tgz": b"first artifact", "b.zip": b"second artifact"})

    def packages(self, name, files):
        directory = self.root / name
        directory.mkdir()
        for file, data in files.items():
            (directory / file).write_bytes(data)
        write_json(directory / MANIFEST, {"version": "1.2.3", "artifacts": inventory(directory, sorted(files))})
        return directory

    def test_accepts_independent_identical_packages(self):
        compare(self.first, shutil.copytree(self.first, self.root / "second"))

    def test_names_each_artifact_that_differs(self):
        second = self.packages("second", {"a.tgz": b"first artifact", "b.zip": b"rebuilt differently"})
        with self.assertRaisesRegex(ValueError, "^Independent package builds differ: b.zip$"):
            compare(self.first, second)

    def test_refuses_bytes_that_differ_from_their_manifest(self):
        second = shutil.copytree(self.first, self.root / "second")
        (second / "b.zip").write_bytes(b"changed after packaging")
        with self.assertRaisesRegex(ValueError, "bytes differ"):
            compare(self.first, second)
        (second / "b.zip").unlink()
        with self.assertRaisesRegex(ValueError, "inventory differs"):
            compare(self.first, second)

    def test_refuses_to_compare_files_with_themselves(self):
        with self.assertRaisesRegex(ValueError, "two different"):
            compare(self.first, self.first)
        second = shutil.copytree(self.first, self.root / "second")
        (second / "a.tgz").unlink()
        os.link(self.first / "a.tgz", second / "a.tgz")
        with self.assertRaisesRegex(ValueError, "same underlying file"):
            compare(self.first, second)


class CombineTests(unittest.TestCase):
    def setUp(self):
        self.root = Path(self.enterContext(tempfile.TemporaryDirectory(prefix="stogas-release-test-")))
        self.source = self.root / "source"
        (self.source / "release").mkdir(parents=True)
        (self.source / "release/targets.json").write_text(json.dumps({"targets": {"linux-amd64": {}, "ios-arm64": {}}}))

    def build(self, name, platforms, bundles=(), recipe="c" * 64):
        directory = self.root / name
        shutil.copytree(self.source, directory / "source")
        for platform in [*platforms, *bundles]:
            (directory / platform).mkdir()
            (directory / platform / f"{platform}.json").write_text(platform)
        write_json(directory / "build.json", {
            "schema": "stogas.sdk-build-set.v1", "environment": "prod", "source": {"commit": "f" * 40, "sha256": source_digest(self.source)},
            "compiler_recipe_sha256": recipe, "platforms": list(platforms), "bundles": list(bundles),
        })
        return directory

    def test_a_complete_set_holds_every_platform_and_the_apple_bundle(self):
        builds = [self.build("linux", ["portable", "linux-amd64"]), self.build("apple", ["ios-arm64"], ["apple"])]
        combine(builds, self.root / "release", complete=True)
        combined = json.loads((self.root / "release/build.json").read_text())
        self.assertEqual((combined["platforms"], combined["bundles"]), (["ios-arm64", "linux-amd64", "portable"], ["apple"]))
        self.assertEqual(sorted(path.name for path in (self.root / "release").iterdir()), ["apple", "build.json", "ios-arm64", "linux-amd64", "portable", "source"])
        self.assertEqual(source_digest(self.root / "release/source"), source_digest(self.source))

    def test_a_partial_set_needs_no_apple_bundle(self):
        combine([self.build("linux", ["linux-amd64"])], self.root / "release", complete=False)

    def test_refuses_builds_that_cannot_form_one_release(self):
        cases = {
            "more than once": lambda: [self.build("one", ["linux-amd64"]), self.build("two", ["linux-amd64", "ios-arm64", "portable"], ["apple"])],
            "different source or compiler": lambda: [self.build("one", ["linux-amd64", "portable"]), self.build("two", ["ios-arm64"], ["apple"], recipe="d" * 64)],
            "every declared platform": lambda: [self.build("one", ["linux-amd64"]), self.build("two", ["ios-arm64"], ["apple"])],
            "Apple bundle": lambda: [self.build("one", ["linux-amd64", "ios-arm64", "portable"])],
        }
        for message, builds in cases.items():
            with self.subTest(message):
                for directory in self.root.iterdir():
                    if directory != self.source:
                        shutil.rmtree(directory)
                with self.assertRaisesRegex(ValueError, message):
                    combine(builds(), self.root / "release", complete=True)
                self.assertFalse((self.root / "release").exists())

    def test_refuses_a_build_whose_source_changed(self):
        builds = [self.build("linux", ["linux-amd64", "portable"]), self.build("apple", ["ios-arm64"], ["apple"])]
        (builds[1] / "source/release/extra").write_text("not in the recorded source")
        with self.assertRaisesRegex(ValueError, "different source"):
            combine(builds, self.root / "release", complete=True)


if __name__ == "__main__":
    unittest.main()

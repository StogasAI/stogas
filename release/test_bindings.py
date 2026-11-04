"""The Android package compiles the Java package's sources, so it ships the same dependencies."""

import re
import unittest
import xml.etree.ElementTree as ElementTree
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
POM = "{http://maven.apache.org/POM/4.0.0}"


class BindingTests(unittest.TestCase):
    def test_java_and_android_ship_the_same_dependency_versions(self):
        project = ElementTree.parse(ROOT / "bindings/java/pom.xml").getroot()
        java = {
            f"{dependency.findtext(f'{POM}groupId')}:{dependency.findtext(f'{POM}artifactId')}": dependency.findtext(f"{POM}version")
            for dependency in project.iter(f"{POM}dependency")
            if dependency.findtext(f"{POM}scope") not in {"test", "provided"}
        }
        # gradle.lockfile lists what the Android package's consumers install, transitive
        # dependencies included, which scanners read.
        lines = (ROOT / "bindings/android/gradle.lockfile").read_text().splitlines()
        android = dict(
            line.split("=", 1)[0].rsplit(":", 1)
            for line in lines
            if line and not line.startswith("#") and not line.startswith("empty=")
        )
        self.assertTrue(java)
        for name, version in java.items():
            with self.subTest(name=name):
                self.assertEqual(android.get(name), version)
        # The build declares what the lockfile pins.
        build = (ROOT / "bindings/android/build.gradle.kts").read_text()
        for name, version in re.findall(r'(?:api|implementation)\("([\w.-]+:[\w.-]+):([\w.-]+)(?:@\w+)?"\)', build):
            with self.subTest(declared=name):
                self.assertEqual(android.get(name), version)


if __name__ == "__main__":
    unittest.main()

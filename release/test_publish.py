"""Compare our prebuilt-crate metadata with a real Cargo registry upload."""

import json
import unittest
from pathlib import Path

from publish import crate_metadata


class CargoUploadTests(unittest.TestCase):
    def test_metadata_matches_cargo_1_97_1_upload(self):
        # Captured from cargo publish to a loopback Cargo registry. Cargo marks
        # crates.io explicitly when publishing to another registry; ours is the
        # same registry as its dependencies. Bare versions and ^ mean the same.
        fixtures = Path(__file__).with_name("fixtures")
        expected = json.loads((fixtures / "metadata.json").read_text())
        actual = crate_metadata(fixtures / "stogas-upload-fixture-1.2.3.crate")
        for dependency in expected["deps"]:
            self.assertEqual(dependency["registry"], "https://github.com/rust-lang/crates.io-index")
            dependency["registry"] = None
            dependency.setdefault("explicit_name_in_toml", None)
            dependency["version_req"] = dependency["version_req"].removeprefix("^")
        self.assertEqual(actual, expected)


if __name__ == "__main__":
    unittest.main()

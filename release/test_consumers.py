"""The release's consumer tests stay in step with the repository, so a change that would break
them fails CI rather than a release."""

import json
import re
import unittest
from pathlib import Path

import qualify_portable

ROOT = Path(__file__).resolve().parents[1]


class ConsumerTests(unittest.TestCase):
    def test_browser_image_has_the_locked_playwright(self):
        # Each Playwright version runs only the browser builds that its own image carries.
        packages = json.loads((ROOT / "package-lock.json").read_text())["packages"]
        versions = {packages[f"node_modules/{name}"]["version"] for name in ("@playwright/test", "playwright", "playwright-core")}
        self.assertEqual(len(versions), 1)
        self.assertRegex(qualify_portable.PLAYWRIGHT, rf"^mcr\.microsoft\.com/playwright:v{re.escape(versions.pop())}-noble@sha256:[0-9a-f]{{64}}$")

    def test_native_consumer_uses_the_fixture_root(self):
        source = (ROOT / "release/consumers/native.c").read_text()
        block = re.search(r"static const char OFFLINE_ROOT\[\] =\n(.*?);\n", source, re.S)
        self.assertIsNotNone(block)
        pieces = re.findall(r'"((?:[^"\\]|\\.)*)"', block.group(1))
        configuration = json.loads("".join(pieces).replace('\\"', '"'))
        fixture = json.loads((ROOT / "tests/fixtures/hardware-session-v1.json").read_text())
        self.assertEqual(configuration, {"environment": "prod", "root": fixture["root"]})


if __name__ == "__main__":
    unittest.main()

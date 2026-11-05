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


class BrowserQualificationTests(unittest.TestCase):
    def test_release_tests_run_the_stogas_browser_package(self):
        # Release qualification once selected its tests by titles that no longer existed, and ran
        # none of the `stogas` browser package.
        total, live = qualify_portable.release_browser_tests(ROOT / "tests/browser")
        self.assertGreaterEqual(total - live, 3)
        self.assertGreaterEqual(live, 1)
        blocks = re.split(r"\n(?=test\()", (ROOT / "tests/browser/verifier.spec.ts").read_text())
        offline = [block for block in blocks if "tag: '@release'" in block]
        self.assertTrue(any("bindings/browser/browser.js" in block or "servePackage()" in block for block in offline))

    def test_every_generated_config_marks_webkit_garbage_with_one_thread(self):
        for config in (qualify_portable.RELEASE_CONFIG, (ROOT / "scripts/live-test.py").read_text()):
            self.assertIn("name==='webkit'?{launchOptions:{env:{...process.env,JSC_numberOfGCMarkers:'1'}}}", config)

    def report(self, statuses):
        """A Playwright 1.64 JSON report with one release test and one live test per engine."""
        specs = [
            {"tags": ["release"], "tests": [{"projectName": name, "status": statuses.get(name, "expected")} for name in qualify_portable.BROWSERS]},
            {"tags": ["release", "live"], "tests": [{"projectName": name, "status": "skipped"} for name in qualify_portable.BROWSERS]},
        ]
        return {"suites": [{"title": "verifier.spec.ts", "specs": [], "suites": [{"specs": specs}]}]}

    def test_each_engine_passes_only_on_its_own_results(self):
        outcomes = qualify_portable.browser_outcomes(self.report({"webkit": "unexpected"}), "offline", (2, 1))
        self.assertEqual(outcomes, {"chromium": "passed", "firefox": "passed", "webkit": "failed"})

    def test_an_engine_that_ran_too_few_tests_failed(self):
        self.assertEqual(set(qualify_portable.browser_outcomes(self.report({}), "offline", (3, 1)).values()), {"failed"})
        self.assertEqual(set(qualify_portable.browser_outcomes({}, "offline", (2, 1)).values()), {"failed"})

    def test_only_an_offline_case_may_skip_the_live_test(self):
        self.assertEqual(set(qualify_portable.browser_outcomes(self.report({}), "live", (2, 1)).values()), {"failed"})


if __name__ == "__main__":
    unittest.main()

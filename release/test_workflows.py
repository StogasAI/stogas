import re
import unittest
from pathlib import Path

WORKFLOWS = Path(__file__).resolve().parents[1] / ".github/workflows"


def jobs(workflow):
    """Each top-level job's name and text."""
    body = (WORKFLOWS / workflow).read_text().split("\njobs:\n", 1)[1]
    return dict(re.findall(r"^  ([a-z-]+):\n(.*?)(?=^  [a-z-]+:\n|\Z)", body, flags=re.M | re.S))


class ReleaseWorkflowTests(unittest.TestCase):
    def test_only_the_phone_targets_can_mint_tokens_during_qualification(self):
        # A qualification step runs third-party build tools. Only the Device Farm sign-in needs a
        # token, and the called workflow's identity keeps it from passing for a release attestation.
        release = jobs("release.yml")
        self.assertEqual({name for name, job in release.items() if "id-token: write" in job}, {"qualify-phones", "release"})
        phones = re.findall(r"^          - \{.*?\}$", release["qualify-phones"], flags=re.M | re.S)
        self.assertEqual(len(phones), 2)
        self.assertTrue(all("device-farm: true" in target for target in phones))
        self.assertNotIn("device-farm", release["qualify"])
        for name in ("qualify", "qualify-phones"):
            self.assertIn("uses: $/.github/workflows/qualify.yml\n", release[name])
        called = (WORKFLOWS / "qualify.yml").read_text()
        self.assertNotIn("permissions:", called)
        self.assertNotIn("id-token", called)

    def test_a_version_is_attested_once_at_its_tagged_commit(self):
        job = jobs("release.yml")["release"]
        self.assertLess(job.index("name: Require the tag at this commit and no release for it"), job.index("uses: actions/attest@"))


class CiWorkflowTests(unittest.TestCase):
    def test_wheels_are_built_with_the_maturin_that_releases_use(self):
        release = WORKFLOWS.parents[1] / "release"
        pins = re.findall(r"maturin(?:==|-)([0-9]+\.[0-9]+\.[0-9]+)\b", (release / "Dockerfile").read_text() + (release / "apple-requirements.txt").read_text())
        self.assertEqual(len(pins), 2)
        ci = (WORKFLOWS / "ci.yml").read_text()
        builds = re.findall(r"uses: PyO3/maturin-action@[0-9a-f]+\n        with:\n(?:          #.*\n)?          maturin-version: v(\S+)\n", ci)
        self.assertEqual(len(builds), ci.count("PyO3/maturin-action@"))
        self.assertEqual(set(pins) | set(builds), {pins[0]})

    def test_wasm_bindgen_runs_at_the_version_of_its_locked_library(self):
        # wasm-bindgen refuses a module that another version of its library built.
        root = WORKFLOWS.parents[1]
        locked = re.search(r'\[\[package\]\]\nname = "wasm-bindgen"\nversion = "([^"]+)"', (root / "Cargo.lock").read_text())[1]
        pins = re.findall(r"wasm-bindgen-cli --version =?(\S+)", (root / "release" / "Dockerfile").read_text() + (WORKFLOWS / "ci.yml").read_text())
        self.assertEqual(len(pins), 2)
        self.assertEqual(set(pins), {locked})


class PublishWorkflowTests(unittest.TestCase):
    def test_publication_ends_by_installing_from_every_channel_without_credentials(self):
        self.assertIn("uses: $/.github/workflows/installs.yml\n", jobs("publish.yml")["installs"])
        installs = (WORKFLOWS / "installs.yml").read_text()
        self.assertEqual(set(jobs("installs.yml")), {"offered", "homebrew", "scoop", "aur", "binstall", "container"})
        for forbidden in (": write", "secrets.", "id-token"):
            self.assertNotIn(forbidden, installs)


if __name__ == "__main__":
    unittest.main()

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


if __name__ == "__main__":
    unittest.main()

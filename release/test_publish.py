"""Check crate upload metadata and npm staging without a registry."""

import contextlib
import io
import json
import os
import sys
import tarfile
import tempfile
import unittest
from pathlib import Path
from unittest import mock

import publish
from publish import crate_metadata

# Plays npm's staging queue: the registry keeps each staged archive under a new ID.
FAKE_NPM = """#!{python} -I
import json, os, shutil, sys, tarfile, uuid
from pathlib import Path

queue = Path(os.environ["FAKE_NPM_QUEUE"])
command = sys.argv[1:]
if command == ["stage", "list", "--json"]:
    print(json.dumps([json.loads(item.read_text()) for item in sorted(queue.glob("*.json"))]))
elif command[:2] == ["stage", "publish"] and command[3:] == ["--access", "public"]:
    with tarfile.open(command[2]) as archive:
        manifest = json.load(archive.extractfile("package/package.json"))
    stage = str(uuid.uuid4())
    shutil.copyfile(command[2], queue / f"{{stage}}.tgz")
    item = {{"id": stage, "packageName": manifest["name"], "version": manifest["version"]}}
    (queue / f"{{stage}}.json").write_text(json.dumps(item))
elif command[:2] == ["stage", "download"]:
    shutil.copyfile(queue / f"{{command[2]}}.tgz", Path.cwd() / f"staged-{{command[2]}}.tgz")
else:
    sys.exit(f"unexpected npm {{command}}")
"""


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


class NpmStageTests(unittest.TestCase):
    def setUp(self):
        directory = Path(self.enterContext(tempfile.TemporaryDirectory(prefix="stogas-npm-test-")))
        self.packages = directory / "packages"
        self.queue = directory / "queue"
        tools = directory / "bin"
        for path in (self.packages, self.queue, tools):
            path.mkdir()
        for name, filename in (("@stogas/sigstore", "stogas-sigstore"), ("stogas", "stogas")):
            manifest = json.dumps({"name": name, "version": "1.2.3"}).encode()
            with tarfile.open(self.packages / f"{filename}-1.2.3.tgz", "w:gz") as archive:
                entry = tarfile.TarInfo("package/package.json")
                entry.size = len(manifest)
                archive.addfile(entry, io.BytesIO(manifest))
        (tools / "npm").write_text(FAKE_NPM.format(python=sys.executable))
        (tools / "npm").chmod(0o755)
        path = f"{tools}{os.pathsep}{os.environ['PATH']}"
        self.enterContext(mock.patch.dict(os.environ, {"PATH": path, "FAKE_NPM_QUEUE": str(self.queue)}))
        # Neither version is published yet.
        self.enterContext(mock.patch.object(publish, "download", return_value=None))

    def stage(self):
        with contextlib.redirect_stdout(io.StringIO()) as output:
            publish.npm(self.packages, "1.2.3", stage=True)
        return output.getvalue()

    def test_stages_each_new_version_once_with_the_approved_bytes(self):
        self.assertIn("stogas@1.2.3 awaits approval on npmjs.com", self.stage())
        # A rerun finds the staged versions instead of staging them again.
        self.assertIn("@stogas/sigstore@1.2.3 awaits approval", self.stage())
        staged = [json.loads(item.read_text()) for item in self.queue.glob("*.json")]
        self.assertCountEqual([item["packageName"] for item in staged], ["@stogas/sigstore", "stogas"])

    def test_refuses_a_staged_version_with_other_bytes(self):
        self.stage()
        for archive in self.queue.glob("*.tgz"):
            archive.write_bytes(b"other")
        with self.assertRaisesRegex(ValueError, "npm staged different bytes as @stogas/sigstore@1.2.3"):
            self.stage()


class CratesTrustTests(unittest.TestCase):

    def test_trusts_only_publish_yml_then_revokes_the_token(self):
        calls = []
        existing = {"stogas-core": [{**publish.PUBLISHER, "crate": "stogas-core", "id": 1}]}

        def api(method, path, token, body=None):
            self.assertEqual(token, "one-time")
            calls.append((method, path, body))
            if method == "GET":
                return {"github_configs": existing.get(path.rsplit("=", 1)[1], [])}
            return None

        with mock.patch.object(publish, "crates_api", side_effect=api), contextlib.redirect_stdout(io.StringIO()):
            publish.crates_trust("one-time")
        # A rerun keeps an existing configuration instead of adding a second one.
        created = [body["github_config"]["crate"] for method, _, body in calls if method == "POST"]
        self.assertEqual(created, ["stogas-sigstore", "stogas", "stogas-cli"])
        updated = [(path, body) for method, path, body in calls if method == "PATCH"]
        self.assertEqual(updated, [(f"crates/{name}", {"crate": {"trustpub_only": True}}) for name in publish.CRATES])
        self.assertEqual(calls[-1][:2], ("DELETE", "tokens/current"))


if __name__ == "__main__":
    unittest.main()

"""Check crate upload metadata and npm staging without a registry."""

import contextlib
import io
import json
import os
import sys
import tarfile
import tempfile
import tomllib
import unittest
import urllib.error
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
elif command[:2] == ["stage", "publish"] and command[3:5] == ["--access", "public"] and command[5:] in (["--provenance=false"], ["--tag", "next", "--provenance=false"]):
    with tarfile.open(command[2]) as archive:
        manifest = json.load(archive.extractfile("package/package.json"))
    # Like npm, refuse a pre-release without a dist-tag.
    if "-" in manifest["version"] and command[5] != "--tag":
        sys.exit("npm requires a tag for a pre-release")
    stage = str(uuid.uuid4())
    shutil.copyfile(command[2], queue / f"{{stage}}.tgz")
    item = {{"id": stage, "packageName": manifest["name"], "version": manifest["version"], "tag": command[6] if command[5] == "--tag" else "latest"}}
    (queue / f"{{stage}}.json").write_text(json.dumps(item))
elif command[:2] == ["stage", "publish"]:
    # npm outside CI cannot generate the provenance that package.json's publishConfig asks for.
    print("npm error code EUSAGE")
    print("npm error Automatic provenance generation not supported for provider: null")
    sys.exit(1)
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


class CrateManifestTests(unittest.TestCase):
    def test_categories_are_ones_crates_io_supports(self):
        # crates.io refuses an upload that names any other category, and reads them from the
        # archive's Cargo.toml. The list is https://crates.io/api/v1/category_slugs on November 5, 2026.
        supported = set(Path(__file__).with_name("fixtures").joinpath("crates-io-category-slugs.txt").read_text().split())
        manifests = sorted(Path(__file__).resolve().parents[1].glob("crates/*/Cargo.toml"))
        self.assertTrue(manifests)
        for manifest in manifests:
            package = tomllib.loads(manifest.read_text())["package"]
            if package.get("publish", True) is not False:
                self.assertEqual(set(package.get("categories", [])) - supported, set(), manifest)


class NpmStageTests(unittest.TestCase):
    def setUp(self):
        directory = Path(self.enterContext(tempfile.TemporaryDirectory(prefix="stogas-npm-test-")))
        self.packages = directory / "packages"
        self.queue = directory / "queue"
        tools = directory / "bin"
        for path in (self.packages, self.queue, tools):
            path.mkdir()
        for version in ("1.2.3", "1.2.3-alpha.1"):
            for name, filename in publish.NPM_PACKAGES:
                manifest = json.dumps({"name": name, "version": version, "publishConfig": {"access": "public", "provenance": True}}).encode()
                with tarfile.open(self.packages / f"{filename}-{version}.tgz", "w:gz") as archive:
                    entry = tarfile.TarInfo("package/package.json")
                    entry.size = len(manifest)
                    archive.addfile(entry, io.BytesIO(manifest))
        (tools / "npm").write_text(FAKE_NPM.format(python=sys.executable))
        (tools / "npm").chmod(0o755)
        path = f"{tools}{os.pathsep}{os.environ['PATH']}"
        self.enterContext(mock.patch.dict(os.environ, {"PATH": path, "FAKE_NPM_QUEUE": str(self.queue)}))
        # Neither version is published yet.
        self.enterContext(mock.patch.object(publish, "download", return_value=None))

    def stage(self, version="1.2.3"):
        with contextlib.redirect_stdout(io.StringIO()) as output:
            publish.npm(self.packages, version, stage=True)
        return output.getvalue()

    def test_stages_each_new_version_once_with_the_approved_bytes(self):
        self.assertIn("stogas@1.2.3 awaits approval on npmjs.com", self.stage())
        # A rerun finds the staged versions instead of staging them again.
        self.assertIn("@stogas/sigstore@1.2.3 awaits approval", self.stage())
        staged = [json.loads(item.read_text()) for item in self.queue.glob("*.json")]
        self.assertCountEqual([item["packageName"] for item in staged], ["@stogas/sigstore", "stogas"])

    def test_stages_a_pre_release_under_next_and_leaves_latest_alone(self):
        self.assertIn("stogas@1.2.3-alpha.1 awaits approval", self.stage("1.2.3-alpha.1"))
        staged = [json.loads(item.read_text()) for item in self.queue.glob("*.json")]
        self.assertEqual({(item["version"], item["tag"]) for item in staged}, {("1.2.3-alpha.1", "next")})

    def test_a_failure_names_only_npms_error_code(self):
        # Without --provenance=false, npm on a maintainer's machine refuses package.json's request.
        with self.assertRaisesRegex(RuntimeError, r"^npm failed \(exit 1, npm error code EUSAGE\); registry publication stopped$"):
            publish.run(["npm", "stage", "publish", str(self.packages / "stogas-1.2.3.tgz"), "--access", "public"])

    def test_refuses_a_staged_version_with_other_bytes(self):
        self.stage()
        for archive in self.queue.glob("*.tgz"):
            archive.write_bytes(b"other")
        with self.assertRaisesRegex(ValueError, "npm staged different bytes as @stogas/sigstore@1.2.3"):
            self.stage()


class ReadbackTests(unittest.TestCase):
    def test_reads_back_until_the_deadline_then_names_it(self):
        clock = [0.0]

        def sleep(seconds):
            clock[0] += seconds

        with mock.patch.object(publish.time, "monotonic", side_effect=lambda: clock[0]), mock.patch.object(publish.time, "sleep", side_effect=sleep):
            with self.assertRaisesRegex(RuntimeError, "within 60 minutes$"):
                publish.wait_for(lambda: False, minutes=60)
        self.assertGreaterEqual(clock[0], 3600)
        self.assertLess(clock[0], 3610)

    def test_nuget_waits_an_hour_for_its_index(self):
        # nuget.org served the first version more than 5 minutes after accepting it.
        directory = Path(self.enterContext(tempfile.TemporaryDirectory(prefix="stogas-nuget-test-")))
        (directory / "Stogas.1.2.3.nupkg").write_bytes(b"package")
        commands, waits = [], []
        with mock.patch.dict(os.environ, {"NUGET_API_KEY": "short-lived"}), mock.patch.object(publish, "download", return_value=None), mock.patch.object(publish, "run", side_effect=lambda arguments, **_: commands.append(arguments[:3])), mock.patch.object(publish, "wait_for", side_effect=lambda check, minutes=5: waits.append(minutes)):
            publish.nuget(directory, "1.2.3")
        self.assertEqual(commands, [["dotnet", "nuget", "push"]])
        self.assertEqual(waits, [60])


class StorageHostTests(unittest.TestCase):
    """static.crates.io and rubygems.org/downloads answered 403 for a missing file on November 5, 2026."""

    def setUp(self):
        self.packages = Path(self.enterContext(tempfile.TemporaryDirectory(prefix="stogas-storage-test-")))
        self.served = {}

        def urlopen(request, timeout):
            if request.full_url not in self.served:
                storage = request.full_url.startswith(("https://static.crates.io/", "https://rubygems.org/downloads/"))
                raise urllib.error.HTTPError(request.full_url, 403 if storage else 404, "absent", {}, None)
            return contextlib.closing(io.BytesIO(self.served[request.full_url]))

        self.enterContext(mock.patch.object(publish.urllib.request, "urlopen", side_effect=urlopen))
        self.enterContext(mock.patch.object(publish, "wait_for", side_effect=lambda check, minutes=5: self.assertTrue(check())))

    def test_uploads_each_crate_the_storage_host_does_not_hold(self):
        uploaded = []

        def upload(path, metadata, token):
            name = path.name.removesuffix("-1.2.3.crate")
            uploaded.append(name)
            self.served[f"https://static.crates.io/crates/{name}/{path.name}"] = path.read_bytes()
            entry = {"vers": "1.2.3", "cksum": publish.digest(path), "yanked": False}
            self.served[f"https://index.crates.io/{name[:2]}/{name[2:4]}/{name}"] = json.dumps(entry).encode()

        for name in publish.CRATES:
            (self.packages / f"{name}-1.2.3.crate").write_bytes(name.encode())
        with mock.patch.dict(os.environ, {"CARGO_REGISTRY_TOKEN": "one-time"}), mock.patch.object(publish, "crate_metadata", return_value={}), mock.patch.object(publish, "crate_upload", side_effect=upload):
            publish.crates(self.packages, "1.2.3")
            self.assertEqual(uploaded, list(publish.CRATES))
            # A rerun finds every crate and uploads none.
            publish.crates(self.packages, "1.2.3")
        self.assertEqual(uploaded, list(publish.CRATES))

    def test_pushes_a_gem_the_storage_host_does_not_hold(self):
        gem = self.packages / "stogas-1.2.3-x86_64-linux.gem"
        gem.write_bytes(b"gem")
        pushed = []

        def run(arguments, **_):
            pushed.append(arguments[:2])
            self.served[f"https://rubygems.org/downloads/{gem.name}"] = gem.read_bytes()

        with mock.patch.object(publish, "run", side_effect=run):
            publish.ruby(self.packages, "1.2.3")
            publish.ruby(self.packages, "1.2.3")
        self.assertEqual(pushed, [["gem", "push"]])

    def test_other_registries_still_fail_on_403(self):
        self.served.clear()
        with mock.patch.object(publish.urllib.request, "urlopen", side_effect=urllib.error.HTTPError("https://registry.npmjs.org/stogas", 403, "forbidden", {}, None)):
            with self.assertRaisesRegex(RuntimeError, r"HTTP 403"):
                publish.download("https://registry.npmjs.org/stogas")


class FirstVersionTests(unittest.TestCase):
    def test_names_each_registry_with_none_of_its_packages(self):
        existing = {"https://crates.io/api/v1/crates/stogas-core", "https://rubygems.org/api/v1/gems/stogas.json"}
        with mock.patch.object(publish, "download", side_effect=lambda url: b"{}" if url in existing else None), contextlib.redirect_stdout(io.StringIO()) as output:
            publish.first_versions()
        # One existing crate means crates.io trusts this workflow, or should.
        self.assertEqual(output.getvalue().split(), ["crates=false", "npm=true", "ruby=false"])

    def test_npm_waits_while_its_versions_are_only_staged(self):
        # As npm served both packages on November 3, 2026, between staging and approval.
        staged = json.dumps({"name": "stogas", "dist-tags": {"latest": "0.0.0-stage"}, "versions": {"0.0.0-stage": {}}}).encode()
        approved = json.dumps({"versions": {"0.0.0-stage": {}, "0.1.0-alpha.1": {}}}).encode()
        for documents, waiting in (({"stogas": staged, "%40stogas%2Fsigstore": staged}, "npm=true"), ({"stogas": approved, "%40stogas%2Fsigstore": staged}, "npm=false")):
            def download(url):
                return documents.get(url.removeprefix("https://registry.npmjs.org/"))
            with mock.patch.object(publish, "download", side_effect=download), contextlib.redirect_stdout(io.StringIO()) as output:
                publish.first_versions()
            self.assertIn(waiting, output.getvalue().split())


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

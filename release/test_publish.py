"""Check crate upload metadata and npm staging without a registry."""

import contextlib
import io
import json
import os
import re
import sys
import tarfile
import tempfile
import tomllib
import unittest
import urllib.error
from pathlib import Path
from unittest import mock

import gate
import publish
from publish import crate_metadata

ROOT = Path(__file__).resolve().parents[1]

# Plays npm's staging queue: the registry keeps each staged archive under a new ID.
FAKE_NPM = """#!{python} -I
import json, os, shutil, sys, tarfile, uuid
from pathlib import Path

queue = Path(os.environ["FAKE_NPM_QUEUE"])
command = sys.argv[1:]
if command == ["stage", "list", "--json"]:
    print(json.dumps([json.loads(item.read_text()) for item in sorted(queue.glob("*.json"))]))
elif command[:2] == ["stage", "publish"] and command[3:6] == ["--access", "public", "--tag"] and command[7:] == ["--provenance=false"]:
    with tarfile.open(command[2]) as archive:
        manifest = json.load(archive.extractfile("package/package.json"))
    stage = str(uuid.uuid4())
    shutil.copyfile(command[2], queue / f"{{stage}}.tgz")
    item = {{"id": stage, "packageName": manifest["name"], "version": manifest["version"], "tag": command[6]}}
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


def published_manifests():
    for path in sorted(ROOT.glob("crates/*/Cargo.toml")):
        manifest = tomllib.loads(path.read_text())
        if manifest["package"].get("publish", True) is not False:
            yield path, manifest


def locked(path):
    return {(package["name"], package["version"]) for package in tomllib.loads(path.read_text())["package"] if "source" in package}


class CrateManifestTests(unittest.TestCase):
    def test_crates_io_accepts_every_published_crate(self):
        published = {}
        for path, manifest in published_manifests():
            published[manifest["package"]["name"]] = manifest
            self.assertEqual(gate.crate_refusals(manifest["package"]), [], path)
            # crates.io records an SPDX expression; the archive carries the text, which release
            # inputs cannot link to.
            self.assertEqual(manifest["package"]["license"], {"workspace": True}, path)
            self.assertEqual((path.parent / "LICENSE").read_bytes(), (ROOT / "LICENSE").read_bytes(), path)
        self.assertEqual(set(published), set(gate.CRATES))
        self.assertEqual(tomllib.loads((ROOT / "Cargo.toml").read_text())["workspace"]["package"]["license"], "Apache-2.0")

    def test_published_crates_require_versions_that_dependents_can_share(self):
        # An exact requirement makes every project that uses the crate take that one version.
        # The siblings release together, and signatures cover the canonicalizer's output; Cargo
        # refuses an exact sibling requirement that differs from the sibling's version.
        workspace = tomllib.loads((ROOT / "Cargo.toml").read_text())["workspace"]
        exact = {"stogas", "stogas-core", "stogas-sigstore", "serde_json_canonicalizer"}
        for path, manifest in published_manifests():
            for table in [manifest, *manifest.get("target", {}).values()]:
                for kind in ("dependencies", "build-dependencies"):
                    for name, dependency in table.get(kind, {}).items():
                        if isinstance(dependency, dict) and dependency.get("workspace"):
                            dependency = workspace["dependencies"][name]
                        requirement = dependency if isinstance(dependency, str) else dependency["version"]
                        with self.subTest(crate=path.parent.name, dependency=name):
                            self.assertEqual(requirement.startswith("="), name in exact, requirement)

    def test_test_workspaces_lock_the_shipped_versions(self):
        # The probe and fuzz targets must test the dependency versions that the crates ship with.
        shipped = locked(ROOT / "Cargo.lock")
        names = {name for name, _ in shipped}
        for workspace in ("fuzz", "tests/security/probe"):
            with self.subTest(workspace=workspace):
                self.assertEqual(sorted(entry for entry in locked(ROOT / workspace / "Cargo.lock") - shipped if entry[0] in names), [])

    def test_names_what_crates_io_would_refuse(self):
        # Both refusals that alpha.1's crates met, and the limits beside them in publish.rs.
        package = {
            "keywords": ["confidential-computing", "sev-snp", "-dash", "ok_1+", "e", "f"],
            "categories": ["web-programming::wasm", "cryptography"],
        }
        self.assertEqual(gate.crate_refusals(package), [
            "6 keywords", "keyword 'confidential-computing'", "keyword '-dash'", "category 'web-programming::wasm'",
        ])
        self.assertEqual(gate.crate_refusals({"categories": ["wasm"] * 6}), ["6 categories"])
        self.assertEqual(gate.crate_refusals({}), [])


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
        # Neither version is published yet, and 1.0.0 is the newest full release.
        self.enterContext(mock.patch.object(publish, "download", return_value=None))
        self.releases = [{"tag_name": "v1.0.0", "draft": False}]
        self.enterContext(mock.patch.object(publish, "releases", side_effect=lambda: self.releases))

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

    def test_latest_follows_what_the_other_package_managers_offer(self):
        self.assertEqual(publish.npm_tag("1.2.3"), "latest")
        self.assertEqual(publish.npm_tag("0.9.1"), "maintenance")
        self.assertEqual(publish.npm_tag("1.2.3-alpha.1"), "next")
        # Before the first full release, the newest preview is latest, even while its GitHub
        # release is still a draft, as when the first version is staged.
        self.releases = [{"tag_name": "v0.1.0-alpha.1", "draft": False}, {"tag_name": "v0.1.0-alpha.2", "draft": True}]
        self.assertEqual(publish.npm_tag("0.1.0-alpha.2"), "latest")
        self.releases[1]["draft"] = False
        self.assertEqual(publish.npm_tag("0.1.0-alpha.1"), "next")

    def test_a_failure_shows_the_tools_reason_and_names_npms_error_code(self):
        # Without --provenance=false, npm on a maintainer's machine refuses package.json's request.
        with contextlib.redirect_stderr(io.StringIO()) as errors:
            with self.assertRaisesRegex(RuntimeError, r"^npm failed \(exit 1, npm error code EUSAGE\); registry publication stopped$"):
                publish.run(["npm", "stage", "publish", str(self.packages / "stogas-1.2.3.tgz"), "--access", "public"])
        self.assertIn("Automatic provenance generation not supported", errors.getvalue())

    def test_refuses_a_staged_version_with_other_bytes(self):
        self.stage()
        for archive in self.queue.glob("*.tgz"):
            archive.write_bytes(b"other")
        with self.assertRaisesRegex(ValueError, "npm staged different bytes as @stogas/sigstore@1.2.3"):
            self.stage()


class ReadbackTests(unittest.TestCase):
    def setUp(self):
        self.clock = [0.0]

        def sleep(seconds):
            self.clock[0] += seconds

        self.enterContext(mock.patch.object(publish.time, "monotonic", side_effect=lambda: self.clock[0]))
        self.enterContext(mock.patch.object(publish.time, "sleep", side_effect=sleep))

    def test_reads_back_until_the_deadline_then_names_it(self):
        with self.assertRaisesRegex(RuntimeError, "^stogas@1.2.3 did not become available for verified readback within 60 minutes$"):
            publish.wait_for(lambda: False, "stogas@1.2.3", minutes=60)
        self.assertGreaterEqual(self.clock[0], 3600)
        self.assertLess(self.clock[0], 3610)

    def test_a_read_that_may_succeed_later_only_delays_readback(self):
        failures = [urllib.error.HTTPError("https://api.nuget.org/x", 503, "unavailable", {}, None), urllib.error.URLError("no DNS"), TimeoutError()]

        def urlopen(request, timeout):
            if failures:
                raise failures.pop(0)
            return contextlib.closing(io.BytesIO(b"served"))

        with mock.patch.object(publish.urllib.request, "urlopen", side_effect=urlopen):
            publish.wait_for(lambda: publish.download("https://api.nuget.org/x") == b"served", "x")
        self.assertEqual(self.clock[0], 30)

    def test_names_the_last_failed_read_at_the_deadline(self):
        with mock.patch.object(publish.urllib.request, "urlopen", side_effect=urllib.error.URLError("no DNS")):
            with self.assertRaisesRegex(RuntimeError, r"within 5 minutes; the last read failed: Registry read of https://api.nuget.org/x failed \(URLError\)$"):
                publish.wait_for(lambda: publish.download("https://api.nuget.org/x?token=1") is not None, "x")

    def test_other_failures_stop_readback_at_once(self):
        def differs():
            raise ValueError("Registry already contains different bytes: x")

        with self.assertRaisesRegex(ValueError, "different bytes"):
            publish.wait_for(differs, "x")
        self.assertEqual(self.clock[0], 0)

    def test_nuget_waits_an_hour_for_its_index_and_skips_a_taken_version(self):
        # nuget.org served the first version more than 5 minutes after accepting it.
        directory = Path(self.enterContext(tempfile.TemporaryDirectory(prefix="stogas-nuget-test-")))
        (directory / "Stogas.1.2.3.nupkg").write_bytes(b"package")
        commands, waits = [], []
        with mock.patch.dict(os.environ, {"NUGET_API_KEY": "short-lived"}), mock.patch.object(publish, "download", return_value=None), mock.patch.object(publish, "run", side_effect=lambda arguments, **_: commands.append(arguments)), mock.patch.object(publish, "wait_for", side_effect=lambda check, what, minutes=5: waits.append((what, minutes))):
            publish.nuget(directory, "1.2.3")
        self.assertEqual([command[:3] for command in commands], [["dotnet", "nuget", "push"]])
        self.assertEqual(commands[0][-1], "--skip-duplicate")
        self.assertEqual(waits, [("Stogas.1.2.3.nupkg", 60)])

    def test_maven_waits_for_files_still_syncing_instead_of_deploying_again(self):
        directory = Path(self.enterContext(tempfile.TemporaryDirectory(prefix="stogas-maven-test-")))
        for name in ("stogas-1.2.3.jar", "stogas-1.2.3.pom"):
            (directory / name).write_bytes(name.encode())
        served = {"https://repo.maven.apache.org/maven2/ai/stogas/stogas/1.2.3/stogas-1.2.3.pom": b"stogas-1.2.3.pom"}
        commands = []
        with mock.patch.object(publish, "download", side_effect=lambda url, absent=(404,): served.get(url)), mock.patch.object(publish, "run", side_effect=lambda arguments, **_: commands.append(arguments)):
            with self.assertRaisesRegex(RuntimeError, "^ai.stogas 1.2.3 on Maven Central did not become available for verified readback within 30 minutes$"):
                publish.maven(directory, "1.2.3")
        self.assertEqual(commands, [])


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
        self.enterContext(mock.patch.object(publish, "wait_for", side_effect=lambda check, what, minutes=5: self.assertTrue(check(), what)))

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

    def test_uploads_no_crate_while_crates_io_would_refuse_any(self):
        for name in publish.CRATES:
            (self.packages / f"{name}-1.2.3.crate").write_bytes(name.encode())
        metadata = lambda path: {"keywords": ["confidential-computing"]} if path.name.startswith("stogas-core-") else {}
        with mock.patch.object(publish, "crate_metadata", side_effect=metadata), mock.patch.object(publish, "crate_upload") as upload:
            with self.assertRaisesRegex(ValueError, "^crates.io would refuse stogas-core-1.2.3.crate: keyword 'confidential-computing'$"):
                publish.crates(self.packages, "1.2.3")
        upload.assert_not_called()

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
            with self.assertRaisesRegex(RuntimeError, r"^Registry read of https://registry.npmjs.org/stogas failed \(HTTP 403\)$"):
                publish.download("https://registry.npmjs.org/stogas")


class FirstVersionTests(unittest.TestCase):
    def first_versions(self, documents):
        with mock.patch.object(publish, "download", side_effect=documents.get), contextlib.redirect_stdout(io.StringIO()) as output:
            publish.first_versions()
        return output.getvalue().split()

    def test_names_each_registry_that_waits_for_a_one_time_setup(self):
        documents = {"https://rubygems.org/api/v1/gems/stogas.json": b"{}"}
        self.assertEqual(self.first_versions(documents), ["crates=true", "npm=true", "ruby=false"])

    def test_crates_wait_until_every_crate_trusts_only_publish_yml(self):
        # The one-time token finishes a partial first upload, which trusted publishing cannot.
        crate = lambda trusted: json.dumps({"crate": {"trustpub_only": trusted}}).encode()
        documents = {f"https://crates.io/api/v1/crates/{name}": crate(True) for name in publish.CRATES}
        self.assertIn("crates=false", self.first_versions(documents))
        documents["https://crates.io/api/v1/crates/stogas-cli"] = crate(False)
        self.assertIn("crates=true", self.first_versions(documents))
        del documents["https://crates.io/api/v1/crates/stogas-cli"]
        self.assertIn("crates=true", self.first_versions(documents))

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

    def test_trusts_only_publish_yml(self):
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
        # crates.io refuses a scoped token's request to revoke itself.
        self.assertNotIn("DELETE", [method for method, _, _ in calls])



class WorkflowTests(unittest.TestCase):
    def setUp(self):
        self.workflow = (ROOT / ".github/workflows/publish.yml").read_text()

    def test_only_first_party_code_runs_where_registries_trust_the_workflow(self):
        # Any step of a job with id-token can mint the token that every registry trusts.
        jobs = re.split(r"^  (?=[a-z-]+:$)", self.workflow.split("\njobs:\n", 1)[1], flags=re.M)
        trusted = [job for job in jobs if "id-token: write" in job]
        self.assertEqual(len(trusted), 1)
        for command in ("cargo ", "npm install", "npm ci", "pip install", "bun install", "uv "):
            self.assertNotIn(command, trusted[0])
        self.assertIn("needs: verify", trusted[0])

    def test_a_pending_publication_waits_its_turn(self):
        # By default a new run in the group cancels the pending one, which could be another release's.
        self.assertIn("\n  cancel-in-progress: false\n  queue: max\n", self.workflow)


if __name__ == "__main__":
    unittest.main()

"""Check the package manager files and the container image without the network."""

import contextlib
import gzip
import hashlib
import io
import json
import os
import subprocess
import tarfile
import tempfile
import unittest
import urllib.error
import urllib.parse
from pathlib import Path
from unittest import mock

import channels
import publish
from artifacts import tar_gz

VERSION = "0.1.0-alpha.1"
PLATFORMS = ("darwin-amd64", "darwin-arm64", "linux-amd64", "linux-arm64", "linux-musl-amd64", "linux-musl-arm64", "windows-amd64", "windows-arm64")


def manifest(version=VERSION, platforms=PLATFORMS):
    return {
        "version": version,
        "source": {"commit": "a" * 40, "dirty": False, "epoch": 1793664000, "sha256": "b" * 64},
        "artifacts": sorted((
            {"name": f"stogas-v{version}-{platform}.{'zip' if platform.startswith('windows') else 'tar.gz'}", "sha256": hashlib.sha256(platform.encode()).hexdigest(), "size": 1}
            for platform in platforms
        ), key=lambda artifact: artifact["name"]),
    }


def release(tag, draft=False):
    return {"tag_name": tag, "draft": draft}


class VersionTests(unittest.TestCase):
    def test_semantic_versioning_order(self):
        # Semantic Versioning 2.0.0's own example, then the forms that Stogas releases use.
        ordered = ["1.0.0-alpha", "1.0.0-alpha.1", "1.0.0-alpha.beta", "1.0.0-beta", "1.0.0-beta.2", "1.0.0-beta.11", "1.0.0-rc.1", "1.0.0"]
        self.assertEqual(sorted(reversed(ordered), key=channels.precedence), ordered)
        ordered = ["0.1.0-alpha.1", "0.1.0-alpha.2", "0.1.0-alpha.10", "0.1.0-rc.1", "0.1.0", "0.1.1", "0.10.0", "1.0.0-0", "1.0.0"]
        self.assertEqual(sorted(reversed(ordered), key=channels.precedence), ordered)
        for version in ("01.0.0", "1.0", "1.0.0-01", "1.0.0-", "1.0.0+build", "v1.0.0"):
            with self.assertRaises(ValueError):
                channels.precedence(version)

    def test_channels_offer_the_newest_full_release_or_preview(self):
        self.assertIsNone(channels.offered([]))
        previews = [release("v0.1.0-alpha.1"), release("v0.1.0-alpha.10"), release("v0.1.0-alpha.2"), release("v0.1.0-rc.1", draft=True)]
        self.assertEqual(channels.offered(previews), "0.1.0-alpha.10")
        # Once a full release exists, a newer preview does not replace it.
        full = [*previews, release("v0.1.0"), release("v0.2.0-alpha.1")]
        self.assertEqual(channels.offered(full), "0.1.0")
        # Other tags, such as the Go module's, are not SDK releases.
        self.assertEqual(channels.offered([*full, release("go/v9.0.0"), release("v9"), release("v1.0.0", draft=True)]), "0.1.0")

    def test_aur_versions_sort_previews_first(self):
        self.assertEqual(channels.aur_version("0.1.0-alpha.1"), "0.1.0_alpha.1")
        self.assertEqual(channels.aur_version("0.1.0"), "0.1.0")


class ManifestTests(unittest.TestCase):
    def test_homebrew_formula_names_each_archive_by_digest(self):
        value = manifest()
        formula = channels.formula(value)
        for platform in ("darwin-amd64", "darwin-arm64", "linux-amd64", "linux-arm64"):
            name = f"stogas-v{VERSION}-{platform}.tar.gz"
            self.assertIn(f'url "https://github.com/StogasAI/stogas/releases/download/v{VERSION}/{name}"', formula)
            self.assertIn(f'sha256 "{hashlib.sha256(platform.encode()).hexdigest()}"', formula)
        self.assertIn(f'version "{VERSION}"', formula)
        self.assertLessEqual(len(channels.DESCRIPTION), 80)
        self.assertFalse(channels.DESCRIPTION.endswith("."))
        self.assertNotRegex(channels.DESCRIPTION, r"^(A|An|The|Stogas)\b")
        with self.assertRaisesRegex(ValueError, "darwin-arm64"):
            channels.formula(manifest(platforms=[p for p in PLATFORMS if p != "darwin-arm64"]))

    def test_scoop_manifest(self):
        value = json.loads(channels.scoop(manifest()))
        self.assertEqual(value["version"], VERSION)
        self.assertEqual(value["bin"], "stogas.exe")
        for key, platform in (("64bit", "windows-amd64"), ("arm64", "windows-arm64")):
            self.assertEqual(value["architecture"][key], {
                "url": f"https://github.com/StogasAI/stogas/releases/download/v{VERSION}/stogas-v{VERSION}-{platform}.zip",
                "hash": hashlib.sha256(platform.encode()).hexdigest(),
                "extract_dir": f"stogas-v{VERSION}-{platform}",
            })

    def test_aur_package_and_its_metadata_agree(self):
        value = manifest()
        pkgbuild = channels.pkgbuild(value)
        srcinfo = channels.srcinfo(value)
        self.assertIn("pkgver=0.1.0_alpha.1\npkgrel=1\n", pkgbuild)
        self.assertIn("\tpkgver = 0.1.0_alpha.1\n\tpkgrel = 1\n", srcinfo)
        for arch, platform in (("x86_64", "linux-amd64"), ("aarch64", "linux-arm64")):
            url = f"https://github.com/StogasAI/stogas/releases/download/v{VERSION}/stogas-v{VERSION}-{platform}.tar.gz"
            sha256 = hashlib.sha256(platform.encode()).hexdigest()
            self.assertIn(f"source_{arch}=('{url}')\nsha256sums_{arch}=('{sha256}')\n", pkgbuild)
            self.assertIn(f"\tsource_{arch} = {url}\n\tsha256sums_{arch} = {sha256}\n", srcinfo)
        self.assertTrue(srcinfo.endswith("\npkgname = stogas-bin\n"))

    def test_pkgrel_changes_only_with_the_package(self):
        value = manifest()
        self.assertEqual(channels.pkgrel(None, value), 1)
        self.assertEqual(channels.pkgrel(channels.srcinfo(value, 1), value), 1)
        self.assertEqual(channels.pkgrel(channels.srcinfo(value, 3), value), 3)
        changed = channels.srcinfo(value, 3).replace("pkgdesc = ", "pkgdesc = Old ")
        self.assertEqual(channels.pkgrel(changed, value), 4)
        self.assertEqual(channels.pkgrel(channels.srcinfo(manifest("0.0.9"), 5), value), 1)


class ImageTests(unittest.TestCase):
    def build(self):
        return channels.image(manifest(), {"amd64": b"amd64 cli", "arm64": b"arm64 cli"}, b"license")

    def test_image_is_the_same_every_time(self):
        first, second = self.build(), self.build()
        self.assertEqual(first, second)
        self.assertNotEqual(
            first["index"],
            channels.image(manifest(), {"amd64": b"other cli", "arm64": b"arm64 cli"}, b"license")["index"],
        )

    def test_index_names_both_platforms_and_the_release(self):
        built = self.build()
        index = json.loads(built["index"])
        self.assertEqual(index["mediaType"], channels.OCI_INDEX)
        self.assertEqual(index["annotations"]["org.opencontainers.image.version"], VERSION)
        self.assertEqual(index["annotations"]["org.opencontainers.image.revision"], "a" * 40)
        self.assertEqual(index["annotations"]["org.opencontainers.image.source"], "https://github.com/StogasAI/stogas")
        self.assertEqual(index["annotations"]["org.opencontainers.image.created"], "2026-11-03T00:00:00Z")
        platforms = [item["platform"] for item in index["manifests"]]
        self.assertEqual(platforms, [{"architecture": "amd64", "os": "linux"}, {"architecture": "arm64", "os": "linux", "variant": "v8"}])
        for item, cli in zip(index["manifests"], (b"amd64 cli", b"arm64 cli")):
            data = built["manifests"][item["digest"]]
            self.assertEqual(item["digest"], "sha256:" + hashlib.sha256(data).hexdigest())
            self.assertEqual(item["size"], len(data))
            image = json.loads(data)
            config = json.loads(built["blobs"][image["config"]["digest"]])
            self.assertEqual(config["config"]["Entrypoint"], ["/usr/local/bin/stogas"])
            self.assertEqual(config["config"]["User"], "65532:65532")
            [layer] = image["layers"]
            compressed = built["blobs"][layer["digest"]]
            self.assertEqual(layer["size"], len(compressed))
            tar = gzip.decompress(compressed)
            self.assertEqual(config["rootfs"]["diff_ids"], ["sha256:" + hashlib.sha256(tar).hexdigest()])
            with tarfile.open(fileobj=io.BytesIO(tar)) as archive:
                entries = {entry.name: entry for entry in archive}
                self.assertEqual(archive.extractfile("usr/local/bin/stogas").read(), cli)
                self.assertEqual(archive.extractfile("usr/local/share/doc/stogas/LICENSE").read(), b"license")
            self.assertEqual(entries["usr/local/bin/stogas"].mode, 0o755)
            self.assertEqual(entries["tmp"].mode, 0o1777)
            self.assertTrue(all(entry.mtime == 1793664000 and entry.uid == 0 for entry in entries.values()))


class FakeRegistry:
    """The OCI distribution API's upload and read paths, for one repository."""
    def __init__(self, public=True):
        self.blobs, self.manifests, self.public, self.uploads = {}, {}, public, 0

    def __call__(self, request, timeout=None):
        url = urllib.parse.urlsplit(request.full_url)
        method = request.get_method()
        authorization = request.get_header("Authorization") or ""
        def respond(status=200, body=b"", headers=None):
            if status >= 400:
                raise urllib.error.HTTPError(request.full_url, status, "error", headers or {}, io.BytesIO(body))
            response = mock.MagicMock()
            response.status, response.headers = status, headers or {}
            response.read.return_value = body
            response.__enter__.return_value = response
            return response
        if url.path == "/token":
            scope = urllib.parse.parse_qs(url.query)["scope"][0]
            self.last_scope = scope
            token = "push" if authorization.startswith("Basic ") else "anonymous"
            return respond(body=json.dumps({"token": token}).encode())
        if authorization == "Bearer anonymous" and not self.public:
            return respond(401)
        prefix = "/v2/stogasai/stogas"
        self.assert_path(url.path.startswith(prefix))
        path = url.path[len(prefix):]
        if path.startswith("/blobs/uploads/"):
            if method == "POST":
                self.uploads += 1
                return respond(202, headers={"Location": f"{prefix}/blobs/uploads/{self.uploads}?state=x"})
            blob_digest = urllib.parse.parse_qs(url.query)["digest"][0]
            if "sha256:" + hashlib.sha256(request.data).hexdigest() != blob_digest:
                return respond(400)
            self.blobs[blob_digest] = request.data
            return respond(201)
        if path.startswith("/blobs/"):
            return respond(200) if path[len("/blobs/"):] in self.blobs else respond(404)
        reference = path[len("/manifests/"):]
        if method == "PUT":
            self.manifests[reference] = (request.get_header("Content-type"), request.data)
            return respond(201)
        if reference not in self.manifests:
            return respond(404)
        return respond(body=self.manifests[reference][1])

    def assert_path(self, condition):
        if not condition:
            raise AssertionError("unexpected registry path")


class PublisherTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.work = Path(temporary.name)
        self.packages = self.work / "packages"
        self.packages.mkdir()
        value = manifest()
        for architecture in ("amd64", "arm64"):
            name = f"stogas-v{VERSION}-linux-musl-{architecture}"
            root = self.work / "inputs" / architecture
            root.mkdir(parents=True)
            (root / "stogas").write_bytes(f"{architecture} cli".encode())
            (root / "stogas").chmod(0o755)
            (root / "LICENSE").write_bytes(b"license")
            tar_gz(self.packages / f"{name}.tar.gz", root, value["source"]["epoch"], name)
        (self.packages / "release-manifest.json").write_text(json.dumps(value))
        self.releases = [release(f"v{VERSION}")]
        patcher = mock.patch.object(publish, "releases", lambda: self.releases)
        patcher.start()
        self.addCleanup(patcher.stop)

    def bare(self, name):
        remote = self.work / name
        subprocess.run(["git", "init", "--quiet", "--bare", str(remote)], check=True)
        return str(remote)

    def show(self, remote, branch, path):
        return subprocess.run(["git", "--git-dir", remote, "show", f"{branch}:{path}"], check=True, stdout=subprocess.PIPE).stdout.decode()

    def count(self, remote, branch):
        return int(subprocess.run(["git", "--git-dir", remote, "rev-list", "--count", branch], check=True, stdout=subprocess.PIPE).stdout)

    def quiet(self):
        return contextlib.redirect_stdout(io.StringIO())

    def test_tap_commits_once_and_skips_older_releases(self):
        remote = self.bare("tap.git")
        with self.quiet():
            publish.tap(self.packages, VERSION, remote)
            publish.tap(self.packages, VERSION, remote)
        self.assertEqual(self.show(remote, "main", "Formula/stogas.rb"), channels.formula(manifest()))
        self.assertEqual(json.loads(self.show(remote, "main", "bucket/stogas.json"))["version"], VERSION)
        self.assertEqual(self.count(remote, "main"), 1)
        self.releases.append(release("v0.1.0-alpha.2"))
        with self.quiet() as output:
            publish.tap(self.packages, VERSION, remote)
        self.assertIn("keeps offering 0.1.0-alpha.2 rather than 0.1.0-alpha.1", output.getvalue())
        self.assertEqual(self.count(remote, "main"), 1)

    def test_aur_starts_a_new_package_and_raises_pkgrel_on_change(self):
        remote = self.bare("aur.git")
        with self.quiet():
            publish.aur(self.packages, VERSION, remote)
            publish.aur(self.packages, VERSION, remote)
        self.assertEqual(self.show(remote, "master", ".SRCINFO"), channels.srcinfo(manifest(), 1))
        self.assertEqual(self.count(remote, "master"), 1)
        with mock.patch.object(channels, "DESCRIPTION", "Another description"), self.quiet():
            publish.aur(self.packages, VERSION, remote)
            self.assertEqual(self.show(remote, "master", ".SRCINFO"), channels.srcinfo(manifest(), 2))
        self.assertIn("pkgrel=2\n", self.show(remote, "master", "PKGBUILD"))

    def test_channels_wait_for_their_keys(self):
        with mock.patch.dict(os.environ, {"AUR_SSH_KEY": "", "TAP_DEPLOY_KEY": ""}), self.quiet() as output:
            publish.aur(self.packages, VERSION)
            publish.tap(self.packages, VERSION)
        self.assertIn("AUR_SSH_KEY is not set", output.getvalue())
        self.assertIn("TAP_DEPLOY_KEY is not set", output.getvalue())

    def test_container_pushes_reads_back_and_keeps_versions_immutable(self):
        registry = FakeRegistry(public=False)
        outputs = self.work / "outputs"
        with mock.patch.dict(os.environ, {"GH_TOKEN": "token"}), mock.patch("urllib.request.urlopen", registry), self.quiet() as output:
            publish.container(self.packages, VERSION, output=outputs)
            publish.container(self.packages, VERSION, output=outputs)
        built = channels.image(manifest(), {"amd64": b"amd64 cli", "arm64": b"arm64 cli"}, b"license")
        index_digest = "sha256:" + hashlib.sha256(built["index"]).hexdigest()
        self.assertEqual(registry.manifests[VERSION], (channels.OCI_INDEX, built["index"]))
        # A preview never becomes latest.
        self.assertNotIn("latest", registry.manifests)
        self.assertEqual(set(registry.blobs), set(built["blobs"]))
        self.assertEqual(outputs.read_text(), f"digest={index_digest}\n" * 2)
        self.assertIn("is private", output.getvalue())
        registry.manifests[VERSION] = (channels.OCI_INDEX, b"{}")
        with mock.patch.dict(os.environ, {"GH_TOKEN": "token"}), mock.patch("urllib.request.urlopen", registry), self.quiet():
            with self.assertRaisesRegex(ValueError, "different image"):
                publish.container(self.packages, VERSION)

    def test_a_full_release_becomes_latest_while_newest(self):
        value = json.loads((self.packages / "release-manifest.json").read_text())
        for architecture in ("amd64", "arm64"):
            old = self.packages / f"stogas-v{VERSION}-linux-musl-{architecture}.tar.gz"
            name = f"stogas-v0.1.0-linux-musl-{architecture}"
            root = self.work / "full" / architecture
            root.mkdir(parents=True)
            (root / "stogas").write_bytes(f"{architecture} cli".encode())
            (root / "LICENSE").write_bytes(b"license")
            tar_gz(self.packages / f"{name}.tar.gz", root, value["source"]["epoch"], name)
            old.unlink()
        value["version"] = "0.1.0"
        (self.packages / "release-manifest.json").write_text(json.dumps(value))
        self.releases[:] = [release("v0.1.0")]
        registry = FakeRegistry()
        with mock.patch.dict(os.environ, {"GH_TOKEN": "token"}), mock.patch("urllib.request.urlopen", registry), self.quiet() as output:
            publish.container(self.packages, "0.1.0")
        self.assertEqual(registry.manifests["latest"], registry.manifests["0.1.0"])
        self.assertNotIn("is private", output.getvalue())
        self.releases.append(release("v0.2.0"))
        del registry.manifests["latest"]
        with mock.patch.dict(os.environ, {"GH_TOKEN": "token"}), mock.patch("urllib.request.urlopen", registry), self.quiet():
            publish.container(self.packages, "0.1.0")
        self.assertNotIn("latest", registry.manifests)


if __name__ == "__main__":
    unittest.main()

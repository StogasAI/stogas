#!/usr/bin/env python3
"""Publish approved bytes with ecosystem tools, then verify registry readback."""

import argparse
import base64
import hashlib
import json
import os
import shutil
import struct
import subprocess
import sys
import tarfile
import tempfile
import time
import tomllib
import urllib.error
import urllib.parse
import urllib.request
import zipfile
from pathlib import Path

sys.dont_write_bytecode = True
from artifacts import digest, source_digest, unpack


def run(arguments, stderr=subprocess.STDOUT, **kwargs):
    # Registry clients may include response bodies in errors. Keep their output
    # private; tokens are supplied through the client's documented environment.
    result = subprocess.run(arguments, stdout=subprocess.PIPE, stderr=stderr, **kwargs)
    if result.returncode:
        raise RuntimeError(f"{Path(arguments[0]).name} failed (exit {result.returncode}); registry publication stopped")
    return result.stdout


def download(url):
    request = urllib.request.Request(url, headers={"User-Agent": "stogas-sdk-release/1 (https://github.com/StogasAI/stogas)"})
    try:
        with urllib.request.urlopen(request, timeout=60) as response:
            value = response.read(2 * 1024**3 + 1)
            if len(value) > 2 * 1024**3:
                raise ValueError("Registry artifact exceeds its size limit")
            return value
    except urllib.error.HTTPError as error:
        if error.code == 404:
            return None
        raise RuntimeError(f"Registry read failed (HTTP {error.code})") from None


def exact_remote(path, url):
    value = download(url)
    if value is None:
        return False
    if hashlib.sha256(value).hexdigest() != digest(path):
        raise ValueError(f"Registry already contains different bytes: {path.name}")
    return True


def wait_for(check):
    for attempt in range(30):
        if check():
            return
        if attempt != 29:
            time.sleep(10)
    raise RuntimeError("Published package did not become available for verified readback")


def crate_metadata(path):
    """The Cargo registry upload schema, derived from Cargo's normalized manifest."""
    with tarfile.open(path) as archive:
        prefix = path.name.removesuffix(".crate")
        config = tomllib.loads(archive.extractfile(f"{prefix}/Cargo.toml").read().decode())
        package = config["package"]
        if prefix != f"{package['name']}-{package['version']}":
            raise ValueError("Crate filename and manifest disagree")
        dependencies = []
        def add(table, target=None):
            for section, kind in (("dependencies", "normal"), ("dev-dependencies", "dev"), ("build-dependencies", "build")):
                for alias, spec in table.get(section, {}).items():
                    if isinstance(spec, str):
                        spec = {"version": spec}
                    if any(key in spec for key in ("git", "path", "registry")) or spec.get("registry-index") not in (None, "https://github.com/rust-lang/crates.io-index"):
                        raise ValueError("Release crates require normalized crates.io dependencies")
                    dependencies.append({
                        "name": spec.get("package", alias), "version_req": spec["version"],
                        "features": spec.get("features", []), "optional": spec.get("optional", False),
                        "default_features": spec.get("default-features", True), "target": target,
                        "kind": kind, "registry": None,
                        "explicit_name_in_toml": alias if "package" in spec else None,
                    })
        add(config)
        for target, table in config.get("target", {}).items():
            add(table, target)
        readme = package.get("readme")
        return {
            "name": package["name"], "vers": package["version"], "deps": dependencies,
            "features": config.get("features", {}), "authors": package.get("authors", []),
            **{key: package.get(key) for key in ("description", "documentation", "homepage", "license", "repository", "links")},
            "readme": archive.extractfile(f"{prefix}/{readme}").read().decode() if readme else None,
            "readme_file": readme, "license_file": package.get("license-file"),
            "keywords": package.get("keywords", []), "categories": package.get("categories", []),
            "badges": config.get("badges", {}), "rust_version": package.get("rust-version"),
        }


CRATES = ("stogas-sigstore", "stogas-core", "stogas", "stogas-cli")
# publish.yml in the release environment, the only workflow a registry may trust.
PUBLISHER = {"repository_owner": "StogasAI", "repository_name": "stogas", "workflow_filename": "publish.yml", "environment": "release"}


# Never forward an authorization header to a redirect target.
class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, *args, **kwargs):
        return None


def crates_api(method, path, token, body=None, content_type="application/json"):
    data = body if body is None or isinstance(body, bytes) else json.dumps(body).encode()
    request = urllib.request.Request(f"https://crates.io/api/v1/{path}", data=data, method=method, headers={
        "Authorization": token, "Content-Type": content_type, "Accept": "application/json",
        "User-Agent": "stogas-sdk-release/1 (https://github.com/StogasAI/stogas)",
    })
    try:
        with urllib.request.build_opener(NoRedirect).open(request, timeout=120) as response:
            return json.loads(response.read(1024 * 1024) or b"null")
    except urllib.error.HTTPError as error:
        raise RuntimeError(f"crates.io {method} {path.split('?')[0]} failed (HTTP {error.code})") from None


def crate_upload(path, metadata, token):
    encoded = json.dumps(metadata, separators=(",", ":")).encode()
    archive = path.read_bytes()
    body = struct.pack("<I", len(encoded)) + encoded + struct.pack("<I", len(archive)) + archive
    result = crates_api("PUT", "crates/new", token, body, "application/octet-stream")
    if result.get("errors") or any(result.get("warnings", {}).values()):
        raise RuntimeError("crates.io returned errors or publication warnings; inspect the registry before continuing")


def crates_trust(token):
    """After the first upload, let only publish.yml publish each crate and revoke the token.
    The token needs the publish-new and trusted-publishing scopes."""
    for name in CRATES:
        configs = crates_api("GET", f"trusted_publishing/github_configs?crate={name}", token)["github_configs"]
        if not any(all(config.get(key) == value for key, value in PUBLISHER.items()) for config in configs):
            crates_api("POST", "trusted_publishing/github_configs", token, {"github_config": {"crate": name, **PUBLISHER}})
        crates_api("PATCH", f"crates/{name}", token, {"crate": {"trustpub_only": True}})
    crates_api("DELETE", "tokens/current", token)
    print("crates: publish.yml is each crate's only publisher, and the one-time token is revoked")


def crates(packages, version, trust=False):
    for name in CRATES:
        path = packages / f"{name}-{version}.crate"
        url = f"https://static.crates.io/crates/{name}/{path.name}"
        check = lambda: exact_remote(path, url)
        if not check():
            crate_upload(path, crate_metadata(path), os.environ["CARGO_REGISTRY_TOKEN"])
        wait_for(check)
        # A downloadable dependency also needs to be visible in the index before
        # crates.io accepts the next dependent package.
        index = f"https://index.crates.io/{name[:2]}/{name[2:4]}/{name}"
        def indexed():
            data = download(index)
            if data is None:
                return False
            for line in data.splitlines():
                entry = json.loads(line)
                if entry["vers"] == version:
                    if entry["cksum"] != digest(path) or entry["yanked"]:
                        raise ValueError("Crate index differs from the approved release")
                    return True
            return False
        wait_for(indexed)
    if trust:
        crates_trust(os.environ["CARGO_REGISTRY_TOKEN"])


def npm(packages, version, stage=False):
    """With `stage`, upload each archive for a maintainer to approve with two-factor
    authentication instead of publishing it. A token can create a package only this way once
    npm stops tokens that bypass two-factor authentication from publishing."""
    for name, filename in (("@stogas/sigstore", "stogas-sigstore"), ("stogas", "stogas")):
        path = packages / f"{filename}-{version}.tgz"
        def check():
            data = download(f"https://registry.npmjs.org/{urllib.parse.quote(name, safe='')}/{version}")
            if data is None:
                return False
            metadata = json.loads(data)
            if metadata["name"] != name or metadata["version"] != version:
                raise ValueError("npm package identity differs from the approved release")
            return exact_remote(path, metadata["dist"]["tarball"])
        if check():
            continue
        if not stage:
            run(["npm", "publish", str(path), "--access", "public"])
            wait_for(check)
            continue
        # A rerun finds the upload that still awaits approval.
        if not (staged := npm_staged(name, version)):
            run(["npm", "stage", "publish", str(path), "--access", "public"])
            staged = npm_staged(name, version)
        if not staged:
            raise RuntimeError(f"npm lists no staged {name}@{version}")
        for stage_id in staged:
            with tempfile.TemporaryDirectory(prefix="stogas-npm-") as temporary:
                run(["npm", "stage", "download", stage_id], cwd=temporary)
                if [digest(file) for file in Path(temporary).iterdir()] != [digest(path)]:
                    raise ValueError(f"npm staged different bytes as {name}@{version}; reject stage {stage_id}")
        print(f"npm: {name}@{version} awaits approval on npmjs.com under Staged Packages")


def npm_staged(name, version):
    # npm writes notices to standard error, which would corrupt the JSON.
    items = json.loads(run(["npm", "stage", "list", "--json"], stderr=subprocess.DEVNULL))
    return [item["id"] for item in items if item["packageName"] == name and item["version"] == version]


def pypi(packages, version):
    # Upload uses PyPI's maintained trusted-publishing action. This command is
    # the mandatory subsequent check of every wheel, including retry skips.
    expected = {path.name: path for path in packages.glob("*.whl")}
    def check():
        data = download(f"https://pypi.org/pypi/stogas/{version}/json")
        if data is None:
            return False
        files = {item["filename"]: item for item in json.loads(data)["urls"]}
        if files.keys() - expected.keys():
            raise ValueError("PyPI contains unapproved files for this release version")
        if not expected.keys() <= files.keys():
            return False
        for name, path in expected.items():
            if files[name]["digests"]["sha256"] != digest(path):
                raise ValueError("PyPI wheel differs from the approved release")
            if not exact_remote(path, files[name]["url"]):
                return False
        return True
    wait_for(check)


def ruby(packages, version):
    for path in sorted(packages.glob("*.gem")):
        url = f"https://rubygems.org/downloads/{path.name}"
        check = lambda: exact_remote(path, url)
        if not check():
            run(["gem", "push", str(path), "--host", "https://rubygems.org"])
        wait_for(check)


def nuget(packages, version):
    path = packages / f"Stogas.{version}.nupkg"
    url = f"https://api.nuget.org/v3-flatcontainer/stogas/{version}/stogas.{version}.nupkg"
    def check():
        data = download(url)
        if data is None:
            return False
        with tempfile.TemporaryDirectory(prefix="stogas-nuget-") as temporary:
            remote = Path(temporary) / path.name
            remote.write_bytes(data)
            # NuGet adds a repository signature. Verify it and require every
            # original ZIP entry to remain byte-for-byte identical.
            run(["dotnet", "nuget", "verify", str(remote), "--all"])
            with zipfile.ZipFile(path) as before, zipfile.ZipFile(remote) as after:
                names = after.namelist()
                if len(names) != len(set(names)) or set(names) != {*before.namelist(), ".signature.p7s"}:
                    raise ValueError("NuGet changed the package inventory")
                if any(before.read(name) != after.read(name) for name in before.namelist()):
                    raise ValueError("NuGet changed approved package contents")
        return True
    if not check():
        run(["dotnet", "nuget", "push", str(path), "--api-key", os.environ["NUGET_API_KEY"], "--source", "https://api.nuget.org/v3/index.json"])
    wait_for(check)


def maven(packages, version):
    artifacts = [path for path in packages.iterdir() if path.suffix in {".pom", ".jar", ".aar", ".module"}]
    def url(path):
        name = "stogas-android" if path.name.startswith("stogas-android-") else "stogas"
        return f"https://repo.maven.apache.org/maven2/ai/stogas/{name}/{version}/{path.name}"
    existing = [exact_remote(path, url(path)) for path in artifacts]
    if any(existing) and not all(existing):
        raise ValueError("Maven Central has a partial release; resolve the existing deployment before retrying")
    if not all(existing):
        with tempfile.TemporaryDirectory(prefix="stogas-central-") as temporary:
            work = Path(temporary)
            configuration = Path(__file__).with_name("jreleaser.yml").read_text()
            (work / "jreleaser.yml").write_text(configuration.replace("release-staging/maven", str(work / "release-staging/maven")))
            for path in artifacts:
                name = "stogas-android" if path.name.startswith("stogas-android-") else "stogas"
                destination = work / "release-staging/maven/ai/stogas" / name / version / path.name
                destination.parent.mkdir(parents=True, exist_ok=True)
                shutil.copyfile(path, destination)
            run(["jreleaser", "deploy", "--config-file", str(work / "jreleaser.yml"), "--basedir", str(Path(__file__).resolve().parents[1]), "--output-directory", str(work / "output")], env={**os.environ, "JRELEASER_PROJECT_VERSION": version})
    wait_for(lambda: all(exact_remote(path, url(path)) for path in artifacts))


def go(packages, version, source):
    tag = f"go/v{version}"
    repository = "https://github.com/StogasAI/stogas.git"
    with tempfile.TemporaryDirectory(prefix="stogas-go-") as temporary:
        work = Path(temporary)
        unpack(packages / f"stogas-go-v{version}.tar.gz", work / "approved")
        run(["git", "clone", "--quiet", "--no-checkout", repository, str(work / "repo")])
        repo = work / "repo"
        approved = work / "approved/go"
        def compare():
            if source_digest(repo / "go") != source_digest(approved):
                raise ValueError("Go release tag differs from the approved module")
        found = run(["git", "tag", "--list", tag], cwd=repo).strip()
        if found:
            run(["git", "checkout", "--quiet", "--detach", tag], cwd=repo)
            compare()
            return
        run(["git", "checkout", "--quiet", "--detach", source["commit"]], cwd=repo)
        shutil.rmtree(repo / "go")
        shutil.copytree(approved, repo / "go")
        for path in approved.rglob("*"):
            if path.is_file() and path.stat().st_size > 100 * 1024**2:
                raise ValueError("Go archive exceeds GitHub's per-file limit")
        run(["git", "add", "--force", "go"], cwd=repo)
        environment = {**os.environ, "GIT_AUTHOR_NAME": "Stogas Release", "GIT_COMMITTER_NAME": "Stogas Release", "GIT_AUTHOR_EMAIL": "release@stogas.ai", "GIT_COMMITTER_EMAIL": "release@stogas.ai", "GIT_AUTHOR_DATE": f"@{source['epoch']} +0000", "GIT_COMMITTER_DATE": f"@{source['epoch']} +0000"}
        run(["git", "commit", "--quiet", "-m", f"Publish approved Go SDK {version}"], cwd=repo, env=environment)
        run(["git", "tag", tag], cwd=repo)
        credential = base64.b64encode(("x-access-token:" + os.environ["GH_TOKEN"]).encode()).decode()
        environment.update({"GIT_CONFIG_COUNT": "1", "GIT_CONFIG_KEY_0": "http.https://github.com/.extraheader", "GIT_CONFIG_VALUE_0": "AUTHORIZATION: basic " + credential})
        run(["git", "push", "origin", f"refs/tags/{tag}"], cwd=repo, env=environment)
        # Fetch into a new reference and check the module that GitHub serves.
        run(["git", "fetch", "origin", f"refs/tags/{tag}:refs/remotes/approved-go"], cwd=repo)
        run(["git", "checkout", "--quiet", "--detach", "refs/remotes/approved-go"], cwd=repo)
        compare()


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("ecosystem", choices=["crates", "npm", "pypi", "ruby", "nuget", "maven", "go"])
    parser.add_argument("packages", type=Path)
    parser.add_argument("--stage", action="store_true", help="npm only: leave each new version for a maintainer to approve")
    parser.add_argument("--trust", action="store_true", help="crates only: then trust publish.yml alone and revoke the one-time token")
    args = parser.parse_args()
    if args.stage and args.ecosystem != "npm":
        parser.error("only npm stages packages")
    if args.trust and args.ecosystem != "crates":
        parser.error("only crates hand over to trusted publishing here")
    packages = args.packages.resolve()
    manifest = json.loads((packages / "release-manifest.json").read_text())
    if args.ecosystem == "go":
        go(packages, manifest["version"], manifest["source"])
    elif args.ecosystem == "npm":
        npm(packages, manifest["version"], args.stage)
    elif args.ecosystem == "crates":
        crates(packages, manifest["version"], args.trust)
    else:
        globals()[args.ecosystem](packages, manifest["version"])
    if not args.stage:
        print(f"{args.ecosystem}: published artifacts match the approved release")

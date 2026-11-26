#!/usr/bin/env python3
"""Publish approved bytes with ecosystem tools, then verify registry readback."""

import argparse
import base64
import contextlib
import getpass
import hashlib
import http.client
import json
import os
import pty
import re
import shlex
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
from artifacts import REPOSITORY, digest, source_digest, unpack
import channels
from gate import CRATES, check_release, crate_refusals

# The tagged checkout that this script runs from.
SOURCE = Path(__file__).resolve().parents[1]


def run(arguments, stderr=subprocess.STDOUT, **kwargs):
    """A tool's output. On failure, its last lines go to standard error, since they name the
    registry's reason. Tools take credentials from their environment and never print them;
    GitHub masks every secret in the log, and the release tool redacts its own token."""
    result = subprocess.run(arguments, stdout=subprocess.PIPE, stderr=stderr, **kwargs)
    if result.returncode:
        output = (result.stdout or b"").decode(errors="replace").splitlines()
        sys.stderr.write("".join(f"{line}\n" for line in output[-60:]))
        codes = re.findall(r"^npm error code ([A-Z0-9_]+)$", "\n".join(output), re.M)
        cause = f", npm error code {codes[0]}" if codes else ""
        raise RuntimeError(
            f"{Path(arguments[0]).name} failed (exit {result.returncode}{cause}); registry publication stopped"
        )
    return result.stdout


# static.crates.io and rubygems.org/downloads answer 403, not 404, for a file they do not hold.
STORAGE_ABSENT = (403, 404)


class TransientRead(RuntimeError):
    """A registry read that may succeed when repeated: a lost connection, HTTP 429 or a 5xx."""


def download(url, absent=(404,)):
    """The registry's bytes at `url`, or None when it answers one of the `absent` statuses."""
    request = urllib.request.Request(
        url, headers={"User-Agent": "stogas-sdk-release/1 (https://github.com/StogasAI/stogas)"}
    )
    where = urllib.parse.urlsplit(url)._replace(query="").geturl()
    try:
        with urllib.request.urlopen(request, timeout=60) as response:
            value = response.read(2 * 1024**3 + 1)
    except urllib.error.HTTPError as error:
        error.close()
        if error.code in absent:
            return None
        failure = TransientRead if error.code == 429 or error.code >= 500 else RuntimeError
        raise failure(f"Registry read of {where} failed (HTTP {error.code})") from None
    except (
        urllib.error.URLError,
        TimeoutError,
        ConnectionError,
        http.client.HTTPException,
    ) as error:
        raise TransientRead(f"Registry read of {where} failed ({type(error).__name__})") from None
    if len(value) > 2 * 1024**3:
        raise ValueError(f"Registry artifact at {where} exceeds its size limit")
    return value


def exact_remote(path, url, absent=(404,)):
    value = download(url, absent)
    if value is None:
        return False
    if hashlib.sha256(value).hexdigest() != digest(path):
        raise ValueError(f"Registry already contains different bytes: {path.name}")
    return True


def wait_for(check, what, minutes=5):
    """Reads `what` back until it matches, for at most `minutes`. A read that may succeed when
    repeated only delays it; any other failure, such as different bytes, stops at once."""
    deadline = time.monotonic() + minutes * 60
    while True:
        try:
            if check():
                return
            failed = None
        except TransientRead as error:
            failed = error
        if time.monotonic() >= deadline:
            cause = f"; the last read failed: {failed}" if failed else ""
            raise RuntimeError(
                f"{what} did not become available for verified readback within {minutes} minutes{cause}"
            )
        time.sleep(10)


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
            for section, kind in (
                ("dependencies", "normal"),
                ("dev-dependencies", "dev"),
                ("build-dependencies", "build"),
            ):
                for alias, spec in table.get(section, {}).items():
                    if isinstance(spec, str):
                        spec = {"version": spec}
                    if any(key in spec for key in ("git", "path", "registry")) or spec.get(
                        "registry-index"
                    ) not in (None, "https://github.com/rust-lang/crates.io-index"):
                        raise ValueError("Release crates require normalized crates.io dependencies")
                    dependencies.append(
                        {
                            "name": spec.get("package", alias),
                            "version_req": spec["version"],
                            "features": spec.get("features", []),
                            "optional": spec.get("optional", False),
                            "default_features": spec.get("default-features", True),
                            "target": target,
                            "kind": kind,
                            "registry": None,
                            "explicit_name_in_toml": alias if "package" in spec else None,
                        }
                    )

        add(config)
        for target, table in config.get("target", {}).items():
            add(table, target)
        readme = package.get("readme")
        return {
            "name": package["name"],
            "vers": package["version"],
            "deps": dependencies,
            "features": config.get("features", {}),
            "authors": package.get("authors", []),
            **{
                key: package.get(key)
                for key in (
                    "description",
                    "documentation",
                    "homepage",
                    "license",
                    "repository",
                    "links",
                )
            },
            "readme": archive.extractfile(f"{prefix}/{readme}").read().decode() if readme else None,
            "readme_file": readme,
            "license_file": package.get("license-file"),
            "keywords": package.get("keywords", []),
            "categories": package.get("categories", []),
            "badges": config.get("badges", {}),
            "rust_version": package.get("rust-version"),
        }


# publish.yml in the release environment, the only workflow a registry may trust.
PUBLISHER = {
    "repository_owner": "StogasAI",
    "repository_name": "stogas",
    "workflow_filename": "publish.yml",
    "environment": "release",
}


# Never forward an authorization header to a redirect target.
class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, *args, **kwargs):
        return None


def crates_api(method, path, token, body=None, content_type="application/json"):
    data = body if body is None or isinstance(body, bytes) else json.dumps(body).encode()
    request = urllib.request.Request(
        f"https://crates.io/api/v1/{path}",
        data=data,
        method=method,
        headers={
            "Authorization": token,
            "Content-Type": content_type,
            "Accept": "application/json",
            "User-Agent": "stogas-sdk-release/1 (https://github.com/StogasAI/stogas)",
        },
    )
    try:
        with urllib.request.build_opener(NoRedirect).open(request, timeout=120) as response:
            return json.loads(response.read(1024 * 1024) or b"null")
    except urllib.error.HTTPError as error:
        # crates.io explains a refusal in its errors' details, which never repeat the request.
        try:
            details = "; ".join(
                item["detail"] for item in json.loads(error.read(64 * 1024))["errors"]
            )
        except (ValueError, KeyError, TypeError):
            details = ""
        cause = f": {details}" if details else ""
        raise RuntimeError(
            f"crates.io {method} {path.split('?')[0]} failed (HTTP {error.code}){cause}"
        ) from None


def crate_upload(path, metadata, token):
    encoded = json.dumps(metadata, separators=(",", ":")).encode()
    archive = path.read_bytes()
    body = struct.pack("<I", len(encoded)) + encoded + struct.pack("<I", len(archive)) + archive
    result = crates_api("PUT", "crates/new", token, body, "application/octet-stream")
    if result.get("errors") or any(result.get("warnings", {}).values()):
        raise RuntimeError(
            "crates.io returned errors or publication warnings; inspect the registry before continuing"
        )


def crate_handed_over(name):
    """Whether crates.io has the crate and lets only its trusted publishers publish it, which it
    shows publicly."""
    document = download(f"https://crates.io/api/v1/crates/{name}")
    return document is not None and json.loads(document)["crate"].get("trustpub_only") is True


def crates_trust(token):
    """Let only publish.yml publish each crate. The token needs the trusted-publishing scope."""
    for name in CRATES:
        configs = crates_api("GET", f"trusted_publishing/github_configs?crate={name}", token)[
            "github_configs"
        ]
        if not any(
            all(config.get(key) == value for key, value in PUBLISHER.items()) for config in configs
        ):
            crates_api(
                "POST",
                "trusted_publishing/github_configs",
                token,
                {"github_config": {"crate": name, **PUBLISHER}},
            )
        crates_api("PATCH", f"crates/{name}", token, {"crate": {"trustpub_only": True}})


def crates(packages, version, token):
    """Upload each crate in dependency order."""
    paths = [packages / f"{name}-{version}.crate" for name in CRATES]
    metadata = {path: crate_metadata(path) for path in paths}
    # A refusal after the first crate would leave the rest unpublished at this version.
    for path, upload in metadata.items():
        if refusals := crate_refusals(upload):
            raise ValueError(f"crates.io would refuse {path.name}: {', '.join(refusals)}")
    for name, path in zip(CRATES, paths):
        url = f"https://static.crates.io/crates/{name}/{path.name}"
        check = lambda: exact_remote(path, url, STORAGE_ABSENT)
        if not check():
            crate_upload(path, metadata[path], token)
        wait_for(check, path.name)
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

        wait_for(indexed, f"{name} {version} in the crates.io index")


NPM_PACKAGES = (
    ("@stogas/sev-snp", "stogas-sev-snp"),
    ("@stogas/sigstore", "stogas-sigstore"),
    ("stogas", "stogas"),
)


def npm_document(name):
    """npm's document for a package, or None while npm has no such package."""
    data = download(f"https://registry.npmjs.org/{urllib.parse.quote(name, safe='')}")
    return None if data is None else json.loads(data)


def npm_tag(version):
    """The dist-tag for a new version. `latest` follows what the other package managers offer once
    this version is public: the newest full release, or before the first one, the newest preview.
    Another preview goes to `next`, and an older line's release to `maintenance`, so neither moves
    `latest`. npm requires a pre-release to name its tag."""
    if channels.offered([*releases(), {"tag_name": f"v{version}", "draft": False}]) == version:
        return "latest"
    return "next" if channels.preview(version) else "maintenance"


def npm_served(name, path, version):
    data = download(f"https://registry.npmjs.org/{urllib.parse.quote(name, safe='')}/{version}")
    if data is None:
        return False
    metadata = json.loads(data)
    if metadata["name"] != name or metadata["version"] != version:
        raise ValueError("npm package identity differs from the approved release")
    return exact_remote(path, metadata["dist"]["tarball"])


def npm(packages, version):
    """Publish each archive with trusted publishing, which adds provenance."""
    tag = ["--tag", npm_tag(version)]
    for name, filename in NPM_PACKAGES:
        path = packages / f"{filename}-{version}.tgz"
        if not npm_served(name, path, version):
            run(["npm", "publish", str(path), "--access", "public", *tag])
        wait_for(lambda: npm_served(name, path, version), f"{name}@{version}")


def pypi(packages, version):
    # Upload uses PyPI's maintained trusted-publishing action. This command is
    # the mandatory subsequent check of every wheel, including retry skips.
    expected = {path.name: path for path in packages.glob("*.whl")}
    # Wheels carry the normalized Python version, such as 0.1.0a1 for 0.1.0-alpha.1.
    versions = {name.split("-")[1] for name in expected}
    if len(versions) != 1:
        raise ValueError("Approved wheels name different versions")
    python_version = versions.pop()

    def check():
        data = download(f"https://pypi.org/pypi/stogas/{python_version}/json")
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

    wait_for(check, f"stogas {python_version} on PyPI")


def gem_push(path, bundle, key):
    """Push a gem with GitHub's build proof, as `gem push --attestation` does from RubyGems 3.6
    on; the runner's RubyGems is 3.4. RubyGems.org accepts the proof only when this workflow made
    it for these exact bytes, and shows it on the version's page."""
    boundary = os.urandom(16).hex()
    body = b"".join(
        [
            f'--{boundary}\r\nContent-Disposition: form-data; name="gem"; filename="{path.name}"\r\n'
            "Content-Type: application/octet-stream\r\n\r\n".encode(),
            path.read_bytes(),
            f'\r\n--{boundary}\r\nContent-Disposition: form-data; name="attestations"\r\n\r\n'
            f"{json.dumps([bundle])}\r\n--{boundary}--\r\n".encode(),
        ]
    )
    request = urllib.request.Request(
        "https://rubygems.org/api/v1/gems",
        data=body,
        method="POST",
        headers={
            "Authorization": key,
            "Content-Type": f"multipart/form-data; boundary={boundary}",
            "User-Agent": "stogas-sdk-release/1 (https://github.com/StogasAI/stogas)",
        },
    )
    try:
        with urllib.request.build_opener(NoRedirect).open(request, timeout=300) as response:
            response.read(64 * 1024)
    except urllib.error.HTTPError as error:
        # RubyGems.org explains a refusal in plain text, which never repeats the key.
        reason = error.read(4096).decode(errors="replace").strip()
        raise RuntimeError(
            f"RubyGems.org refused {path.name} (HTTP {error.code}): {reason}"
        ) from None


def ruby(packages, attestation):
    """Push each platform gem with the build proof in `attestation`, a Sigstore bundle whose
    subjects are every gem."""
    bundle = json.loads(attestation.read_text())
    key = os.environ["GEM_HOST_API_KEY"]
    for path in sorted(packages.glob("*.gem")):
        url = f"https://rubygems.org/downloads/{path.name}"
        check = lambda: exact_remote(path, url, STORAGE_ABSENT)
        if not check():
            gem_push(path, bundle, key)
        wait_for(check, path.name)


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
                if len(names) != len(set(names)) or set(names) != {
                    *before.namelist(),
                    ".signature.p7s",
                }:
                    raise ValueError("NuGet changed the package inventory")
                if any(before.read(name) != after.read(name) for name in before.namelist()):
                    raise ValueError("NuGet changed approved package contents")
        return True

    # nuget.org validates and indexes a version before serving it, usually within 15 minutes;
    # its support takes over after an hour. The first version took longer than 5. A rerun in
    # the meantime finds the version taken, which only readback can check.
    if not check():
        run(
            [
                "dotnet",
                "nuget",
                "push",
                str(path),
                "--api-key",
                os.environ["NUGET_API_KEY"],
                "--source",
                "https://api.nuget.org/v3/index.json",
                "--skip-duplicate",
            ]
        )
    wait_for(check, path.name, minutes=60)


def maven(packages, version):
    artifacts = sorted(
        path for path in packages.iterdir() if path.suffix in {".pom", ".jar", ".aar", ".module"}
    )

    def url(path):
        name = "stogas-android" if path.name.startswith("stogas-android-") else "stogas"
        return f"https://repo.maven.apache.org/maven2/ai/stogas/{name}/{version}/{path.name}"

    # Central checks a Sigstore signature beside each file's PGP signature. This workflow makes it
    # with its GitHub identity at the release tag, in the log that Sigstore's signing config names.
    def verify(path, bundle):
        run(
            [
                "cosign",
                "verify-blob",
                "--bundle",
                str(bundle),
                "--certificate-identity",
                f"{REPOSITORY}/.github/workflows/publish.yml@refs/tags/v{version}",
                "--certificate-oidc-issuer",
                "https://token.actions.githubusercontent.com",
                str(path),
            ]
        )

    # Central publishes a deployment whole, but repo.maven.apache.org serves its files as they
    # sync, so any file there means the deployment exists and readback waits for the rest.
    if not any([exact_remote(path, url(path)) for path in artifacts]):
        with tempfile.TemporaryDirectory(prefix="stogas-central-") as temporary:
            work = Path(temporary)
            configuration = Path(__file__).with_name("jreleaser.yml").read_text()
            (work / "jreleaser.yml").write_text(
                configuration.replace("release-staging/maven", str(work / "release-staging/maven"))
            )
            for path in artifacts:
                name = "stogas-android" if path.name.startswith("stogas-android-") else "stogas"
                destination = work / "release-staging/maven/ai/stogas" / name / version / path.name
                destination.parent.mkdir(parents=True, exist_ok=True)
                shutil.copyfile(path, destination)
                run(
                    [
                        "cosign",
                        "sign-blob",
                        "--yes",
                        "--bundle",
                        f"{destination}.sigstore.json",
                        str(destination),
                    ]
                )
                verify(path, f"{destination}.sigstore.json")
            run(
                [
                    "jreleaser",
                    "deploy",
                    "--config-file",
                    str(work / "jreleaser.yml"),
                    "--basedir",
                    str(SOURCE),
                    "--output-directory",
                    str(work / "output"),
                ],
                env={**os.environ, "JRELEASER_PROJECT_VERSION": version},
            )
    pending = set(artifacts)

    def served():
        for path in sorted(pending):
            bundle = exact_remote(path, url(path)) and download(f"{url(path)}.sigstore.json")
            if bundle:
                with tempfile.TemporaryDirectory(prefix="stogas-central-") as temporary:
                    (Path(temporary) / "bundle").write_bytes(bundle)
                    verify(path, Path(temporary) / "bundle")
                pending.remove(path)
        return not pending

    wait_for(served, f"ai.stogas {version} on Maven Central", minutes=30)


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
        environment = {
            **os.environ,
            **release_author(),
            "GIT_AUTHOR_DATE": f"@{source['epoch']} +0000",
            "GIT_COMMITTER_DATE": f"@{source['epoch']} +0000",
        }
        run(
            ["git", "commit", "--quiet", "-m", f"Publish approved Go SDK {version}"],
            cwd=repo,
            env=environment,
        )
        run(["git", "tag", tag], cwd=repo)
        credential = base64.b64encode(
            ("x-access-token:" + os.environ["GH_TOKEN"]).encode()
        ).decode()
        environment.update(
            {
                "GIT_CONFIG_COUNT": "1",
                "GIT_CONFIG_KEY_0": "http.https://github.com/.extraheader",
                "GIT_CONFIG_VALUE_0": "AUTHORIZATION: basic " + credential,
            }
        )
        run(["git", "push", "origin", f"refs/tags/{tag}"], cwd=repo, env=environment)
        # Fetch into a new reference and check the module that GitHub serves.
        run(["git", "fetch", "origin", f"refs/tags/{tag}:refs/remotes/approved-go"], cwd=repo)
        run(["git", "checkout", "--quiet", "--detach", "refs/remotes/approved-go"], cwd=repo)
        compare()


# GitHub publishes its host keys at https://api.github.com/meta, and the AUR lists its keys'
# fingerprints on https://aur.archlinux.org; this one's is SHA256:RFzBCUItH9LZS0cKB5UE6ceAYhBD5C8GeOBip8Z11+4.
GITHUB_HOST_KEY = (
    "github.com ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIOMqqnkVzrm0SdG6UOoqKLsabgH5C9okWi0dh2l9GKJl"
)
AUR_HOST_KEY = "aur.archlinux.org ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIEuBKrPzbawxA/k2g6NcyV5jmqwJ2s+zpgZGZ7tpLIcN"
TAP = "git@github.com:StogasAI/homebrew-tap.git"
AUR = "ssh://aur@aur.archlinux.org/stogas-bin.git"


def release_author():
    """The commits that a release makes in the tap, the AUR and the Go module's tag carry the
    GitHub identity of the person who started it, so those repositories list no other author. A
    manual run outside Actions commits as Git's own configuration does."""
    actor, actor_id = os.environ.get("GITHUB_ACTOR"), os.environ.get("GITHUB_ACTOR_ID")
    if not (actor and actor_id):
        return {}
    email = f"{actor_id}+{actor}@users.noreply.github.com"
    return {
        "GIT_AUTHOR_NAME": actor,
        "GIT_COMMITTER_NAME": actor,
        "GIT_AUTHOR_EMAIL": email,
        "GIT_COMMITTER_EMAIL": email,
    }


def releases():
    """Every GitHub release of the SDK, drafts included; channels.offered leaves those out."""
    pages = json.loads(
        run(
            ["gh", "api", "--paginate", "--slurp", "repos/StogasAI/stogas/releases?per_page=100"],
            stderr=subprocess.DEVNULL,
        )
    )
    return [release for page in pages for release in page]


def offered_now(version, channel):
    """Package managers follow the newest full release, or the newest preview before the first, so
    a rerun for an older release leaves them alone."""
    newest = channels.offered(releases())
    if newest != version:
        print(f"{channel}: keeps offering {newest} rather than {version}")
        return False
    return True


@contextlib.contextmanager
def checkout(remote, branch, key_variable, host_key):
    """`branch` of `remote`, or a new branch when the repository has none, such as a new AUR
    package's. Git pushes with the SSH key in `key_variable` and trusts only `host_key`; without
    the variable, it uses the ambient credentials, for a manual run."""
    with tempfile.TemporaryDirectory(prefix="stogas-channel-") as temporary:
        work = Path(temporary)
        environment = {**os.environ, **release_author()}
        if os.environ.get(key_variable):
            key = work / "key"
            key.write_text(os.environ[key_variable].strip() + "\n")
            key.chmod(0o600)
            known = work / "known_hosts"
            known.write_text(host_key + "\n")
            environment["GIT_SSH_COMMAND"] = shlex.join(
                [
                    "ssh",
                    "-F",
                    "/dev/null",
                    "-i",
                    str(key),
                    "-o",
                    "IdentitiesOnly=yes",
                    "-o",
                    f"UserKnownHostsFile={known}",
                    "-o",
                    "StrictHostKeyChecking=yes",
                    "-o",
                    "HostKeyAlgorithms=ssh-ed25519",
                ]
            )
        repo = work / "repo"
        clone = subprocess.run(
            ["git", "clone", "--quiet", "--no-checkout", remote, str(repo)],
            env=environment,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.PIPE,
            text=True,
        )
        if clone.returncode:
            if "Permission denied (publickey)" in clone.stderr:
                raise PermissionError(f"The remote refused the key in {key_variable}")
            raise RuntimeError(f"git clone failed (exit {clone.returncode}); nothing was published")
        if (
            subprocess.run(
                ["git", "rev-parse", "--verify", "--quiet", f"refs/remotes/origin/{branch}"],
                cwd=repo,
                stdout=subprocess.DEVNULL,
            ).returncode
            == 0
        ):
            run(
                ["git", "checkout", "--quiet", "-B", branch, f"refs/remotes/origin/{branch}"],
                cwd=repo,
            )
        else:
            run(["git", "symbolic-ref", "HEAD", f"refs/heads/{branch}"], cwd=repo)
        yield repo, environment


def commit_files(repo, environment, branch, files, message):
    """Commit `files` unless the branch already holds them, push, and read them back from the
    remote. Returns whether anything changed."""

    def held(reference):
        found = {}
        for path in files:
            result = subprocess.run(
                ["git", "show", f"{reference}:{path}"],
                cwd=repo,
                stdout=subprocess.PIPE,
                stderr=subprocess.DEVNULL,
            )
            found[path] = result.stdout.decode() if result.returncode == 0 else None
        return found

    if held("HEAD") == files:
        return False
    for path, content in files.items():
        (repo / path).parent.mkdir(parents=True, exist_ok=True)
        (repo / path).write_text(content)
    run(["git", "add", "--", *files], cwd=repo)
    run(["git", "commit", "--quiet", "-m", message], cwd=repo, env=environment)
    run(
        ["git", "push", "--quiet", "origin", f"HEAD:refs/heads/{branch}"], cwd=repo, env=environment
    )
    run(
        ["git", "fetch", "--quiet", "origin", f"+refs/heads/{branch}:refs/remotes/published"],
        cwd=repo,
        env=environment,
    )
    if held("refs/remotes/published") != files:
        raise ValueError(f"{branch} of the channel repository differs from what was pushed")
    return True


def tap(packages, version, remote=TAP):
    """The Homebrew formula and the Scoop manifest, in StogasAI/homebrew-tap, which this workflow
    reaches with that repository's deploy key."""
    if not os.environ.get("TAP_DEPLOY_KEY") and remote == TAP:
        print(
            "::warning::TAP_DEPLOY_KEY is not set, so Homebrew and Scoop wait for the tap's deploy key"
        )
        return
    if not offered_now(version, "Homebrew and Scoop"):
        return
    manifest = json.loads((packages / "release-manifest.json").read_text())
    files = {
        "Formula/stogas.rb": channels.formula(manifest),
        "bucket/stogas.json": channels.scoop(manifest),
    }
    with checkout(remote, "main", "TAP_DEPLOY_KEY", GITHUB_HOST_KEY) as (repo, environment):
        changed = commit_files(repo, environment, "main", files, f"Install stogas {version}")
    print(f"Homebrew and Scoop: {'now offer' if changed else 'already offer'} {version}")


def aur(packages, version, remote=AUR):
    """The stogas-bin package in the Arch User Repository, which AUR_SSH_KEY's account maintains."""
    if not os.environ.get("AUR_SSH_KEY") and remote == AUR:
        print("::warning::AUR_SSH_KEY is not set, so the AUR package waits")
        return
    if not offered_now(version, "AUR"):
        return
    manifest = json.loads((packages / "release-manifest.json").read_text())
    try:
        with checkout(remote, "master", "AUR_SSH_KEY", AUR_HOST_KEY) as (repo, environment):
            current = (repo / ".SRCINFO").read_text() if (repo / ".SRCINFO").is_file() else None
            release = channels.pkgrel(current, manifest)
            files = {
                "PKGBUILD": channels.pkgbuild(manifest, release),
                ".SRCINFO": channels.srcinfo(manifest, release),
            }
            changed = commit_files(repo, environment, "master", files, f"Install stogas {version}")
    except PermissionError:
        # The AUR knows a key only once its account adds it.
        print(
            "::warning::The AUR refused AUR_SSH_KEY, so the AUR package waits for an account that holds its public key"
        )
        return
    print(f"AUR: stogas-bin {'now offers' if changed else 'already offers'} {version}")


class Registry:
    """The OCI distribution API of one repository, with a bearer token for `scope`."""

    def __init__(self, image, scope, password=None):
        host, self.name = image.split("/", 1)
        self.base = f"https://{host}/v2/{self.name}"
        query = urllib.parse.urlencode(
            {"service": host, "scope": f"repository:{self.name}:{scope}"}
        )
        headers = {"User-Agent": "stogas-sdk-release/1 (https://github.com/StogasAI/stogas)"}
        if password is not None:
            user = os.environ.get("GITHUB_ACTOR", "x-access-token")
            headers["Authorization"] = (
                "Basic " + base64.b64encode(f"{user}:{password}".encode()).decode()
            )
        request = urllib.request.Request(f"https://{host}/token?{query}", headers=headers)
        try:
            with urllib.request.urlopen(request, timeout=60) as response:
                self.token = json.loads(response.read())["token"]
        except urllib.error.HTTPError as error:
            error.close()
            raise PermissionError(f"The registry refused a token (HTTP {error.code})") from None

    def request(self, method, path, data=None, headers=None, missing_ok=False):
        url = path if path.startswith("https://") else self.base + path
        request = urllib.request.Request(
            url,
            data=data,
            method=method,
            headers={
                "Authorization": f"Bearer {self.token}",
                "User-Agent": "stogas-sdk-release/1 (https://github.com/StogasAI/stogas)",
                **(headers or {}),
            },
        )
        try:
            with urllib.request.urlopen(request, timeout=300) as response:
                return response.status, dict(response.headers), response.read()
        except urllib.error.HTTPError as error:
            error.close()
            if missing_ok and error.code == 404:
                return 404, dict(error.headers), b""
            raise RuntimeError(f"Registry {method} failed (HTTP {error.code})") from None

    def put_blob(self, blob_digest, data):
        if self.request("HEAD", f"/blobs/{blob_digest}", missing_ok=True)[0] == 200:
            return
        _, headers, _ = self.request("POST", "/blobs/uploads/", data=b"")
        location = urllib.parse.urljoin(self.base, headers["Location"])
        separator = "&" if "?" in location else "?"
        self.request(
            "PUT",
            f"{location}{separator}digest={urllib.parse.quote(blob_digest)}",
            data=data,
            headers={"Content-Type": "application/octet-stream"},
        )

    def put_manifest(self, reference, data, media_type):
        self.request(
            "PUT", f"/manifests/{reference}", data=data, headers={"Content-Type": media_type}
        )

    def manifest(self, reference, media_type):
        status, _, data = self.request(
            "GET", f"/manifests/{reference}", headers={"Accept": media_type}, missing_ok=True
        )
        return data if status == 200 else None


def container(packages, version, image=channels.IMAGE, output=None):
    """The release's container image in GitHub's container registry, byte for byte as the release
    holds it, tagged with the version, and `latest` while package managers offer it. Writes
    `digest=` for its build proof."""
    built = channels.read_oci_archive((packages / channels.container_archive(version)).read_bytes())
    index_digest = "sha256:" + hashlib.sha256(built["index"]).hexdigest()
    registry = Registry(image, "pull,push", os.environ["GH_TOKEN"])
    tags = [version]
    if channels.offered(releases()) == version:
        tags.append("latest")
    for tag in tags:
        existing = registry.manifest(tag, channels.OCI_INDEX)
        if existing is not None and existing != built["index"] and tag == version:
            raise ValueError(f"{image}:{tag} already names a different image")
    for blob_digest, data in built["blobs"].items():
        registry.put_blob(blob_digest, data)
    for manifest_digest, data in built["manifests"].items():
        registry.put_manifest(manifest_digest, data, channels.OCI_MANIFEST)
    for tag in tags:
        registry.put_manifest(tag, built["index"], channels.OCI_INDEX)
    # Read back what the registry serves under each tag, and every manifest the index names.
    for tag in tags:
        if registry.manifest(tag, channels.OCI_INDEX) != built["index"]:
            raise ValueError(f"{image}:{tag} differs from the built image")
    for manifest_digest, data in built["manifests"].items():
        if registry.manifest(manifest_digest, channels.OCI_MANIFEST) != data:
            raise ValueError(f"{image}@{manifest_digest} differs from the built image")
    for blob_digest in built["blobs"]:
        if registry.request("HEAD", f"/blobs/{blob_digest}", missing_ok=True)[0] != 200:
            raise ValueError(f"{image} lacks the blob {blob_digest}")
    if output:
        with open(output, "a") as lines:
            lines.write(f"digest={index_digest}\n")
    # GitHub creates a new package as private, and only its settings page makes it public.
    try:
        public = Registry(image, "pull").manifest(version, channels.OCI_INDEX) == built["index"]
    except (PermissionError, RuntimeError):
        public = False
    if not public:
        print(f"::warning::{image} is private; make it public in the package's settings on GitHub")
    print(f"Container: {image}:{version} is {index_digest} ({', '.join(tags)})")


def preview(packages):
    """A preview has no Stogas signature. Require the gate's preview, every file the manifest
    names and nothing else, and GitHub's build proof for the manifest and the qualification
    report, which together name every artifact. GitLab rebuilds every full release and a preview
    only on request, so a preview that holds GitLab's proof must also pass it for the manifest,
    which names its digest only when GitLab's rebuild made the same bytes. gh attestation verify
    accepts only github.com certificates, so cosign checks it."""
    manifest, is_preview = check_release(packages)
    if not is_preview:
        raise ValueError("Only a preview is published without the Stogas signature")
    reference = f"refs/tags/v{manifest['version']}"
    for name in ("release-manifest.json", "qualification.json"):
        run(
            [
                "gh",
                "attestation",
                "verify",
                str(packages / name),
                "--repo",
                "StogasAI/stogas",
                "--bundle",
                str(packages / "github-attestation.jsonl"),
                "--cert-identity",
                f"https://github.com/StogasAI/stogas/.github/workflows/release.yml@{reference}",
                "--cert-oidc-issuer",
                "https://token.actions.githubusercontent.com",
                "--predicate-type",
                "https://slsa.dev/provenance/v1",
                "--source-ref",
                reference,
                "--source-digest",
                manifest["source"]["commit"],
                "--deny-self-hosted-runners",
            ]
        )
    bundle = packages / "gitlab-attestation.jsonl"
    if bundle.exists():
        run(
            [
                "cosign",
                "verify-blob-attestation",
                str(packages / "release-manifest.json"),
                "--bundle",
                str(bundle),
                "--type",
                "https://slsa.dev/provenance/v1",
                "--certificate-oidc-issuer",
                "https://gitlab.com",
                "--certificate-identity",
                f"https://gitlab.com/stogasai/stogas//.gitlab-ci.yml@{reference}",
            ]
        )
    builders = "GitHub's and GitLab's build proofs" if bundle.exists() else "GitHub's build proof"
    print(f"Preview {manifest['version']}: the gate and {builders} cover every file")


def first_versions():
    """Print which registries still wait for the owner, as GitHub output lines: crates.io until
    every crate trusts only publish.yml, npm until it has every package, and RubyGems until it has
    the gem."""
    waiting = {
        "crates": not all(crate_handed_over(name) for name in CRATES),
        "npm": any(npm_document(name) is None for name, _ in NPM_PACKAGES),
        "ruby": download("https://rubygems.org/api/v1/gems/stogas.json") is None,
    }
    for registry, value in waiting.items():
        print(f"{registry}={'true' if value else 'false'}")


def terminal(arguments):
    """Run a tool on the owner's terminal, where npm can ask for two-factor authentication, and
    return what it printed."""
    printed = bytearray()

    def read(descriptor):
        data = os.read(descriptor, 1024)
        printed.extend(data)
        return data

    code = os.waitstatus_to_exitcode(pty.spawn(arguments, read))
    if code:
        raise RuntimeError(f"{shlex.join(arguments[:3])} failed (exit {code})")
    return printed.decode(errors="replace")


def json_objects(text):
    """Each JSON object in a tool's output, such as npm's one per trust configuration."""
    decoder, found, start = json.JSONDecoder(), [], text.find("{")
    while start >= 0:
        try:
            value, end = decoder.raw_decode(text, start)
            found.append(value)
        except ValueError:
            end = start + 1
        start = text.find("{", end)
    return found


def crates_owner(packages, version, token):
    """Upload this version of every crate with the owner's token, or one pasted here, then make
    publish.yml each crate's only publisher. A new crate can depend on this version of the others,
    so the token publishes them too."""
    if all(crate_handed_over(name) for name in CRATES):
        return
    pasted = not token
    if pasted:
        print(
            "crates.io: create a token at https://crates.io/settings/tokens/new "
            "with the publish-new, publish-update and trusted-publishing scopes for crates stogas*."
        )
        token = getpass.getpass("Paste the token, or press Enter to skip crates.io: ").strip()
        if not token:
            raise RuntimeError("skipped")
    for name in CRATES:
        if crate_handed_over(name):
            crates_api("PATCH", f"crates/{name}", token, {"crate": {"trustpub_only": False}})
    crates(packages, version, token)
    crates_trust(token)
    print("crates.io: publish.yml is each crate's only publisher.")
    if pasted:
        # crates.io lets no scoped token revoke itself.
        print("crates.io: revoke the pasted token at https://crates.io/settings/tokens.")


def npm_trusted(document):
    """Whether a workflow has published a version with trusted publishing, which keeps npm's
    configuration for it."""
    return any(
        "trustedPublisher" in (item.get("_npmUser") or {}) for item in document["versions"].values()
    )


# npm publishes this version to hold the name of a package whose first version is staged, and its
# page calls it a temporary holding version awaiting review.
NPM_PLACEHOLDER = "0.0.0-stage"


def npm_tidy(name, document):
    """Remove npm's staging placeholder, moving `latest` off it first, and a `next` tag that
    `latest` has reached, so that npm offers what the other package managers offer."""
    releases = [version for version in document["versions"] if version != NPM_PLACEHOLDER]
    latest, upcoming = document["dist-tags"].get("latest"), document["dist-tags"].get("next")
    if NPM_PLACEHOLDER in document["versions"] and releases:
        if latest == NPM_PLACEHOLDER:
            latest = max(releases, key=channels.precedence)
            terminal(["npm", "dist-tag", "add", f"{name}@{latest}", "latest"])
        terminal(["npm", "unpublish", f"{name}@{NPM_PLACEHOLDER}"])
    if {latest, upcoming} <= set(releases) and channels.precedence(upcoming) <= channels.precedence(
        latest
    ):
        terminal(["npm", "dist-tag", "rm", name, "next"])


def npm_owner(packages, version):
    """From the owner's browser sign-in, publish each package that npm lacks and make publish.yml
    the trusted publisher of each package that no workflow has published. npm discards a trusted
    publisher that publishes nothing within 2 days, and makes provenance only in CI, so a package's
    first version carries none."""
    documents = {name: npm_document(name) for name, _ in NPM_PACKAGES}
    untrusted = [
        name
        for name, document in documents.items()
        if document is None or not npm_trusted(document)
    ]
    if not untrusted:
        return
    print(f"npm: {', '.join(untrusted)} need the owner. Sign in to npm as stogas in your browser.")
    with tempfile.TemporaryDirectory(prefix="stogas-npm-") as session:
        # npm keeps the sign-in here, never in the owner's own npmrc.
        os.environ["NPM_CONFIG_USERCONFIG"] = str(Path(session) / "npmrc")
        try:
            terminal(["npm", "login", "--auth-type=web"])
            tag = npm_tag(version)
            for name, filename in NPM_PACKAGES:
                if documents[name] is None:
                    path = packages / f"{filename}-{version}.tgz"
                    terminal(
                        [
                            "npm",
                            "publish",
                            str(path),
                            "--access",
                            "public",
                            "--tag",
                            tag,
                            "--provenance=false",
                        ]
                    )
                    wait_for(lambda: npm_served(name, path, version), f"{name}@{version}")
            for name in untrusted:
                # No workflow has published with these, and an expired one cannot be changed.
                for config in json_objects(terminal(["npm", "trust", "list", name, "--json"])):
                    terminal(["npm", "trust", "revoke", name, "--id", config["id"]])
                terminal(
                    [
                        "npm",
                        "trust",
                        "github",
                        name,
                        "--repo",
                        "StogasAI/stogas",
                        "--file",
                        "publish.yml",
                        "--env",
                        "release",
                        "--allow-publish",
                        "--yes",
                    ]
                )
                # Require two-factor authentication and disallow tokens.
                terminal(["npm", "access", "set", "mfa=publish", name])
            for name, document in documents.items():
                if document is not None:
                    # Tags and placeholders hold up no publication.
                    try:
                        npm_tidy(name, document)
                    except RuntimeError as error:
                        print(f"npm: could not tidy {name}: {error}", file=sys.stderr)
        finally:
            with contextlib.suppress(RuntimeError):
                terminal(["npm", "logout"])
            del os.environ["NPM_CONFIG_USERCONFIG"]


def ruby_owner():
    if download("https://rubygems.org/api/v1/gems/stogas.json") is not None:
        return
    # A pending trusted publisher lasts 12 hours.
    print(
        "RubyGems: sign in as stogas and add a pending trusted publisher at https://rubygems.org/profile/oidc/pending_trusted_publishers "
        "with gem name stogas, repository owner StogasAI, repository stogas, workflow publish.yml and environment release."
    )
    input("Press Enter once it exists, or to skip RubyGems. ")


def owner(packages, version):
    """The owner's part of a release that adds a package, run on the owner's terminal before
    publish.yml. crates.io and npm trust a workflow only for a package that exists, and RubyGems
    only through a pending trusted publisher, so a new package's first version needs the owner.
    A registry whose packages all trust publish.yml needs nothing, and a failure holds up only its
    own registry, which publish.yml then skips. The owner's lasting crates.io token may come in
    CARGO_REGISTRY_TOKEN, which no tool that the step runs receives."""
    cargo_token = os.environ.pop("CARGO_REGISTRY_TOKEN", None)
    waiting = []
    for registry, setup in (
        ("crates.io", lambda: crates_owner(packages, version, cargo_token)),
        ("npm", lambda: npm_owner(packages, version)),
        ("RubyGems", ruby_owner),
    ):
        try:
            setup()
        except (OSError, RuntimeError, ValueError) as error:
            print(f"{registry}: {error}", file=sys.stderr)
            waiting.append(registry)
    if waiting:
        print(
            f"{', '.join(waiting)} still wait for the owner; run this again once the cause above is fixed"
        )


if __name__ == "__main__":
    if sys.argv[1:] == ["first-versions"]:
        first_versions()
        raise SystemExit
    if sys.argv[1:] == ["offered"]:
        print(channels.offered(releases()))
        raise SystemExit
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "ecosystem",
        choices=[
            "owner",
            "crates",
            "npm",
            "pypi",
            "ruby",
            "nuget",
            "maven",
            "go",
            "preview",
            "tap",
            "aur",
            "container",
        ],
    )
    parser.add_argument("packages", type=Path)
    parser.add_argument(
        "--remote",
        help="tap and aur only: another Git remote, such as an HTTPS one for a manual run",
    )
    parser.add_argument(
        "--attestation",
        type=Path,
        help="ruby only, and required: the Sigstore bundle that proves where every gem was built",
    )
    args = parser.parse_args()
    if args.remote and args.ecosystem not in ("tap", "aur"):
        parser.error("only tap and aur take another remote")
    if (args.attestation is not None) != (args.ecosystem == "ruby"):
        parser.error("ruby, and only ruby, takes --attestation")
    packages = args.packages.resolve()
    if args.ecosystem == "preview":
        preview(packages)
        raise SystemExit
    manifest = json.loads((packages / "release-manifest.json").read_text())
    if args.ecosystem == "owner":
        owner(packages, manifest["version"])
        raise SystemExit
    if args.ecosystem == "go":
        go(packages, manifest["version"], manifest["source"])
    elif args.ecosystem == "crates":
        crates(packages, manifest["version"], os.environ["CARGO_REGISTRY_TOKEN"])
    elif args.ecosystem == "ruby":
        ruby(packages, args.attestation)
    elif args.ecosystem in ("tap", "aur"):
        globals()[args.ecosystem](
            packages, manifest["version"], *([args.remote] if args.remote else [])
        )
        raise SystemExit
    elif args.ecosystem == "container":
        container(packages, manifest["version"], output=os.environ.get("GITHUB_OUTPUT"))
        raise SystemExit
    else:
        globals()[args.ecosystem](packages, manifest["version"])
    print(f"{args.ecosystem}: published artifacts match the approved release")

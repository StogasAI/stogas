"""Require a complete, production-only release before signing or publication."""

import json
import re
import sys
from pathlib import Path

from artifacts import canonical, release_source, verify_inventory, wheel, write_json

METADATA = {"github-attestation.jsonl", "stogas-signature.json", "qualification.json"}
HEX = re.compile(r"[0-9a-f]{64}\Z")
# Offline cases test installed bytes without a network. Live cases send
# requests through production attested TLS and E2EE and verify its evidence.
CASES = ("offline", "live")
NPM_RUNTIMES = ("node", "node-minimum", "bun", "deno", "worker", "chromium", "firefox", "webkit")


def attempt(name, action):
    """Run one qualification case and return its outcome, so a failure does not hide later cases."""
    try:
        action()
    except Exception as error:
        print(f"{name} failed: {error}", file=sys.stderr, flush=True)
        return "failed"
    return "passed"


def read_document(path):
    encoded = Path(path).read_bytes()
    if len(encoded) > 2 * 1024**2:
        raise ValueError("Release metadata exceeds its size limit")
    document = json.loads(encoded)
    if canonical(document) + b"\n" != encoded:
        raise ValueError(f"Release metadata is not canonical: {Path(path).name}")
    return document


def required_checks(targets):
    checks = set()
    for platform, target in targets.items():
        # Android also runs every test on a 16 KB page-size device.
        cases = CASES + (("16k",) if target["os"] == "android" else ())
        for package in target["packages"]:
            for case in cases:
                checks.add((platform, package, case))
    for case in CASES:
        checks.add(("portable", "rust", case))
        for runtime in NPM_RUNTIMES:
            checks.add(("portable", "npm", f"{runtime}-{case}"))
    return checks


def check_qualification(report, manifest_sha256, targets):
    if set(report) != {"schema", "environment", "manifest_sha256", "checks"} or report["schema"] != "stogas.sdk-qualification.v1" or report["environment"] != "prod" or report["manifest_sha256"] != manifest_sha256:
        raise ValueError("Qualification does not identify this production artifact set")
    found = set()
    for check in report["checks"]:
        if set(check) != {"platform", "package", "case", "runtime", "outcome"} or check["outcome"] != "passed" or not isinstance(check["runtime"], str) or not check["runtime"].strip():
            raise ValueError("Every required qualification must have a recorded runtime and pass")
        identity = (check["platform"], check["package"], check["case"])
        if identity in found:
            raise ValueError("Duplicate qualification result")
        found.add(identity)
    expected = required_checks(targets)
    if found != expected:
        missing = ["/".join(check) for check in sorted(expected - found)]
        extra = ["/".join(check) for check in sorted(found - expected)]
        raise ValueError(f"Qualification is incomplete: missing={missing}, extra={extra}")


def check_release(directory, *, reports=True):
    """Validate a self-contained release directory against its recorded source."""
    directory = Path(directory)
    manifest = read_document(directory / "release-manifest.json")
    if set(manifest) != {"schema", "environment", "version", "source", "targets", "artifacts"} or manifest["schema"] != "stogas.sdk-release.v1" or manifest["environment"] != "prod":
        raise ValueError("Invalid production release manifest")
    if not isinstance(manifest["version"], str) or not re.fullmatch(r"[0-9]+\.[0-9]+\.[0-9]+(?:-[0-9A-Za-z.-]+)?", manifest["version"]):
        raise ValueError("Invalid release version")
    identity = manifest["source"]
    if set(identity) != {"commit", "sha256", "epoch", "dirty"} or identity["dirty"] is not False or not re.fullmatch(r"[0-9a-f]{40}", identity["commit"]) or not HEX.fullmatch(identity["sha256"]):
        raise ValueError("Release source must have an immutable production identity")
    if type(identity["epoch"]) is not int or not 315532800 <= identity["epoch"] <= 0xFFFFFFFF:
        raise ValueError("Invalid source timestamp")
    names = {artifact["name"] for artifact in manifest["artifacts"]}
    if names & (METADATA | {"release-manifest.json"}):
        raise ValueError("Artifact name collides with release metadata")
    for artifact in manifest["artifacts"]:
        if set(artifact) != {"name", "sha256", "size"} or not HEX.fullmatch(artifact["sha256"]) or type(artifact["size"]) is not int or not 0 < artifact["size"] <= 2 * 1024**3:
            raise ValueError("Invalid release artifact")
    present_metadata = METADATA & {path.name for path in directory.iterdir()}
    manifest_sha256 = verify_inventory(directory, manifest, present_metadata)
    with release_source(directory, manifest) as source:
        targets = json.loads((source / "release/targets.json").read_text())["targets"]
        if manifest["version"] != json.loads((source / "package.json").read_text())["version"]:
            raise ValueError("Release version differs from its source")
    if manifest["targets"] != sorted([*targets, "portable"]):
        raise ValueError("Release does not include every declared platform and portable package")
    check_artifact_families(names, targets, manifest["version"])
    if reports:
        check_qualification(read_document(directory / "qualification.json"), manifest_sha256, targets)
    return manifest


def check_artifact_families(names, targets, version):
    expected = {
        f"stogas-{version}.tgz", f"stogas-offline-sigstore-{version}.tgz",
        *[f"{crate}-{version}.crate" for crate in ("stogas", "stogas-verifier", "stogas-offline-sigstore")],
        f"stogas-go-v{version}.tar.gz", f"stogas-swift-v{version}.tar.gz",
        f"stogas-xcframework-v{version}.zip",
        f"stogas-source-v{version}.tar.gz",
        f"stogas-{version}.jar", f"stogas-{version}.pom", f"Stogas.{version}.nupkg",
        f"stogas-android-{version}.aar", f"stogas-android-{version}.pom",
        f"stogas-android-{version}.module",
        *[f"{name}-{version}-{classifier}.jar" for name in ("stogas", "stogas-android") for classifier in ("sources", "javadoc")],
    }
    for platform, target in targets.items():
        extension = "zip" if target["os"] == "windows" else "tar.gz"
        expected |= {f"stogas-v{version}-{platform}.{extension}", f"stogas-v{version}-{platform}-debug.{extension}"}
        if "ruby" in target:
            expected.add(f"stogas-{version.replace('-', '.')}-{target['ruby']}.gem")
    if expected - names:
        raise ValueError("Release package families are missing or contain unexpected artifacts")
    wheels = {wheel(names, target) for target in targets.values() if "python" in target["packages"]}
    if names - expected - wheels:
        raise ValueError("Release contains unexpected artifacts")


def combine_reports(paths, destination, manifest_sha256, targets):
    checks = []
    for path in paths:
        report = read_document(path)
        if report.get("manifest_sha256") != manifest_sha256 or report.get("environment") != "prod":
            raise ValueError("Cannot combine qualifications from different artifacts")
        checks.extend(report["checks"])
    report = {"schema": "stogas.sdk-qualification.v1", "environment": "prod", "manifest_sha256": manifest_sha256, "checks": sorted(checks, key=lambda check: (check["platform"], check["package"], check["case"]))}
    check_qualification(report, manifest_sha256, targets)
    write_json(destination, report)

"""Require a complete, production-only release before signing or publication."""

import json
import re
from pathlib import Path

from artifacts import canonical, digest, verify_inventory

METADATA = {"github-attestation.json", "release-approval.json", "qualification.json", "rebuild.json"}
HEX = re.compile(r"[0-9a-f]{64}\Z")


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
        for package in target["packages"]:
            for case in ("installed-contract", "transport-tls", "transport-e2ee"):
                checks.add((platform, package, case))
            if target.get("os") == "android" and target["arch"] in {"amd64", "arm64"}:
                checks.add((platform, package, "installed-contract-16k"))
    for case in ("installed-contract", "transport-tls", "transport-e2ee"):
        checks.add(("portable", "rust", case))
    for runtime in ("node", "node-minimum", "bun", "deno", "worker", "chromium", "firefox", "webkit"):
        checks.add(("portable", "npm", f"{runtime}-contract"))
        checks.add(("portable", "npm", f"{runtime}-e2ee"))
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


def check_release(directory, source, *, reports=True, allow_dirty=False):
    directory, source = Path(directory), Path(source)
    manifest = read_document(directory / "release-manifest.json")
    if set(manifest) != {"schema", "environment", "version", "source", "targets", "artifacts"} or manifest["schema"] != "stogas.sdk-release.v1" or manifest["environment"] != "prod":
        raise ValueError("Invalid production release manifest")
    identity = manifest["source"]
    if set(identity) != {"commit", "sha256", "epoch", "dirty"} or not isinstance(identity["dirty"], bool) or (identity["dirty"] and not allow_dirty) or not re.fullmatch(r"[0-9a-f]{40}", identity["commit"]) or not HEX.fullmatch(identity["sha256"]):
        raise ValueError("Release source must have an immutable production identity")
    if type(identity["epoch"]) is not int or not 315532800 <= identity["epoch"] <= 0xFFFFFFFF:
        raise ValueError("Invalid source timestamp")
    from release import source_digest
    if source_digest(source) != identity["sha256"]:
        raise ValueError("Release source differs from its recorded identity")
    targets = json.loads((source / "release/targets.json").read_text())["targets"]
    if manifest["targets"] != sorted([*targets, "portable"]):
        raise ValueError("Release does not include every declared platform and portable package")
    if manifest["version"] != json.loads((source / "package.json").read_text())["version"]:
        raise ValueError("Release version differs from its source")
    names = {artifact["name"] for artifact in manifest["artifacts"]}
    if names & (METADATA | {"release-manifest.json"}):
        raise ValueError("Artifact name collides with release metadata")
    for artifact in manifest["artifacts"]:
        if set(artifact) != {"name", "sha256", "size"} or not HEX.fullmatch(artifact["sha256"]) or type(artifact["size"]) is not int or not 0 < artifact["size"] <= 2 * 1024**3:
            raise ValueError("Invalid release artifact")
    present_metadata = METADATA & {path.name for path in directory.iterdir()}
    manifest_sha256 = verify_inventory(directory, manifest, present_metadata)
    check_artifact_families(names, targets, manifest["version"])
    if reports:
        check_qualification(read_document(directory / "qualification.json"), manifest_sha256, targets)
        rebuild = read_document(directory / "rebuild.json")
        if set(rebuild) != {"schema", "manifest_sha256", "source_sha256", "artifacts"} or rebuild["schema"] != "stogas.sdk-rebuild.v1" or rebuild["manifest_sha256"] != manifest_sha256 or rebuild["source_sha256"] != identity["sha256"] or rebuild["artifacts"] != manifest["artifacts"]:
            raise ValueError("Independent rebuild does not cover the complete release")
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
    wheels = names - expected
    if expected - names:
        raise ValueError("Release package families are missing or contain unexpected artifacts")
    for target in targets.values():
        if "python" not in target["packages"]:
            continue
        machine = {"amd64": "x86_64", "arm64": "aarch64"}[target["arch"]]
        if target["os"] == "linux":
            tag = f"manylinux_2_17_{machine}.manylinux2014_{machine}" if target["libc"] == "glibc" else f"musllinux_1_2_{machine}"
        elif target["os"] == "windows":
            tag = {"amd64": "win_amd64", "arm64": "win_arm64"}[target["arch"]]
        else:
            tag = f"macosx_{target['minimum'].replace('.', '_')}_{'arm64' if target['arch'] == 'arm64' else 'x86_64'}"
        matching = {name for name in wheels if re.fullmatch(r"stogas-[0-9A-Za-z.]+-cp310-abi3-" + re.escape(tag) + r"\.whl", name)}
        if len(matching) != 1:
            raise ValueError(f"Release requires exactly one wheel for {tag}")
        wheels -= matching
    if wheels:
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
    from artifacts import write_json
    write_json(destination, report)

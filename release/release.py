#!/usr/bin/env python3
"""Build and compare SDK artifacts from a fixed source snapshot."""

import argparse
import json
import os
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

sys.dont_write_bytecode = True
if sys.version_info < (3, 11):
    raise SystemExit("Release tooling requires Python 3.11 or later")

from artifacts import canonical, digest, regular_files, write_json

ROOT = Path(__file__).resolve().parents[1]
TARGETS = json.loads((ROOT / "release/targets.json").read_text())["targets"]
BUILD_TARGETS = {**TARGETS, "portable": {"os": "portable"}}


def git(*args):
    return subprocess.check_output(["git", "-C", str(ROOT), *args])


def capture(destination, allow_dirty):
    dirty = bool(git("status", "--porcelain", "--untracked-files=all").strip())
    if dirty and not allow_dirty:
        raise ValueError("Release source has uncommitted changes; use --allow-dirty for local qualification only")
    commit = git("rev-parse", "HEAD").decode().strip()
    epoch = int(git("show", "-s", "--format=%ct", "HEAD"))
    if not dirty:
        # A clean release comes from Git's immutable objects, avoiding a mixed
        # snapshot when another editor changes and restores a working-tree file.
        from artifacts import unpack
        with tempfile.TemporaryDirectory(prefix="stogas-source-") as temporary:
            archive = Path(temporary) / "source.tar.gz"
            subprocess.run(["git", "-C", str(ROOT), "archive", "--format=tar.gz", "--output", str(archive), commit], check=True)
            unpack(archive, destination)
        return {"commit": commit, "dirty": False, "epoch": epoch, "sha256": source_digest(destination)}
    destination.mkdir()
    files = []
    for name in sorted(set(git("ls-files", "--cached", "--others", "--exclude-standard", "-z").split(b"\0")) - {b""}):
        relative = os.fsdecode(name)
        source = ROOT / relative
        if source.is_symlink():
            raise ValueError(f"Release source contains a symlink: {relative}")
        if not source.exists():
            continue  # A deliberate deletion in an explicitly dirty snapshot.
        if not source.is_file():
            raise ValueError(f"Release source is not a regular file: {relative}")
        target = destination / relative
        target.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(source, target)
        mode = 0o755 if source.stat().st_mode & 0o111 else 0o644
        target.chmod(mode)
        files.append({"path": relative, "mode": mode, "sha256": digest(target)})
    # Hash the captured files, never the changing working tree after capture.
    if git("rev-parse", "HEAD").decode().strip() != commit or (not dirty and git("status", "--porcelain", "--untracked-files=all").strip()):
        raise ValueError("Release source changed while it was being captured")
    import hashlib
    return {"commit": commit, "dirty": dirty, "epoch": epoch, "sha256": hashlib.sha256(canonical(files)).hexdigest()}


def source_digest(source):
    import hashlib
    files = [{"path": path.relative_to(source).as_posix(), "mode": 0o755 if path.stat().st_mode & 0o111 else 0o644, "sha256": digest(path)} for path in regular_files(source)]
    return hashlib.sha256(canonical(files)).hexdigest()


def build(platforms, output, allow_dirty, previous=None):
    if output.exists():
        raise ValueError("Build output must be a new directory")
    if output.is_relative_to(ROOT):
        raise ValueError("Build output must be outside the source checkout")
    output.mkdir(parents=True)
    snapshot = output / "source"
    if previous:
        source = json.loads((previous / "build.json").read_text())["source"]
        if source["dirty"] and not allow_dirty:
            raise ValueError("A dirty source snapshot requires --allow-dirty")
        if source_digest(previous / "source") != source["sha256"]:
            raise ValueError("Source snapshot differs from its recorded identity")
        shutil.copytree(previous / "source", snapshot)
    else:
        source = capture(snapshot, allow_dirty)
    if source_digest(snapshot) != source["sha256"]:
        raise ValueError("Captured source differs from its recorded identity")
    build_targets = {**json.loads((snapshot / "release/targets.json").read_text())["targets"], "portable": {"os": "portable"}}
    apple = {name for name, target in build_targets.items() if target["os"] in {"macos", "ios"}}
    if "apple" in platforms:
        platforms = [name for name in platforms if name != "apple"] + sorted(apple)
    if len(set(platforms)) != len(platforms):
        raise ValueError("A platform was requested more than once")
    bundles = ["apple"] if apple <= set(platforms) else []
    write_json(output / "build.json", {
        "schema": "stogas.sdk-build-set.v1", "environment": "prod", "source": source,
        "platforms": sorted(platforms), "bundles": bundles, "compiler_recipe_sha256": digest(snapshot / "release/Dockerfile"),
    })
    try:
        images = {}
        for operating_system in sorted({build_targets[platform]["os"] for platform in platforms}):
            if operating_system in {"macos", "ios"}:
                continue
            # BuildKit writes the immutable ID directly, avoiding a mutable tag
            # race with another local build.
            identity = output / f".{operating_system}-image"
            subprocess.run(["docker", "build", "--target", operating_system, "--iidfile", str(identity), "--file", str(snapshot / "release/Dockerfile"), str(snapshot / "release")], check=True)
            images[operating_system] = identity.read_text().strip()
            identity.unlink()
        for platform in platforms:
            destination = output / platform
            destination.mkdir()
            if build_targets[platform]["os"] in {"macos", "ios"}:
                subprocess.run(["python3", "-B", str(snapshot / "release/build_native.py"), "--platform", platform, "--out", str(destination), "--epoch", str(source["epoch"])], check=True)
                continue
            subprocess.run([
                "docker", "run", "--rm", "--init", "--memory", "8g", "--cpus", "4",
                "--mount", f"type=bind,source={snapshot},target=/build/source,readonly",
                "--mount", f"type=bind,source={destination},target=/out",
                images[build_targets[platform]["os"]],
                *([] if platform == "portable" else ["--platform", platform]),
                "--out", "/out", "--epoch", str(source["epoch"]),
            ], check=True)
        if "apple" in bundles:
            subprocess.run([sys.executable, "-B", str(snapshot / "release/build_apple.py"), str(output)], check=True)
    finally:
        if source_digest(snapshot) != source["sha256"]:
            raise ValueError("Source snapshot changed during the build")


def compare(first, second):
    def files(root):
        from artifacts import regular_files
        return {path.relative_to(root).as_posix(): digest(path) for path in regular_files(root)}
    a, b = files(first), files(second)
    if a != b:
        changed = sorted(name for name in a.keys() | b.keys() if a.get(name) != b.get(name))
        raise ValueError("Independent build bytes differ: " + ", ".join(changed))
    print(f"Independent builds match: {len(a)} files")


def collect(builds, output, complete):
    if output.exists():
        raise ValueError("Collected output must be a new directory")
    metadata = [json.loads((directory / "build.json").read_text()) for directory in builds]
    first = metadata[0]
    platforms = [platform for item in metadata for platform in item["platforms"]]
    bundles = [bundle for item in metadata for bundle in item["bundles"]]
    if len(set(platforms)) != len(platforms):
        raise ValueError("A platform was built more than once")
    if len(set(bundles)) != len(bundles):
        raise ValueError("A bundle was built more than once")
    for directory, item in zip(builds, metadata):
        if item["schema"] != "stogas.sdk-build-set.v1" or item["environment"] != "prod" or item["source"] != first["source"] or item["compiler_recipe_sha256"] != first["compiler_recipe_sha256"] or source_digest(directory / "source") != first["source"]["sha256"]:
            raise ValueError("Cannot combine builds from different source or compiler recipes")
    declared = json.loads((builds[0] / "source/release/targets.json").read_text())["targets"]
    if complete and set(platforms) != {*declared, "portable"}:
        raise ValueError("Complete collection requires every declared platform and portable package")
    if complete and bundles != ["apple"]:
        raise ValueError("Complete collection requires the Xcode-built Apple bundle")
    output.mkdir(parents=True)
    shutil.copytree(builds[0] / "source", output / "source")
    for directory, item in zip(builds, metadata):
        for platform in [*item["platforms"], *item["bundles"]]:
            shutil.copytree(directory / platform, output / platform)
    write_json(output / "build.json", {**first, "platforms": sorted(platforms), "bundles": sorted(bundles)})


def compare_packages(first, second, report):
    from gate import METADATA, read_document
    from artifacts import verify_inventory
    manifests = [read_document(directory / "release-manifest.json") for directory in (first, second)]
    if first == second or manifests[0] != manifests[1]:
        raise ValueError("Independent package builds must have the same complete manifest")
    for directory, manifest in zip((first, second), manifests):
        verify_inventory(directory, manifest, METADATA & {path.name for path in directory.iterdir()})
    for artifact in manifests[0]["artifacts"]:
        if (first / artifact["name"]).samefile(second / artifact["name"]):
            raise ValueError("Compared artifacts must not share the same underlying file")
    write_json(report, {"schema": "stogas.sdk-rebuild.v1", "manifest_sha256": digest(first / "release-manifest.json"), "source_sha256": manifests[0]["source"]["sha256"], "artifacts": manifests[0]["artifacts"]})


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest="command", required=True)
    build_parser = commands.add_parser("build", help="Build production artifacts; staging packages do not exist")
    build_parser.add_argument("--platform", action="append", choices=[*BUILD_TARGETS, "apple"], required=True, help="apple builds all Apple slices and their XCFramework together")
    build_parser.add_argument("--out", type=Path, required=True)
    build_parser.add_argument("--allow-dirty", action="store_true")
    build_parser.add_argument("--snapshot", type=Path, help="Use a previously captured local build's source, with a fresh compiler process and no artifact cache")
    compare_parser = commands.add_parser("compare", help="Compare every file from independent builds")
    compare_parser.add_argument("first", type=Path)
    compare_parser.add_argument("second", type=Path)
    compare_parser.add_argument("--report", type=Path, help="Compare complete package manifests and write the independent rebuild report")
    inventory_parser = commands.add_parser("inventory", help="Verify every downloaded artifact against its manifest")
    inventory_parser.add_argument("directory", type=Path)
    collect_parser = commands.add_parser("collect", help="Combine platform builds from the same captured source")
    collect_parser.add_argument("builds", type=Path, nargs="+")
    collect_parser.add_argument("--out", type=Path, required=True)
    collect_parser.add_argument("--complete", action="store_true")
    package_parser = commands.add_parser("package", help="Assemble language packages from a captured build")
    package_parser.add_argument("build", type=Path)
    qualify_parser = commands.add_parser("qualify", help="Run installed-package checks; full release approval requires transport qualification too")
    qualify_parser.add_argument("build", type=Path)
    qualify_parser.add_argument("--platform", choices=BUILD_TARGETS, required=True)
    qualify_parser.add_argument("--out", type=Path, required=True)
    qualify_parser.add_argument("--package", action="append", default=[], help="Qualify a subset; release approval still requires every declared package")
    qualify_parser.add_argument("--device", help="Explicit Android adb serial or iOS destination UDID")
    qualify_parser.add_argument("--python", type=Path, help="Desktop Python consumer interpreter; independent of the release tooling's Python")
    gate_parser = commands.add_parser("gate", help="Require complete packages, qualification and independent rebuild")
    gate_parser.add_argument("directory", type=Path)
    gate_parser.add_argument("--source", type=Path, required=True)
    gate_parser.add_argument("--packages-only", action="store_true", help="Validate a draft's complete artifacts before post-build qualification")
    reports_parser = commands.add_parser("reports", help="Combine complete qualification reports for one artifact set")
    reports_parser.add_argument("paths", type=Path, nargs="+")
    reports_parser.add_argument("--packages", type=Path, required=True)
    reports_parser.add_argument("--source", type=Path, required=True)
    args = parser.parse_args()
    if args.command == "build":
        if len(args.platform) != len(set(args.platform)):
            parser.error("Duplicate platform")
        build(args.platform, args.out.resolve(), args.allow_dirty, args.snapshot.resolve() if args.snapshot else None)
    elif args.command == "compare":
        if args.report:
            compare_packages(args.first.resolve(), args.second.resolve(), args.report.resolve())
        else:
            compare(args.first.resolve(), args.second.resolve())
    elif args.command == "collect":
        collect([directory.resolve() for directory in args.builds], args.out.resolve(), args.complete)
    elif args.command == "inventory":
        from artifacts import verify_inventory
        from gate import METADATA, read_document
        directory = args.directory.resolve()
        verify_inventory(directory, read_document(directory / "release-manifest.json"), METADATA & {path.name for path in directory.iterdir()})
        print("Every release artifact matches its manifest")
    elif args.command == "gate":
        from gate import check_release
        check_release(args.directory.resolve(), args.source.resolve(), reports=not args.packages_only)
        print("Complete production release gate passed")
    elif args.command == "reports":
        from gate import check_release, combine_reports
        packages, source = args.packages.resolve(), args.source.resolve()
        check_release(packages, source, reports=False)
        targets = json.loads((source / "release/targets.json").read_text())["targets"]
        combine_reports(args.paths, packages / "qualification.json", digest(packages / "release-manifest.json"), targets)
    elif args.command == "qualify":
        recorded = args.build.resolve() / "source/release/release.py"
        if recorded.resolve() != Path(__file__).resolve():
            subprocess.run([sys.executable, "-B", str(recorded), "qualify", str(args.build.resolve()), "--platform", args.platform, "--out", str(args.out.resolve()), *[part for package in args.package for part in ("--package", package)], *(["--device", args.device] if args.device else []), *(["--python", str(args.python.resolve())] if args.python else [])], check=True)
        else:
            from qualify import qualify
            qualify(args.build.resolve(), args.platform, args.out.resolve(), args.package, args.device, args.python.resolve() if args.python else None)
    else:
        recorded = args.build.resolve() / "source/release/release.py"
        if recorded.resolve() != Path(__file__).resolve():
            subprocess.run(["python3", "-B", str(recorded), "package", str(args.build.resolve())], check=True)
        else:
            from package_bindings import package
            package(args.build.resolve())

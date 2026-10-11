#!/usr/bin/env python3
"""Build, package, qualify and compare SDK artifacts from a fixed source snapshot."""

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

from artifacts import digest, inventory, release_source, source_digest, tar_gz, unpack, verify_inventory, wheel, write_json
from gate import METADATA, check_release, combine_reports, read_document
from package_bindings import package

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
    epoch = int(git("show", "-s", "--format=%ct", commit))
    if not dirty:
        # A clean release comes from Git's immutable objects, avoiding a mixed
        # snapshot when another editor changes and restores a working-tree file.
        with tempfile.TemporaryDirectory(prefix="stogas-source-") as temporary:
            archive = Path(temporary) / "source.tar.gz"
            subprocess.run(["git", "-C", str(ROOT), "archive", "--format=tar.gz", "--output", str(archive), commit], check=True)
            unpack(archive, destination)
    else:
        destination.mkdir()
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
            target.chmod(0o755 if source.stat().st_mode & 0o111 else 0o644)
    return {"commit": commit, "dirty": dirty, "epoch": epoch, "sha256": source_digest(destination)}


def build(platforms, output, allow_dirty, archive=None):
    if output.exists() or (archive and (archive.exists() or archive.is_relative_to(output))):
        raise ValueError("Build output and archive must be new and separate")
    if output.is_relative_to(ROOT):
        raise ValueError("Build output must be outside the source checkout")
    output.mkdir(parents=True)
    snapshot = output / "source"
    source = capture(snapshot, allow_dirty)
    build_targets = {**json.loads((snapshot / "release/targets.json").read_text())["targets"], "portable": {"os": "portable"}}
    apple = {name for name, target in build_targets.items() if target["os"] in {"macos", "ios"}}
    platforms = [name for platform in platforms for name in (sorted(apple) if platform == "apple" else [platform])]
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
    if archive:
        # File transfers between machines drop modes; the archive keeps them.
        tar_gz(archive, output, source["epoch"])


def collect(builds, output, complete):
    if output.exists():
        raise ValueError("Collected output must be a new directory")
    output.parent.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(prefix="stogas-builds-", dir=output.parent) as temporary:
        directories = []
        for index, build in enumerate(builds):
            if build.is_file():
                unpack(build, Path(temporary) / str(index))
                build = Path(temporary) / str(index)
            directories.append(build)
        combine(directories, output, complete)


def combine(builds, output, complete):
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


def rebuild(release, output):
    """Build every platform except Apple again from HEAD and require the release's exact bytes.

    Xcode runs only on Apple hardware, so the Apple compiler outputs come from
    the release. Packaging repacks each Apple archive with the pinned packer,
    which reproduces the released bytes."""
    manifest = check_release(release, reports=False)
    if output.exists():
        raise ValueError("Rebuild output must be a new directory")
    apple = sorted(name for name, target in TARGETS.items() if target["os"] in {"macos", "ios"})
    native = output / "native"
    build(sorted(set(BUILD_TARGETS) - set(apple)), native, False)
    metadata = json.loads((native / "build.json").read_text())
    if metadata["source"] != manifest["source"]:
        raise ValueError("HEAD differs from the release source")
    imported = output / "apple"
    imported.mkdir()
    shutil.copytree(native / "source", imported / "source")
    names = [artifact["name"] for artifact in manifest["artifacts"]]
    version = manifest["version"]
    shards = {"apple": [f"stogas-xcframework-v{version}.zip"]}
    for platform in apple:
        shards[platform] = [f"stogas-v{version}-{platform}.tar.gz", f"stogas-v{version}-{platform}-debug.tar.gz"]
        if "python" in TARGETS[platform]["packages"]:
            shards[platform].append(wheel(names, TARGETS[platform]))
    for name, files in shards.items():
        (imported / name).mkdir()
        for file in files:
            shutil.copyfile(release / file, imported / name / file)
        write_json(imported / name / f"{name}.json", {"schema": "stogas.sdk-build.v1", "platform": name, "environment": "prod", "artifacts": inventory(imported / name, files)})
    write_json(imported / "build.json", {**metadata, "platforms": apple, "bundles": ["apple"]})
    collect([native, imported], output / "release", complete=True)
    subprocess.run([sys.executable, "-B", str(output / "release/source/release/release.py"), "package", str(output / "release")], check=True)
    compare(release, output / "release/packages")


def compare(first, second):
    if first == second:
        raise ValueError("Compare two different package directories")
    manifests = [read_document(directory / "release-manifest.json") for directory in (first, second)]
    if manifests[0] != manifests[1]:
        a, b = ({artifact["name"]: artifact for artifact in manifest["artifacts"]} for manifest in manifests)
        changed = sorted(name for name in a.keys() | b.keys() if a.get(name) != b.get(name))
        raise ValueError("Independent package builds differ: " + (", ".join(changed) or "source identity or targets"))
    for directory, manifest in zip((first, second), manifests):
        verify_inventory(directory, manifest, METADATA & {path.name for path in directory.iterdir()})
    for artifact in manifests[0]["artifacts"]:
        if (first / artifact["name"]).samefile(second / artifact["name"]):
            raise ValueError("Compared artifacts must not share the same underlying file")


if __name__ == "__main__":
    # Packages record file permissions, so every host creates files alike.
    os.umask(0o022)
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest="command", required=True)
    build_parser = commands.add_parser("build", help="Build production artifacts; staging packages do not exist")
    build_parser.add_argument("--platform", action="append", choices=[*BUILD_TARGETS, "apple"], required=True, help="apple builds all Apple slices and their XCFramework together")
    build_parser.add_argument("--out", type=Path, required=True)
    build_parser.add_argument("--allow-dirty", action="store_true")
    build_parser.add_argument("--archive", type=Path, help="Also write the build as one archive that keeps file modes, for collection on another machine")
    compare_parser = commands.add_parser("compare", help="Require two complete package directories to hold identical release artifacts")
    compare_parser.add_argument("first", type=Path)
    compare_parser.add_argument("second", type=Path)
    collect_parser = commands.add_parser("collect", help="Combine platform builds or build archives from the same captured source")
    collect_parser.add_argument("builds", type=Path, nargs="+")
    collect_parser.add_argument("--out", type=Path, required=True)
    collect_parser.add_argument("--complete", action="store_true")
    rebuild_parser = commands.add_parser("rebuild", help="Build every platform except Apple again from HEAD and require the release's exact packages")
    rebuild_parser.add_argument("release", type=Path)
    rebuild_parser.add_argument("--out", type=Path, required=True)
    package_parser = commands.add_parser("package", help="Assemble language packages from a captured build")
    package_parser.add_argument("build", type=Path)
    qualify_parser = commands.add_parser("qualify", help="Run the release's own offline and live tests on its installed packages")
    qualify_parser.add_argument("packages", type=Path)
    qualify_parser.add_argument("--platform", required=True)
    qualify_parser.add_argument("--out", type=Path, required=True)
    qualify_parser.add_argument("--package", action="append", default=[], help="Qualify a subset; release approval still requires every declared package")
    qualify_parser.add_argument("--device", help="Explicit Android adb serial or iOS destination UDID")
    qualify_parser.add_argument("--device-farm", help="AWS Device Farm project ARN for tests on a real phone")
    gate_parser = commands.add_parser("gate", help="Require complete packages and their qualification")
    gate_parser.add_argument("directory", type=Path)
    gate_parser.add_argument("--packages-only", action="store_true", help="Validate a draft's complete artifacts before post-build qualification")
    reports_parser = commands.add_parser("reports", help="Combine complete qualification reports for one artifact set")
    reports_parser.add_argument("paths", type=Path, nargs="+")
    reports_parser.add_argument("--packages", type=Path, required=True)
    args = parser.parse_args()
    if args.command == "build":
        build(args.platform, args.out.resolve(), args.allow_dirty, args.archive.resolve() if args.archive else None)
    elif args.command == "compare":
        compare(args.first.resolve(), args.second.resolve())
        print("Package directories contain identical release artifacts")
    elif args.command == "collect":
        collect([directory.resolve() for directory in args.builds], args.out.resolve(), args.complete)
    elif args.command == "rebuild":
        rebuild(args.release.resolve(), args.out.resolve())
        print("The rebuild reproduces every release artifact")
    elif args.command == "gate":
        check_release(args.directory.resolve(), reports=not args.packages_only)
        print("Complete production release gate passed")
    elif args.command == "reports":
        packages = args.packages.resolve()
        manifest = check_release(packages, reports=False)
        with release_source(packages, manifest) as source:
            targets = json.loads((source / "release/targets.json").read_text())["targets"]
        combine_reports(args.paths, packages / "qualification.json", digest(packages / "release-manifest.json"), targets)
    elif args.command == "qualify":
        packages = args.packages.resolve()
        with release_source(packages, read_document(packages / "release-manifest.json")) as source:
            subprocess.run([sys.executable, "-B", str(source / "release/qualify.py"), str(packages), "--platform", args.platform, "--out", str(args.out.resolve()), *[part for package in args.package for part in ("--package", package)], *(["--device", args.device] if args.device else []), *(["--device-farm", args.device_farm] if args.device_farm else [])], check=True)
    else:
        recorded = args.build.resolve() / "source/release/release.py"
        if recorded.resolve() != Path(__file__).resolve():
            subprocess.run([sys.executable, "-B", str(recorded), "package", str(args.build.resolve())], check=True)
        else:
            package(args.build.resolve())

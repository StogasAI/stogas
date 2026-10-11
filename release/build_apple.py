"""Create the Apple binary bundle with Xcode from the exact native archives."""

import argparse
import json
import os
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

from apple_metadata import normalize_xcframework
from artifacts import digest, inventory, source_digest, unpack, write_json, zip_archive


def build(directory):
    if sys.platform != "darwin" or subprocess.check_output(["xcodebuild", "-version"], text=True).strip() != "Xcode 26.3\nBuild version 17C529":
        raise ValueError("Apple bundles require macOS with Xcode 26.3 (17C529)")
    metadata = json.loads((directory / "build.json").read_text())
    source = directory / "source"
    if source_digest(source) != metadata["source"]["sha256"]:
        raise ValueError("Apple bundle source differs from the native build")
    targets = json.loads((source / "release/targets.json").read_text())["targets"]
    apple = {name: target for name, target in targets.items() if target["os"] in {"macos", "ios"}}
    if not apple.keys() <= set(metadata["platforms"]):
        raise ValueError("The Apple bundle requires every declared Apple platform")
    version = json.loads((source / "package.json").read_text())["version"]
    destination = directory / "apple"
    if destination.exists():
        raise ValueError("Apple bundle output already exists")
    with tempfile.TemporaryDirectory(prefix="stogas-xcframework-") as temporary:
        work = Path(temporary)
        headers = work / "include"
        headers.mkdir()
        shutil.copyfile(source / "include/stogas_verifier.h", headers / "stogas_verifier.h")
        (headers / "module.modulemap").write_text('module CStogas { header "stogas_verifier.h" export * }\n')
        groups = {}
        for platform, target in sorted(apple.items()):
            shard = directory / platform
            description = json.loads((shard / f"{platform}.json").read_text())
            actual = inventory(shard, [entry["name"] for entry in description["artifacts"]] + [f"{platform}.json"])
            if [entry for entry in actual if entry["name"] != f"{platform}.json"] != description["artifacts"]:
                raise ValueError("Apple native artifact changed before framework assembly")
            unpack(shard / f"stogas-v{version}-{platform}.tar.gz", work / platform)
            group = target["os"] + ("-simulator" if target.get("simulator") else "")
            groups.setdefault(group, []).append(work / platform / f"stogas-v{version}-{platform}/libstogas_verifier_ffi.a")
        arguments = ["xcodebuild", "-create-xcframework"]
        for group, libraries in sorted(groups.items()):
            library = work / group / "libstogas_verifier_ffi.a"
            library.parent.mkdir()
            # A fat library combines architectures only within one platform.
            # iOS device and simulator slices remain separate XCFramework entries.
            subprocess.run(["xcrun", "lipo", "-create", *map(str, libraries), "-output", str(library)], check=True, env={**os.environ, "ZERO_AR_DATE": "1"})
            arguments += ["-library", str(library), "-headers", str(headers)]
        framework = work / "CStogas.xcframework"
        subprocess.run([*arguments, "-output", str(framework)], check=True)
        normalize_xcframework(framework)
        destination.mkdir()
        archive = destination / f"stogas-xcframework-v{version}.zip"
        zip_archive(archive, framework, metadata["source"]["epoch"], framework.name)
        write_json(destination / "apple.json", {
            "schema": "stogas.sdk-build.v1", "platform": "apple", "environment": "prod",
            "artifacts": [{"name": archive.name, "size": archive.stat().st_size, "sha256": digest(archive)}],
        })


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("directory", type=Path)
    build(parser.parse_args().directory.resolve())

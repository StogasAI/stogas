#!/usr/bin/env python3
"""Stage one built C ABI library into the native language packages."""

import argparse
import json
import shutil
import subprocess
import tempfile
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
PLATFORMS = json.loads((ROOT / "release/targets.json").read_text())["targets"]


def copy(source, destination):
    if not source.is_file() or source.is_symlink():
        raise ValueError(f"Missing regular native artifact: {source}")
    destination.parent.mkdir(parents=True, exist_ok=True)
    shutil.copyfile(source, destination)


def stage(platform, native, bindings, version, *, apple_swift=True):
    target = PLATFORMS[platform]
    extension = "dll" if platform.startswith("windows") else "dylib" if platform.startswith("darwin") else "so"
    name = ("" if extension == "dll" else "lib") + "stogas_ffi." + extension
    if "dotnet" in target:
        copy(native / name, bindings / "dotnet/Stogas/runtimes" / target["dotnet"] / "native" / name)
    if "jna" in target:
        copy(native / name, bindings / "java/src/main/resources" / target["jna"] / name)
    if "ruby" in target:
        copy(native / name, bindings / "ruby/lib/stogas/native" / name)
    if "android_abi" in target:
        copy(native / name, bindings / "android/src/main/jniLibs" / target["android_abi"] / name)

    if "swift" in target and target["os"] in {"macos", "ios"} and apple_swift:
        # Development staging needs only the running platform. Release builds
        # assemble all Apple architectures with release/build_apple.py.
        with tempfile.TemporaryDirectory(prefix="stogas-swift-") as temporary:
            temporary = Path(temporary)
            headers = temporary / "include"
            copy(ROOT / "include/stogas.h", headers / "stogas.h")
            (headers / "module.modulemap").write_text('module CStogas { header "stogas.h" export * }\n')
            bundle = temporary / "CStogas.xcframework"
            subprocess.run(["xcodebuild", "-create-xcframework", "-library", str((native / "libstogas_ffi.a").resolve()), "-headers", str(headers), "-output", str(bundle)], check=True)
            destination = bindings / "swift/CStogas.xcframework"
            if destination.exists():
                shutil.rmtree(destination)
            shutil.copytree(bundle, destination)

    if "swift" in target and target["os"] == "linux":
        bundle = bindings / "swift/CStogas.artifactbundle"
        static = "libstogas_ffi.a"
        copy(native / static, bundle / platform / static)
        copy(Path(__file__).resolve().parents[1] / "include/stogas.h", bundle / "include/stogas.h")
        (bundle / "include/module.modulemap").write_text('module CStogas { header "stogas.h" export * }\n')
        manifest = bundle / "info.json"
        artifact = {"type": "staticLibrary", "version": version, "variants": []}
        if manifest.exists():
            artifact = json.loads(manifest.read_text())["artifacts"]["CStogas"]
            if artifact["version"] != version:
                raise ValueError("Cannot combine native libraries from different releases")
        path = f"{platform}/{static}"
        variants = [v for v in artifact["variants"] if v["path"] != path]
        variants.append({
            "path": path,
            "supportedTriples": [target["swift"]],
            "staticLibraryMetadata": {"headerPaths": ["include"], "moduleMapPath": "include/module.modulemap"},
        })
        artifact["variants"] = sorted(variants, key=lambda v: v["path"])
        manifest.write_text(json.dumps({"schemaVersion": "1.0", "artifacts": {"CStogas": artifact}}, indent=2) + "\n")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--platform", required=True, choices=PLATFORMS)
    parser.add_argument("--native-dir", required=True, type=Path)
    parser.add_argument("--bindings-dir", type=Path, default=Path(__file__).resolve().parents[1] / "bindings")
    parser.add_argument("--version", default=json.loads((Path(__file__).resolve().parents[1] / "package.json").read_text())["version"])
    arguments = parser.parse_args()
    stage(arguments.platform, arguments.native_dir, arguments.bindings_dir, arguments.version)

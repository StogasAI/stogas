#!/usr/bin/env python3
"""Build npm/WASM and verified Rust archives in the pinned portable compiler."""

import argparse
import json
import os
import shutil
import subprocess
from pathlib import Path

from artifacts import digest, function_names, tar_gz, without_names, write_json

ROOT = Path(__file__).resolve().parents[1]


def build(output, epoch):
    # npm and Cargo package need writable source trees; the recorded source mount
    # stays immutable. The fixed destination also keeps compiler paths identical.
    work = Path("/build/portable")
    shutil.copytree(ROOT, work)
    env = {key: value for key, value in os.environ.items() if not key.startswith(("CARGO_", "RUST", "PYO3_"))}
    env.update({
        "CARGO_INCREMENTAL": "0", "CARGO_BUILD_JOBS": "4",
        "CARGO_TARGET_DIR": "/build/target", "SOURCE_DATE_EPOCH": str(epoch),
        "CARGO_HOME": "/usr/local/cargo", "RUSTUP_HOME": "/usr/local/rustup", "RUSTUP_TOOLCHAIN": "1.97.1",
        "RUSTFLAGS": "--remap-path-prefix=/build/portable=/stogas", "TZ": "UTC", "LC_ALL": "C.UTF-8",
    })

    def run(*arguments):
        subprocess.run([str(argument) for argument in arguments], cwd=work, env=env, check=True)

    output.mkdir(parents=True, exist_ok=True)
    version = json.loads((work / "package.json").read_text())["version"]
    run("cargo", "build", "--locked", "--profile", "wasm", "--target", "wasm32-unknown-unknown", "-p", "stogas-wasm", "-p", "stogas-sigstore-wasm")
    # Web pages download the npm packages' WebAssembly, so it ships without function names, which
    # made it 83% larger. The debug archive holds the same modules with them, and symbol maps, as
    # the native packages keep their debug information in theirs. Removing the names afterwards
    # gives the bytes that `wasm-bindgen --remove-name-section` writes.
    debug = Path("/build/wasm-debug")
    debug.mkdir()
    for crate, destination, name in [
        ("stogas_wasm", "pkg/browser", "stogas"),
        ("stogas_sigstore_wasm", "packages/sigstore/pkg/browser", "stogas_sigstore"),
    ]:
        run("wasm-bindgen", f"/build/target/wasm32-unknown-unknown/wasm/{crate}.wasm", "--target", "web", "--out-dir", destination, "--out-name", name)
        module = work / destination / f"{name}_bg.wasm"
        named = module.read_bytes()
        (debug / module.name).write_bytes(named)
        (debug / f"{module.name}.symbols").write_bytes(function_names(named))
        module.write_bytes(without_names(named))
    shutil.copyfile(work / "LICENSE", debug / "LICENSE")
    tar_gz(output / f"stogas-v{version}-wasm32-debug.tar.gz", debug, epoch, f"stogas-v{version}-wasm32-debug")
    run("node", "scripts/package-npm.mjs", "--pack-destination", output)
    # Cargo packages interdependent workspace members together, using an isolated
    # temporary registry for verification before any real registry publication.
    run("cargo", "package", "--locked", "--registry", "crates-io", "-p", "stogas-sigstore", "-p", "stogas-core", "-p", "stogas", "-p", "stogas-cli")
    for archive in Path("/build/target/package").glob("*.crate"):
        shutil.copyfile(archive, output / archive.name)
    files = sorted(path for path in output.iterdir() if path.is_file())
    write_json(output / "portable.json", {
        "schema": "stogas.sdk-build.v1", "platform": "portable", "environment": "prod",
        "artifacts": [{"name": path.name, "size": path.stat().st_size, "sha256": digest(path)} for path in files],
    })


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--out", type=Path, required=True)
    parser.add_argument("--epoch", type=int, required=True)
    args = parser.parse_args()
    build(args.out.resolve(), args.epoch)

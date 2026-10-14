#!/usr/bin/env python3
"""Build npm/WASM and verified Rust archives in the pinned portable compiler."""

import argparse
import os
import shutil
import subprocess
from pathlib import Path

from artifacts import digest, write_json

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
    run("cargo", "build", "--locked", "--profile", "dist", "--target", "wasm32-unknown-unknown", "-p", "stogas-verifier-wasm", "-p", "stogas-offline-sigstore-wasm")
    for crate, destination, name in [
        ("stogas_verifier_wasm", "pkg/browser", "stogas_verifier"),
        ("stogas_offline_sigstore_wasm", "packages/offline-sigstore/pkg/browser", "stogas_offline_sigstore"),
    ]:
        run("wasm-bindgen", f"/build/target/wasm32-unknown-unknown/dist/{crate}.wasm", "--target", "web", "--out-dir", destination, "--out-name", name)
    run("node", "scripts/package-npm.mjs", "--pack-destination", output)
    # Cargo packages interdependent workspace members together, using an isolated
    # temporary registry for verification before any real registry publication.
    run("cargo", "package", "--locked", "--registry", "crates-io", "-p", "stogas-offline-sigstore", "-p", "stogas-verifier", "-p", "stogas", "-p", "stogas-cli")
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

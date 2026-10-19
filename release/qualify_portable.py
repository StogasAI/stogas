"""Install approved npm and Rust archives in independent consumer projects."""

import json
import os
import shutil
import subprocess
import tempfile
from pathlib import Path

from artifacts import unpack
from gate import CASES, attempt

PLAYWRIGHT = "mcr.microsoft.com/playwright:v1.62.1-noble@sha256:dcc5531e97840b9b5e794f2814476b21571c5124a3fca2267d73041f56e7580e"
RUST = "rust:1.97.1-bookworm@sha256:0e2bcaef56d041a486784e54104a81aebe0da44bd03019bd70bc0401e42e4a97"
BUN = "oven/bun:1.4.2@sha256:9114c058aeae42162ee16dd5084b95fe9473970bb6bcb5b232ab1630f0546895"
DENO = "denoland/deno:2.9.6@sha256:2014dc167ece617ef7e7ba40631ac2234c59e75ce693e7cc2dc2602b3c87859d"
NODE_MINIMUM = "node:20.20.2-bookworm-slim@sha256:2cf067cfed83d5ea958367df9f966191a942351a2df77d6f0193e162b5febfc0"


def qualify(source, packages, version, requested=()):
    selected = set(requested or ("npm", "rust"))
    if not selected <= {"npm", "rust"}:
        raise ValueError("Portable qualification supports npm and Rust")
    checks = []
    with tempfile.TemporaryDirectory(prefix="stogas-portable-consumer-") as temporary:
        work = Path(temporary)
        shutil.copytree(packages, work / "packages")
        shutil.copytree(source / "tests", work / "tests")
        # Setup steps use the network. Offline cases have none; live cases use
        # the production gateways.
        def run(image, arguments, case=None):
            subprocess.run([
                "docker", "run", "--rm", "--init", "--memory", "4g", "--cpus", "4", "--shm-size", "1g",
                "--platform", "linux/amd64", "--user", f"{os.getuid()}:{os.getgid()}",
                "--mount", f"type=bind,source={work},target=/work", "--workdir", "/work",
                "--env", "HOME=/work", "--env", "CARGO_HOME=/work/.cargo", "--env", "CARGO_BUILD_JOBS=4",
                *(["--network", "none"] if case == "offline" else []), *(["--env", "STOGAS_LIVE=prod"] if case == "live" else []),
                "--entrypoint", arguments[0], image, *arguments[1:],
            ], check=True)
        def record(package, case, runtime, outcome):
            checks.append({"platform": "portable", "package": package, "case": case, "runtime": runtime, "outcome": outcome})
        if "npm" in selected:
            package = json.loads((source / "package.json").read_text())
            (work / "package.json").write_text(json.dumps({"name": "stogas-release-consumer", "private": True, "type": "module", "devDependencies": package["devDependencies"]}))
            shutil.copyfile(source / "package-lock.json", work / "package-lock.json")
            run(PLAYWRIGHT, ["npm", "ci", "--ignore-scripts", "--no-audit", "--no-fund"])
            run(PLAYWRIGHT, ["npm", "install", "--no-save", "--ignore-scripts", "--no-audit", "--no-fund", f"/work/packages/stogas-{version}.tgz", f"/work/packages/stogas-sigstore-{version}.tgz"])
            # Existing adapter tests use repository-relative module paths. Their
            # inputs here come exclusively from npm's installed package bytes.
            installed = work / "node_modules/stogas"
            for name in ("bindings", "pkg"):
                shutil.copytree(installed / name, work / name)
            shutil.copytree(work / "node_modules/@stogas/sigstore", work / "packages/sigstore")
            shutil.copytree(installed / "pkg/browser", work / "target/browser")
            shutil.copytree(work / "node_modules/@stogas/sigstore/pkg/browser", work / "target/sigstore-browser")
            tests = ["tests/node/" + path.name for path in sorted((work / "tests/node").glob("*.test.mjs")) if path.name != "fuzz-workflows.test.mjs"]
            (work / "tests/browser/release.config.mjs").write_text("""import {defineConfig} from '@playwright/test';
export default defineConfig({testDir:'.',testMatch:['verifier.spec.ts','live.spec.ts'],forbidOnly:true,retries:0,reporter:'line',workers:2,projects:['chromium','firefox','webkit'].map(name=>({name,use:{browserName:name,headless:true}}))});
""")
            # Staging authority cases require a different compile-time trust
            # profile. Production packages test real offline GitHub evidence and
            # independent signing vectors here.
            browsers = ["npx", "--no-install", "playwright", "test", "--config", "tests/browser/release.config.mjs", "--grep", "ML-DSA publisher|standalone lightweight|real GitHub release|invalid Rekor|live gateway"]
            for case in CASES:
                for runtime, image, arguments in (
                    ("node", PLAYWRIGHT, ["node", "--test", *tests]),
                    ("node-minimum", NODE_MINIMUM, ["node", "--test", *tests]),
                    ("bun", BUN, ["bun", "test", *tests]),
                    ("deno", DENO, ["deno", "test", "--allow-all", "--no-check", *tests]),
                    ("worker", PLAYWRIGHT, ["node", "--test", "tests/worker/transport.test.mjs"]),
                ):
                    record("npm", f"{runtime}-{case}", image, attempt(f"npm/{runtime}-{case}", lambda: run(image, arguments, case)))
                outcome = attempt(f"npm/browsers-{case}", lambda: run(PLAYWRIGHT, browsers, case))
                for runtime in ("chromium", "firefox", "webkit"):
                    record("npm", f"{runtime}-{case}", PLAYWRIGHT, outcome)
        if "rust" in selected:
            crates = ("stogas-sigstore", "stogas-core", "stogas")
            for name in crates:
                unpack(packages / f"{name}-{version}.crate", work / name)
            (work / "src").mkdir()
            paths = {name: f"{name}/{name}-{version}" for name in crates}
            manifest = '[package]\nname="stogas-release-consumer"\nversion="0.0.0"\nedition="2024"\n[dependencies]\n'
            manifest += '\n'.join(f'{name}={{path="{path}"}}' for name, path in paths.items())
            manifest += '\n[patch.crates-io]\n' + '\n'.join(f'{name}={{path="{path}"}}' for name, path in paths.items()) + '\n'
            (work / "Cargo.toml").write_text(manifest)
            shutil.copyfile(work / paths["stogas"] / "Cargo.lock", work / "Cargo.lock")
            shutil.copyfile(source / "release/consumers/rust.rs", work / "src/main.rs")
            # Cargo retains the shipped lock's dependency versions, adding the
            # consumer and local overrides for the three unpublished archives.
            run(RUST, ["cargo", "build", "--release"])
            for case in CASES:
                record("rust", case, RUST, attempt(f"rust/{case}", lambda: run(RUST, ["cargo", "run", "--release", "--locked", "--offline"], case)))
    return checks

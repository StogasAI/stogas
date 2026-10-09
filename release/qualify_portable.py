"""Install approved npm and Rust archives in independent consumer projects."""

import json
import os
import shutil
import subprocess
import tempfile
from pathlib import Path

from artifacts import unpack

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
        def run(image, arguments, network=True):
            subprocess.run([
                "docker", "run", "--rm", "--init", "--memory", "4g", "--cpus", "4", "--shm-size", "1g",
                "--platform", "linux/amd64", "--user", f"{os.getuid()}:{os.getgid()}",
                "--mount", f"type=bind,source={work},target=/work", "--workdir", "/work",
                "--env", "HOME=/work", "--env", "CARGO_HOME=/work/.cargo", "--env", "CARGO_BUILD_JOBS=4",
                *([] if network else ["--network", "none"]), "--entrypoint", arguments[0], image, *arguments[1:],
            ], check=True)
        def passed(package, case, runtime):
            checks.append({"platform": "portable", "package": package, "case": case, "runtime": runtime, "outcome": "passed"})
        if "npm" in selected:
            package = json.loads((source / "package.json").read_text())
            (work / "package.json").write_text(json.dumps({"name": "stogas-release-consumer", "private": True, "type": "module", "devDependencies": package["devDependencies"]}))
            shutil.copyfile(source / "package-lock.json", work / "package-lock.json")
            run(PLAYWRIGHT, ["npm", "ci", "--ignore-scripts", "--no-audit", "--no-fund"])
            run(PLAYWRIGHT, ["npm", "install", "--no-save", "--ignore-scripts", "--no-audit", "--no-fund", f"/work/packages/stogas-{version}.tgz", f"/work/packages/stogas-offline-sigstore-{version}.tgz"])
            # Existing adapter tests use repository-relative module paths. Their
            # inputs here come exclusively from npm's installed package bytes.
            installed = work / "node_modules/stogas"
            for name in ("bindings", "pkg"):
                shutil.copytree(installed / name, work / name)
            shutil.copytree(work / "node_modules/@stogas/offline-sigstore", work / "packages/offline-sigstore")
            shutil.copytree(installed / "pkg/browser", work / "target/browser")
            shutil.copytree(work / "node_modules/@stogas/offline-sigstore/pkg/browser", work / "target/offline-browser")
            tests = ["tests/node/" + path.name for path in sorted((work / "tests/node").glob("*.test.mjs")) if path.name != "fuzz-workflows.test.mjs"]
            run(PLAYWRIGHT, ["node", "--test", *tests], network=False)
            passed("npm", "node-contract", PLAYWRIGHT)
            run(NODE_MINIMUM, ["node", "--test", *tests], network=False)
            passed("npm", "node-minimum-contract", NODE_MINIMUM)
            run(BUN, ["bun", "test", *tests], network=False)
            passed("npm", "bun-contract", BUN)
            run(DENO, ["deno", "test", "--allow-all", "--no-check", *tests], network=False)
            passed("npm", "deno-contract", DENO)
            run(PLAYWRIGHT, ["node", "--test", "tests/worker/transport.test.mjs"], network=False)
            passed("npm", "worker-contract", PLAYWRIGHT)
            (work / "tests/browser/release.config.mjs").write_text("""import {defineConfig} from '@playwright/test';
export default defineConfig({testDir:'.',testMatch:'verifier.spec.ts',forbidOnly:true,retries:0,reporter:'line',workers:2,projects:['chromium','firefox','webkit'].map(name=>({name,use:{browserName:name,headless:true}}))});
""")
            # Staging authority cases require a different compile-time trust
            # profile. Production packages test real offline GitHub evidence and
            # independent signing vectors here; live transport is a separate gate.
            run(PLAYWRIGHT, ["npx", "--no-install", "playwright", "test", "--config", "tests/browser/release.config.mjs", "--grep", "ML-DSA publisher|standalone lightweight|real GitHub release|invalid Rekor"], network=False)
            for runtime in ("chromium", "firefox", "webkit"):
                passed("npm", f"{runtime}-contract", PLAYWRIGHT)
        if "rust" in selected:
            crates = ("stogas-offline-sigstore", "stogas-verifier", "stogas")
            for name in crates:
                unpack(packages / f"{name}-{version}.crate", work / name)
            (work / "src").mkdir()
            paths = {name: f"{name}/{name}-{version}" for name in crates}
            manifest = '[package]\nname="stogas-release-consumer"\nversion="0.0.0"\nedition="2024"\n[dependencies]\n'
            manifest += '\n'.join(f'{name}={{path="{path}"}}' for name, path in paths.items())
            manifest += '\n[patch.crates-io]\n' + '\n'.join(f'{name}={{path="{path}"}}' for name, path in paths.items()) + '\n'
            (work / "Cargo.toml").write_text(manifest)
            shutil.copyfile(work / paths["stogas"] / "Cargo.lock", work / "Cargo.lock")
            (work / "src/main.rs").write_text('''use stogas::{Environment, Transport, TransportOptions, Verifier};
fn main() {
    assert!(Transport::start(&TransportOptions { max_connections: 0, ..Default::default() }).is_err());
    let mut verifier = Verifier::stogas(Environment::Production).unwrap();
    assert!(verifier.refresh(b"{}", 1_791_331_200_000).is_err());
    assert!(verifier.current().is_none());
    println!("Installed Rust SDK preserves production authority and rejects invalid configuration/evidence");
}
''')
            # Cargo retains the shipped lock's dependency versions, adding the
            # consumer and local overrides for the three unpublished archives.
            run(RUST, ["cargo", "run", "--release"])
            run(RUST, ["cargo", "run", "--release", "--locked", "--offline"], network=False)
            passed("rust", "installed-contract", RUST)
    return checks

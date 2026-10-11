#!/usr/bin/env python3
"""Run each SDK runtime's live tests from this checkout against one environment.

Builds the C ABI library, CLI and Wasm package for the environment, stages them
into the language packages, and runs the tests with STOGAS_LIVE set. Runs on
Linux x86_64 with Cargo, wasm-bindgen, a C compiler, Go, Maven, Ruby, uv,
Docker, and Node with this repository's npm dependencies and Playwright
browsers installed.
"""

import argparse
import json
import os
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.dont_write_bytecode = True
sys.path.insert(0, str(ROOT / "release"))
from package_bindings import DOTNET
from qualify import SWIFT
from qualify_portable import BUN, DENO


def main(environment):
    if not (ROOT / "node_modules/@playwright/test").is_dir():
        raise SystemExit("Install the npm dependencies and Playwright browsers first")
    staging = environment == "staging"
    target = ROOT / "target/live" / environment
    native = target / "debug"
    version = json.loads((ROOT / "package.json").read_text())["version"]
    env = {**os.environ, "STOGAS_LIVE": environment}

    def run(*arguments, cwd=ROOT, **variables):
        print("+", *arguments, flush=True)
        subprocess.run([str(argument) for argument in arguments], cwd=cwd, env={**env, **variables}, check=True)

    def docker(image, mounts, *arguments, workdir="/work"):
        run("docker", "run", "--rm", "--init", "--user", f"{os.getuid()}:{os.getgid()}",
            *[part for source, path in mounts.items() for part in ("--mount", f"type=bind,source={source},target={path}")],
            "--workdir", workdir, "--env", "HOME=/work", "--env", "DOTNET_CLI_HOME=/work", "--env", f"STOGAS_LIVE={environment}",
            "--entrypoint", arguments[0], image, *arguments[1:])

    features = ["--features", "staging"] if staging else []
    cargo = ["cargo", "build", "--locked", "--target-dir", target]
    run(*cargo, "--package", "stogas-verifier-ffi", *features)
    run(*cargo, "--package", "stogas", "--features", "cli,staging" if staging else "cli")
    run(*cargo, "--release", "--package", "stogas-verifier-wasm", "--target", "wasm32-unknown-unknown", *features)
    run(sys.executable, "-B", "scripts/stage-native-bindings.py", "--platform", "linux-amd64", "--native-dir", native)
    (ROOT / "go/native/linux-amd64").mkdir(parents=True, exist_ok=True)
    shutil.copyfile(native / "libstogas_verifier_ffi.a", ROOT / "go/native/linux-amd64/libstogas_verifier_ffi.a")

    target.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(prefix="live-", dir=target) as temporary:
        work = Path(temporary)
        run(sys.executable, "-I", "release/consumers/cli.py", native / "stogas", version, "tests/fixtures")
        run("cc", "-Wall", "-Wextra", "-Werror", "-Iinclude", "release/consumers/native.c", f"-L{native}", "-lstogas_verifier_ffi", f"-Wl,-rpath,{native}", "-o", work / "native")
        run(work / "native")
        run("go", "test", "-count=1", *(["-tags", "staging"] if staging else []), "./...", cwd=ROOT / "go", CGO_ENABLED="1", GOWORK="off")
        run("mvn", "-B", "-q", "-f", "bindings/java/pom.xml", "test")
        gems = {"GEM_HOME": work / "gems", "GEM_PATH": work / "gems"}
        run("gem", "-C", "bindings/ruby", "build", "stogas.gemspec", "--output", work / "stogas.gem")
        run("gem", "install", "--no-document", work / "stogas.gem", "minitest:6.0.6", **gems)
        run("ruby", "bindings/ruby/test/transport_test.rb", **gems)

        python = work / "python/bin/python"
        run("uv", "venv", work / "python")
        run("uv", "tool", "run", "--from", "maturin>=1.14,<2", "maturin", "build", "--locked", *features, "--interpreter", python,
            "--manifest-path", "bindings/python/Cargo.toml", "--target-dir", target, "--out", work / "wheels")
        run("uv", "pip", "install", "--python", python, *(work / "wheels").glob("*.whl"))
        run(python, "-m", "unittest", "discover", "-s", "bindings/python/tests", "-p", "test_package.py", "-v")

        source = {ROOT: "/source", work: "/work"}
        shutil.copytree(ROOT / "bindings/dotnet/tests", work / "dotnet", ignore=shutil.ignore_patterns("bin", "obj"))
        shutil.copyfile(ROOT / "release/consumers/dotnet/NuGet.Config", work / "dotnet/NuGet.Config")
        docker(DOTNET, source, "dotnet", "pack", "/source/bindings/dotnet/Stogas", "--artifacts-path", "/work/dotnet-build", "-o", "/work/packages")
        docker(DOTNET, source, "dotnet", "restore", "dotnet/Consumer.csproj", "--configfile", "dotnet/NuGet.Config")
        docker(DOTNET, source, "dotnet", "run", "--no-restore", "--project", "dotnet/Consumer.csproj")
        docker(SWIFT, source, "swift", "test", "--package-path", "/source/bindings/swift", "--scratch-path", "/work/swift", "-j", "4")

        # JavaScript runtimes load this environment's Wasm build from a package copy.
        js = work / "js"
        run("wasm-bindgen", target / "wasm32-unknown-unknown/release/stogas_verifier_wasm.wasm", "--target", "web", "--out-dir", js / "pkg/browser", "--out-name", "stogas_verifier")
        for name in ("bindings", "tests"):
            shutil.copytree(ROOT / name, js / name)
        shutil.copyfile(ROOT / "package.json", js / "package.json")
        (js / "node_modules").symlink_to(ROOT / "node_modules")
        run("node", "--test", "tests/node/live.test.mjs", cwd=js)
        run("node", "--test", "--test-name-pattern", "live gateway", "tests/worker/transport.test.mjs", cwd=js)
        docker(BUN, {js: "/work"}, "bun", "test", "tests/node/live.test.mjs")
        docker(DENO, {js: "/work"}, "deno", "test", "--allow-all", "--no-check", "tests/node/live.test.mjs")
        (js / "tests/browser/live.config.mjs").write_text("""import {defineConfig} from '@playwright/test';
export default defineConfig({testDir:'.',testMatch:'live.spec.ts',forbidOnly:true,retries:0,reporter:'line',projects:['chromium','firefox','webkit'].map(name=>({name,use:{browserName:name,headless:true}}))});
""")
        run("npx", "--no-install", "playwright", "test", "--config", "tests/browser/live.config.mjs", cwd=js)
    print(f"Every runtime reached the {environment} gateway and verified its evidence")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--environment", required=True, choices=("staging", "prod"))
    main(parser.parse_args().environment)

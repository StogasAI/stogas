#!/usr/bin/env bash
# Runs the release's native, CLI and Rust consumer tests offline against debug builds of this
# checkout, so a change that would break them fails CI rather than a release. A release runs
# the same tests on every platform's packages.
set -euo pipefail
cd "$(dirname "$0")/.."
cargo build --locked --package stogas-ffi --package stogas-cli
target=$(cd "${CARGO_TARGET_DIR:-target}" && pwd)
version=$(cargo metadata --locked --no-deps --format-version 1 |
  python3 -I -c 'import json, sys; print(next(p["version"] for p in json.load(sys.stdin)["packages"] if p["name"] == "stogas-cli"))')
work=$(mktemp -d "$target/release-consumers.XXXXXX")
trap 'rm -rf "$work"' EXIT

cc -Wall -Wextra -Werror -Iinclude release/consumers/native.c -L"$target/debug" -lstogas_ffi \
  -Wl,-rpath,"$target/debug" -o "$work/native-consumer"
"$work/native-consumer"
c++ -Wall -Wextra -Werror -Iinclude release/consumers/native.cpp -L"$target/debug" -lstogas_ffi \
  -Wl,-rpath,"$target/debug" -o "$work/native-cpp-consumer"
"$work/native-cpp-consumer"
python3 -I release/consumers/cli.py "$target/debug/stogas" "$version" tests/fixtures

# The Rust consumer reads its offline root from ../tests, as it does in a release.
mkdir -p "$work/rust/src"
cp release/consumers/rust.rs "$work/rust/src/main.rs"
ln -s "$PWD/tests" "$work/rust/tests"
cp Cargo.lock "$work/rust/Cargo.lock"
cat > "$work/rust/Cargo.toml" <<EOF
[package]
name = "stogas-release-consumer"
version = "0.0.0"
edition = "2024"

[dependencies]
serde_json = "1"
stogas = { path = "$PWD/crates/sdk" }
stogas-core = { path = "$PWD/crates/core" }

[workspace]
EOF
cargo run --manifest-path "$work/rust/Cargo.toml" --target-dir "$target"

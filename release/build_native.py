#!/usr/bin/env python3
"""Build production native packages with the pinned release compiler image."""

import argparse
import json
import os
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

from apple_metadata import normalize_dsym, normalize_wheel
from artifacts import crate_list_root, digest, tar_gz, unpack, write_json, write_record, zip_archive

ROOT = Path(__file__).resolve().parents[1]
TARGETS = json.loads((ROOT / "release/targets.json").read_text())["targets"]


def run(arguments, env):
    subprocess.run([str(arg) for arg in arguments], cwd=ROOT, env=env, check=True)


def build(platform, output, epoch, tools):
    target = TARGETS[platform]
    windows = target["os"] == "windows"
    android = target["os"] == "android"
    apple = target["os"] in {"macos", "ios"}
    if apple:
        if sys.platform != "darwin":
            raise ValueError("Apple release builds require macOS with Xcode 26.3 (17C529)")
        if (
            subprocess.check_output(["xcodebuild", "-version"], text=True).strip()
            != "Xcode 26.3\nBuild version 17C529"
        ):
            raise ValueError("Apple release builds require Xcode 26.3 (17C529)")
    if subprocess.check_output(["rustc", "--version"], text=True).split()[1] != "1.97.1":
        raise ValueError("Release builds require Rust 1.97.1")
    version = json.loads((ROOT / "package.json").read_text())["version"]
    triple = target["triple"]
    zig_triple = triple + (".2.17" if target.get("libc") == "glibc" else "")
    # Never inherit caller features, compiler flags, wrappers or Cargo overrides.
    compiler_options = (
        "CARGO",
        "RUST",
        "PYO3_",
        "CC",
        "CXX",
        "CFLAGS",
        "CPPFLAGS",
        "LDFLAGS",
        "AR",
        "NASM",
        "CMAKE_",
        "MAKEFLAGS",
    )
    sdk_options = {
        "SDKROOT",
        "MACOSX_DEPLOYMENT_TARGET",
        "IPHONEOS_DEPLOYMENT_TARGET",
        "TOOLCHAINS",
        "XCODE_XCCONFIG_FILE",
    }
    env = {
        key: value
        for key, value in os.environ.items()
        if not key.startswith(compiler_options) and key not in sdk_options
    }
    flags = f"--remap-path-prefix={ROOT}=/stogas -C debuginfo=line-tables-only"
    env.update(
        {
            "CARGO_INCREMENTAL": "0",
            "CARGO_BUILD_JOBS": "4",
            "CARGO_TARGET_DIR": str(output / "target") if apple else "/build/target",
            "SOURCE_DATE_EPOCH": str(epoch),
            "CARGO_HOME": str(output / "cargo-home") if apple else "/usr/local/cargo",
            "RUSTUP_HOME": os.environ.get("RUSTUP_HOME", str(Path.home() / ".rustup"))
            if apple
            else "/usr/local/rustup",
            "RUSTUP_TOOLCHAIN": "1.97.1",
            "RUSTFLAGS": flags,
            "TZ": "UTC",
            "LC_ALL": "C.UTF-8",
        }
    )
    # cargo-auditable lists each executable's and shared library's crates in it, which Trivy,
    # Grype, Syft and `cargo audit bin` read. Maturin and the cross-compilers run Cargo
    # themselves, so this `cargo` sends every Cargo command through it.
    (tools / "cargo").write_text(
        f'#!/bin/sh\nexec "{shutil.which("cargo", path=env["PATH"])}" auditable "$@"\n'
    )
    (tools / "cargo").chmod(0o755)
    env["PATH"] = f"{tools}{os.pathsep}{env['PATH']}"
    if windows:
        # llvm-mingw's open-source runtime, linked statically, takes the place of Microsoft's, so
        # no Windows file holds closed-source code or needs a runtime DLL beside it.
        clang = f"/opt/llvm-mingw/bin/{triple.split('-')[0]}-w64-mingw32-clang"
        variable = triple.replace("-", "_")
        env["RUSTFLAGS"] += " -C target-feature=+crt-static -C link-arg=-Wl,--no-insert-timestamp"
        env[f"CARGO_TARGET_{variable.upper()}_LINKER"] = clang
        env[f"CC_{variable}"] = clang
        env[f"CFLAGS_{variable}"] = "-mno-incremental-linker-compatible"
        env[f"CXXFLAGS_{variable}"] = "-mno-incremental-linker-compatible"
        env[f"AR_{variable}"] = "/opt/llvm-mingw/bin/llvm-ar"
        env["NASMENV"] = "--reproducible"
    if apple:
        env["RUSTFLAGS"] += (
            f" --remap-path-prefix={env['CARGO_HOME']}=/cargo --remap-path-prefix={env['CARGO_TARGET_DIR']}=/build/target"
        )
        env["ZERO_AR_DATE"] = "1"
        env[
            "MACOSX_DEPLOYMENT_TARGET" if target["os"] == "macos" else "IPHONEOS_DEPLOYMENT_TARGET"
        ] = target["minimum"]
        sdk = (
            "macosx"
            if target["os"] == "macos"
            else "iphonesimulator"
            if target.get("simulator")
            else "iphoneos"
        )
        env["SDKROOT"] = subprocess.check_output(
            ["xcrun", "--sdk", sdk, "--show-sdk-path"], text=True
        ).strip()
    sysroot = Path(subprocess.check_output(["rustc", "--print", "sysroot"], text=True).strip())
    host = subprocess.check_output(["rustc", "-vV"], text=True).split("host: ")[1].splitlines()[0]
    objcopy = sysroot / "lib/rustlib" / host / "bin/llvm-objcopy"
    if not objcopy.is_file():
        raise ValueError("The release compiler requires llvm-tools-preview")
    if android:
        base = [
            "cargo",
            "ndk",
            "--target",
            target["android_abi"],
            "--platform",
            target["minimum"],
            "build",
        ]
    elif apple or windows:
        base = ["cargo", "build", "--target", triple]
    else:
        base = ["cargo", "zigbuild", "--target", zig_triple]
    base += ["--locked", "--profile", "dist"]
    library_env = dict(env)
    if target.get("libc") == "musl":
        library_env["RUSTFLAGS"] += " -C target-feature=-crt-static"
    # Independent Cargo invocations prevent the CLI's optional dependencies from
    # entering the FFI archive through Cargo feature unification.
    if apple:
        library_command = [*base]
        library_command[1] = "rustc"
        link_options = (
            ["--crate-type", "staticlib"]
            if target["os"] == "ios"
            else [
                "--",
                "-C",
                "link-arg=-Wl,-install_name,@rpath/libstogas_ffi.dylib",
            ]
        )
        run([*library_command, "--package", "stogas-ffi", "--lib", *link_options], library_env)
    else:
        run([*base, "--package", "stogas-ffi"], library_env)
    built = Path(env["CARGO_TARGET_DIR"]) / triple / "dist"
    output.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(prefix="stogas-package-") as temporary:
        temporary = Path(temporary)
        runtime, symbols = temporary / "runtime", temporary / "symbols"
        runtime.mkdir()
        symbols.mkdir()
        archive = "libstogas_ffi.a"
        shutil.copyfile(built / archive, symbols / archive)
        if windows:
            # GNU objcopy preserves NASM's reproducible COFF file records. LLVM objcopy
            # corrupts their empty auxiliary filename; ARM objects use LLVM's backend.
            coff_objcopy = objcopy if target["arch"] == "arm64" else Path("/usr/bin/objcopy")
            strip_windows_archive(
                coff_objcopy, objcopy.with_name("llvm-ar"), built / archive, runtime / archive, env
            )
        else:
            sections = (
                ["__LLVM,__bitcode", "__LLVM,__cmdline"] if apple else [".llvmbc", ".llvmcmd"]
            )
            run(
                [
                    objcopy,
                    "--strip-debug",
                    *[f"--remove-section={name}" for name in sections],
                    built / archive,
                    runtime / archive,
                ],
                env,
            )
        # GitHub limits individual Git files to 100 MiB. Keep real symbol names;
        # the separate unstripped archive supports source-level relinking.
        if (runtime / archive).stat().st_size > 100 * 1024**2:
            raise ValueError("Static library exceeds the GitHub per-file limit for the Go module")
        if windows:
            shared = "stogas_ffi.dll"
            split_debug(
                objcopy, built / shared, runtime / shared, symbols / (shared + ".debug"), env
            )
            # lld writes the import library in the format that Visual Studio's linker also reads.
            shutil.copyfile(built / "libstogas_ffi.dll.a", runtime / (shared + ".lib"))
        elif target["os"] == "macos":
            shared = "libstogas_ffi.dylib"
            split_apple_debug(built / shared, runtime / shared, symbols / (shared + ".dSYM"), env)
        elif not apple:
            shared = "libstogas_ffi.so"
            split_debug(
                objcopy, built / shared, runtime / shared, symbols / (shared + ".debug"), env
            )
        if target["os"] != "ios":
            require_crate_list(objcopy, runtime / shared, "stogas-ffi", apple, env)
        # The CLI has its own archive, which package managers install without the library.
        cli = temporary / "cli"
        executable = "stogas.exe" if windows else "stogas"
        if "cli" in target["packages"]:
            run([*base, "--package", "stogas-cli"], env)
            cli.mkdir()
            if apple:
                split_apple_debug(
                    built / executable, cli / executable, symbols / "stogas.dSYM", env
                )
            else:
                split_debug(
                    objcopy, built / executable, cli / executable, symbols / "stogas.debug", env
                )
            require_crate_list(objcopy, cli / executable, "stogas-cli", apple, env)
        for directory in (runtime, symbols, cli):
            if directory.is_dir():
                shutil.copyfile(ROOT / "LICENSE", directory / "LICENSE")
        shutil.copyfile(ROOT / "include/stogas.h", runtime / "stogas.h")
        name = f"stogas-v{version}-{platform}"
        pack, extension = (zip_archive, "zip") if windows else (tar_gz, "tar.gz")
        pack(output / f"{name}.{extension}", runtime, epoch, name)
        pack(output / f"{name}-debug.{extension}", symbols, epoch, name + "-debug")
        if cli.is_dir():
            pack(
                output / f"stogas-cli-v{version}-{platform}.{extension}",
                cli,
                epoch,
                f"stogas-cli-v{version}-{platform}",
            )
        if "python" in target["packages"]:
            wheels = output / "wheels"
            wheels.mkdir()
            compatibility = (
                []
                if windows or apple
                else [
                    "--compatibility",
                    "manylinux_2_17" if target["libc"] == "glibc" else "musllinux_1_2",
                ]
            )
            run(
                [
                    "maturin",
                    "build",
                    "--locked",
                    "--profile",
                    "dist",
                    *([] if windows or apple else ["--zig"]),
                    "--target",
                    triple,
                    *compatibility,
                    *(["--include-debuginfo"] if apple else []),
                    "--manifest-path",
                    "bindings/python/Cargo.toml",
                    "--out",
                    wheels,
                    *(["--", "-C", "strip=debuginfo"] if windows or apple else []),
                ],
                library_env,
            )
            # Maturin owns native dependency validation. The wheel also installs the CLI as a
            # script, so `pipx install stogas` and `uvx stogas` run it, and Apple metadata needs
            # portable paths; RECORD then binds those exact bytes.
            for wheel in wheels.glob("*.whl"):
                with tempfile.TemporaryDirectory(prefix="stogas-wheel-") as unpacked:
                    tree = Path(unpacked) / "wheel"
                    unpack(wheel, tree)
                    extensions = [
                        path
                        for path in (tree / "stogas").iterdir()
                        if path.suffix in {".so", ".pyd"}
                    ]
                    if len(extensions) != 1:
                        raise ValueError(f"{wheel.name} must hold one extension module")
                    require_crate_list(objcopy, extensions[0], "stogas-python", apple, env)
                    if apple:
                        normalize_wheel(tree, ROOT)
                    if cli.is_dir():
                        (dist_info,) = tree.glob("*.dist-info")
                        scripts = tree / dist_info.name.replace(".dist-info", ".data") / "scripts"
                        scripts.mkdir(parents=True)
                        shutil.copyfile(cli / executable, scripts / executable)
                        (scripts / executable).chmod(0o755)
                    write_record(tree)
                    zip_archive(output / wheel.name, tree, epoch)
            shutil.rmtree(wheels)
    if apple:
        shutil.rmtree(env["CARGO_TARGET_DIR"])
        shutil.rmtree(env["CARGO_HOME"])
    files = sorted(path for path in output.iterdir() if path.is_file())
    write_json(
        output / f"{platform}.json",
        {
            "schema": "stogas.sdk-build.v1",
            "platform": platform,
            "environment": "prod",
            "artifacts": [
                {"name": path.name, "size": path.stat().st_size, "sha256": digest(path)}
                for path in files
            ],
        },
    )


def require_crate_list(objcopy, binary, package, apple, env):
    """Refuse a binary that lacks the list of its package's crates."""
    with tempfile.TemporaryDirectory(prefix="stogas-crates-") as temporary:
        section = Path(temporary) / "crates"
        run(
            [
                objcopy,
                f"--dump-section={'__DATA,' if apple else ''}.dep-v0={section}",
                binary,
                Path(temporary) / "copy",
            ],
            env,
        )
        if crate_list_root(section.read_bytes()) != package:
            raise ValueError(f"{binary.name} lists the crates of another package than {package}")


def split_debug(objcopy, source, binary, debug, env):
    run([objcopy, "--only-keep-debug", source, debug], env)
    run([objcopy, "--strip-debug", source, binary], env)
    run([objcopy, f"--add-gnu-debuglink={debug}", binary], env)
    binary.chmod(0o755)


def split_apple_debug(source, binary, debug, env):
    run(["xcrun", "dsymutil", source, "-o", debug], env)
    normalize_dsym(debug)
    shutil.copyfile(source, binary)
    run(["xcrun", "strip", "-S", binary], env)
    binary.chmod(0o755)


def strip_windows_archive(objcopy, ar, original, packaged, env):
    # COFF archives contain both ordinary object files and short import records.
    # Only object files have debug/LLVM sections. Replace those members through
    # llvm-ar, preserving every import record and the archive's symbol index.
    members = subprocess.check_output([ar, "t", original], text=True).splitlines()
    objects = [name for name in members if name.endswith((".o", ".obj"))]
    if len(objects) != len(set(objects)) or any(Path(name).name != name for name in members):
        raise ValueError("Static archive contains duplicate object names or paths")
    if any(not name.endswith((".o", ".obj", ".dll", ".exe", ".sys")) for name in members):
        raise ValueError("Static archive contains an unexpected member format")
    symbol_command = [
        ar.with_name("llvm-nm"),
        "--defined-only",
        "--extern-only",
        "--format=just-symbols",
    ]
    expected_symbols = subprocess.check_output([*symbol_command, original], env=env)
    shutil.copyfile(original, packaged)
    with tempfile.TemporaryDirectory(prefix="stogas-coff-") as temporary:
        subprocess.run([ar, "x", original, *objects], cwd=temporary, check=True)
        for name in objects:
            run(
                [
                    objcopy,
                    "--strip-debug",
                    "--remove-section=.llvmbc",
                    "--remove-section=.llvmcmd",
                    Path(temporary) / name,
                ],
                env,
            )
        subprocess.run([ar, "rD", packaged, *objects], cwd=temporary, check=True)
    if subprocess.check_output([ar, "t", packaged], text=True).splitlines() != members:
        raise ValueError("Static archive member order changed")
    if subprocess.check_output([*symbol_command, packaged], env=env) != expected_symbols:
        raise ValueError("Static archive processing changed its exported symbols")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--platform", choices=TARGETS, required=True)
    parser.add_argument("--out", type=Path, required=True)
    parser.add_argument("--epoch", type=int, required=True)
    args = parser.parse_args()
    if args.epoch < 315532800 or args.epoch > 0xFFFFFFFF:
        parser.error("Source epoch must fit the ZIP/gzip timestamp range")
    with tempfile.TemporaryDirectory(prefix="stogas-tools-") as tools:
        build(args.platform, args.out.resolve(), args.epoch, Path(tools))

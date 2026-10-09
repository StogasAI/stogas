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

from artifacts import digest, tar_gz, zip_archive, write_json

ROOT = Path(__file__).resolve().parents[1]
TARGETS = json.loads((ROOT / "release/targets.json").read_text())["targets"]


def run(arguments, env):
    subprocess.run([str(arg) for arg in arguments], cwd=ROOT, env=env, check=True)


def build(platform, output, epoch):
    target = TARGETS[platform]
    windows = target["os"] == "windows"
    android = target["os"] == "android"
    apple = target["os"] in {"macos", "ios"}
    if apple:
        if sys.platform != "darwin":
            raise ValueError("Apple release builds require macOS with Xcode 26.3 (17C529)")
        if subprocess.check_output(["xcodebuild", "-version"], text=True).strip() != "Xcode 26.3\nBuild version 17C529":
            raise ValueError("Apple release builds require Xcode 26.3 (17C529)")
    if subprocess.check_output(["rustc", "--version"], text=True).split()[1] != "1.97.1":
        raise ValueError("Release builds require Rust 1.97.1")
    version = json.loads((ROOT / "package.json").read_text())["version"]
    triple = target["triple"]
    zig_triple = triple + (".2.17" if target.get("libc") == "glibc" else "")
    # Never inherit caller features, compiler flags, wrappers or Cargo overrides.
    compiler_options = ("CARGO_", "RUST", "PYO3_", "CC", "CXX", "CFLAGS", "CPPFLAGS", "LDFLAGS", "AR", "NASM", "CMAKE_", "MAKEFLAGS")
    sdk_options = {"SDKROOT", "MACOSX_DEPLOYMENT_TARGET", "IPHONEOS_DEPLOYMENT_TARGET", "TOOLCHAINS", "XCODE_XCCONFIG_FILE"}
    env = {key: value for key, value in os.environ.items() if not key.startswith(compiler_options) and key not in sdk_options}
    flags = f"--remap-path-prefix={ROOT}=/stogas -C debuginfo=line-tables-only"
    env.update({
        "CARGO_INCREMENTAL": "0", "CARGO_BUILD_JOBS": "4",
        "CARGO_TARGET_DIR": str(output / "target") if apple else "/build/target", "SOURCE_DATE_EPOCH": str(epoch),
        "CARGO_HOME": str(output / "cargo-home") if apple else "/usr/local/cargo",
        "RUSTUP_HOME": os.environ.get("RUSTUP_HOME", str(Path.home() / ".rustup")) if apple else "/usr/local/rustup", "RUSTUP_TOOLCHAIN": "1.97.1",
        "RUSTFLAGS": flags, "TZ": "UTC", "LC_ALL": "C.UTF-8",
    })
    if windows:
        env["RUSTFLAGS"] += " -C target-feature=+crt-static -C link-arg=/Brepro -C link-arg=/PDBALTPATH:%_PDB%"
        env["RUSTFLAGS"] += f" -C linker={ROOT}/release/windows_link.py"
        env["CL_FLAGS"] = "/Brepro"
        env["NASMENV"] = "--reproducible"
        env["MATURIN_USE_XWIN"] = "1"
    if apple:
        env["RUSTFLAGS"] += f" --remap-path-prefix={env['CARGO_HOME']}=/cargo --remap-path-prefix={env['CARGO_TARGET_DIR']}=/build/target"
        env["ZERO_AR_DATE"] = "1"
        env["MACOSX_DEPLOYMENT_TARGET" if target["os"] == "macos" else "IPHONEOS_DEPLOYMENT_TARGET"] = target["minimum"]
        sdk = "macosx" if target["os"] == "macos" else "iphonesimulator" if target.get("simulator") else "iphoneos"
        env["SDKROOT"] = subprocess.check_output(["xcrun", "--sdk", sdk, "--show-sdk-path"], text=True).strip()
    sysroot = Path(subprocess.check_output(["rustc", "--print", "sysroot"], text=True).strip())
    host = subprocess.check_output(["rustc", "-vV"], text=True).split("host: ")[1].splitlines()[0]
    objcopy = sysroot / "lib/rustlib" / host / "bin/llvm-objcopy"
    if not objcopy.is_file():
        raise ValueError("The release compiler requires llvm-tools-preview")
    if android:
        base = ["cargo", "ndk", "--target", target["android_abi"], "--platform", target["minimum"], "build"]
    elif apple:
        base = ["cargo", "build", "--target", triple]
    else:
        base = ["cargo", "xwin", "build"] if windows else ["cargo", "zigbuild"]
        base += ["--target", zig_triple]
    base += ["--locked", "--profile", "dist"]
    library_env = dict(env)
    if target.get("libc") == "musl":
        library_env["RUSTFLAGS"] += " -C target-feature=-crt-static"
    # Independent Cargo invocations prevent the CLI's optional dependencies from
    # entering the FFI archive through Cargo feature unification.
    if apple:
        library_command = [*base]
        library_command[1] = "rustc"
        link_options = ["--crate-type", "staticlib"] if target["os"] == "ios" else [
            "--", "-C", "link-arg=-Wl,-install_name,@rpath/libstogas_verifier_ffi.dylib",
        ]
        run([*library_command, "--package", "stogas-verifier-ffi", "--lib", *link_options], library_env)
    else:
        run([*base, "--package", "stogas-verifier-ffi"], library_env)
    built = Path(env["CARGO_TARGET_DIR"]) / triple / "dist"
    output.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(prefix="stogas-package-") as temporary:
        temporary = Path(temporary)
        runtime, symbols = temporary / "runtime", temporary / "symbols"
        runtime.mkdir()
        symbols.mkdir()
        archive = "stogas_verifier_ffi.lib" if windows else "libstogas_verifier_ffi.a"
        if windows:
            # COFF import members cannot be rewritten by llvm-objcopy. Preserve
            # the complete MSVC archive; its debug records support consumer PDBs.
            shutil.copyfile(built / archive, runtime / archive)
        else:
            shutil.copyfile(built / archive, symbols / archive)
            sections = ["__LLVM,__bitcode", "__LLVM,__cmdline"] if apple else [".llvmbc", ".llvmcmd"]
            run([objcopy, "--strip-debug", *[f"--remove-section={name}" for name in sections], built / archive, runtime / archive], env)
        # GitHub limits individual Git files to 100 MiB. Keep real symbol names;
        # the separate unstripped archive supports source-level relinking.
        if not windows and (runtime / archive).stat().st_size > 100 * 1024**2:
            raise ValueError("Static library exceeds the GitHub per-file limit for the Go module")
        if windows:
            shared = "stogas_verifier_ffi.dll"
            shutil.copyfile(built / shared, runtime / shared)
            shutil.copyfile(built / (shared + ".lib"), runtime / (shared + ".lib"))
            shutil.copyfile(built / "stogas_verifier_ffi.pdb", symbols / "stogas_verifier_ffi.pdb")
        elif target["os"] == "macos":
            shared = "libstogas_verifier_ffi.dylib"
            split_apple_debug(built / shared, runtime / shared, symbols / (shared + ".dSYM"), env)
        elif not apple:
            shared = "libstogas_verifier_ffi.so"
            split_debug(objcopy, built / shared, runtime / shared, symbols / (shared + ".debug"), env)
        if "cli" in target["packages"]:
            run([*base, "--package", "stogas", "--features", "cli"], env)
            if windows:
                shutil.copyfile(built / "stogas.exe", runtime / "stogas.exe")
                shutil.copyfile(built / "stogas.pdb", symbols / "stogas.pdb")
            elif apple:
                split_apple_debug(built / "stogas", runtime / "stogas", symbols / "stogas.dSYM", env)
            else:
                split_debug(objcopy, built / "stogas", runtime / "stogas", symbols / "stogas.debug", env)
        if windows:
            build_windows_go(target, runtime, symbols, objcopy, env)
        for directory in (runtime, symbols):
            shutil.copyfile(ROOT / "LICENSE", directory / "LICENSE")
        shutil.copyfile(ROOT / "include/stogas_verifier.h", runtime / "stogas_verifier.h")
        name = f"stogas-v{version}-{platform}"
        pack, extension = (zip_archive, "zip") if windows else (tar_gz, "tar.gz")
        pack(output / f"{name}.{extension}", runtime, epoch, name)
        pack(output / f"{name}-debug.{extension}", symbols, epoch, name + "-debug")
    if "python" in target["packages"]:
        wheels = output / "wheels"
        wheels.mkdir()
        compatibility = [] if windows or apple else ["--compatibility", "manylinux_2_17" if target["libc"] == "glibc" else "musllinux_1_2"]
        run([
            "maturin", "build", "--locked", "--profile", "dist", *([] if windows or apple else ["--zig"]),
            "--target", triple, *compatibility, *(["--include-debuginfo"] if windows or apple else []),
            "--manifest-path", "bindings/python/Cargo.toml", "--out", wheels,
            *(["--", "-C", "strip=debuginfo"] if apple else []),
        ], library_env)
        # Maturin owns native dependency validation. Apple metadata additionally
        # needs portable paths, with RECORD updated to bind those exact bytes.
        from artifacts import unpack
        for wheel in wheels.glob("*.whl"):
            with tempfile.TemporaryDirectory(prefix="stogas-wheel-") as temporary:
                tree = Path(temporary) / "wheel"
                unpack(wheel, tree)
                if apple:
                    from apple_metadata import normalize_wheel
                    normalize_wheel(tree, ROOT)
                zip_archive(output / wheel.name, tree, epoch)
        shutil.rmtree(wheels)
    if apple:
        shutil.rmtree(env["CARGO_TARGET_DIR"])
        shutil.rmtree(env["CARGO_HOME"])
    files = sorted(path for path in output.iterdir() if path.is_file())
    write_json(output / f"{platform}.json", {
        "schema": "stogas.sdk-build.v1", "platform": platform, "environment": "prod",
        "artifacts": [{"name": path.name, "size": path.stat().st_size, "sha256": digest(path)} for path in files],
    })


def split_debug(objcopy, source, binary, debug, env):
    run([objcopy, "--only-keep-debug", source, debug], env)
    run([objcopy, "--strip-debug", source, binary], env)
    run([objcopy, f"--add-gnu-debuglink={debug}", binary], env)
    binary.chmod(0o755)


def split_apple_debug(source, binary, debug, env):
    run(["xcrun", "dsymutil", source, "-o", debug], env)
    from apple_metadata import normalize_dsym
    normalize_dsym(debug)
    shutil.copyfile(source, binary)
    run(["xcrun", "strip", "-S", binary], env)
    binary.chmod(0o755)


def build_windows_go(target, runtime, symbols, objcopy, env):
    triple = target["go_triple"]
    machine = {"amd64": "x86_64", "arm64": "aarch64"}[target["arch"]]
    prefix = f"/opt/llvm-mingw/bin/{machine}-w64-mingw32"
    env = dict(env)
    # cgo uses the GNU ABI. MSVC archives cannot substitute for this build.
    env["RUSTFLAGS"] = f"--remap-path-prefix={ROOT}=/stogas -C debuginfo=line-tables-only -C link-arg=-Wl,--no-insert-timestamp"
    env[f"CARGO_TARGET_{triple.upper().replace('-', '_')}_LINKER"] = prefix + "-clang"
    env[f"CC_{triple.replace('-', '_')}"] = prefix + "-clang"
    env[f"CFLAGS_{triple.replace('-', '_')}"] = "-mno-incremental-linker-compatible"
    env[f"CXXFLAGS_{triple.replace('-', '_')}"] = "-mno-incremental-linker-compatible"
    env[f"AR_{triple.replace('-', '_')}"] = "/opt/llvm-mingw/bin/llvm-ar"
    run(["cargo", "build", "--locked", "--profile", "dist", "--target", triple, "--package", "stogas-verifier-ffi"], env)
    original = Path(env["CARGO_TARGET_DIR"]) / triple / "dist/libstogas_verifier_ffi.a"
    (runtime / "go").mkdir()
    (symbols / "go").mkdir()
    shutil.copyfile(original, symbols / "go/libstogas_verifier_ffi.a")
    packaged = runtime / "go/libstogas_verifier_ffi.a"
    # GNU objcopy preserves NASM's reproducible COFF file records. LLVM objcopy
    # corrupts their empty auxiliary filename; ARM objects use LLVM's backend.
    coff_objcopy = objcopy if target["arch"] == "arm64" else Path("/usr/bin/objcopy")
    strip_windows_archive(coff_objcopy, objcopy.with_name("llvm-ar"), original, packaged, env)
    if packaged.stat().st_size > 100 * 1024**2:
        raise ValueError("Go static library exceeds the GitHub per-file limit")


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
    symbol_command = [ar.with_name("llvm-nm"), "--defined-only", "--extern-only", "--format=just-symbols"]
    expected_symbols = subprocess.check_output([*symbol_command, original], env=env)
    shutil.copyfile(original, packaged)
    with tempfile.TemporaryDirectory(prefix="stogas-coff-") as temporary:
        subprocess.run([ar, "x", original, *objects], cwd=temporary, check=True)
        for name in objects:
            run([objcopy, "--strip-debug", "--remove-section=.llvmbc", "--remove-section=.llvmcmd", Path(temporary) / name], env)
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
    build(args.platform, args.out.resolve(), args.epoch)

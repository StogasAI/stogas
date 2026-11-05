#!/usr/bin/env python3
"""Build the native consumers with Visual Studio's compiler, which most Windows C and C++
projects use, from a directory that holds them, stogas.h and the import library."""

import argparse
import os
import shutil
import subprocess
from pathlib import Path

# Each machine's Visual Studio compiler component, and the vcvarsall.bat argument for a native build.
TOOLS = {"amd64": ("Microsoft.VisualStudio.Component.VC.Tools.x86.x64", "x64"), "arm64": ("Microsoft.VisualStudio.Component.VC.Tools.ARM64", "arm64")}


def variable(env, name):
    """Windows names variables in any case, and os.environ there gives them in capitals."""
    return next(value for key, value in env.items() if key.upper() == name.upper())


def environment(arch, base):
    """The environment that Visual Studio's developer prompt sets."""
    component, argument = TOOLS[arch]
    vswhere = Path(variable(base, "ProgramFiles(x86)")) / "Microsoft Visual Studio/Installer/vswhere.exe"
    installation = subprocess.run([vswhere, "-latest", "-products", "*", "-requires", component, "-property", "installationPath"], env=base, check=True, capture_output=True, text=True).stdout.strip()
    if not installation:
        raise ValueError(f"Native qualification requires Visual Studio with {component}")
    script = Path(installation) / "VC/Auxiliary/Build/vcvarsall.bat"
    listing = subprocess.run(f'"{script}" {argument} >nul && set', shell=True, env=base, check=True, capture_output=True, text=True).stdout
    return dict(line.split("=", 1) for line in listing.splitlines() if "=" in line[1:] and not line.startswith("="))


def build(directory, arch, base):
    """Build native-msvc.exe from native.c, build and run the C++ consumer, and return the
    compiler version."""
    compiler_environment = environment(arch, base)
    compiler = shutil.which("cl", path=variable(compiler_environment, "PATH"))
    if not compiler:
        raise ValueError("Visual Studio's developer environment has no cl.exe")
    # The consumer uses getenv and sscanf, which MSVC deprecates in favor of its own _s functions.
    flags = [compiler, "/nologo", "/W4", "/WX", "/D_CRT_SECURE_NO_WARNINGS"]
    subprocess.run([*flags, "native.c", "stogas_ffi.dll.lib", "ws2_32.lib", "/Fenative-msvc.exe"], cwd=directory, env=compiler_environment, check=True)
    subprocess.run([*flags, "/EHsc", "native.cpp", "stogas_ffi.dll.lib", "/Fenative-cpp-msvc.exe"], cwd=directory, env=compiler_environment, check=True)
    subprocess.run([Path(directory) / "native-cpp-msvc.exe"], cwd=directory, env=base, check=True)
    return "MSVC " + variable(compiler_environment, "VCToolsVersion")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("directory", type=Path)
    parser.add_argument("arch", choices=sorted(TOOLS))
    args = parser.parse_args()
    print(build(args.directory, args.arch, dict(os.environ)))

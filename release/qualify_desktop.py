"""Exercise installed packages on macOS and Windows using native toolchains."""

import os
import platform as host
import re
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

import msvc
from artifacts import unpack, wheel
from gate import attempt


def qualify(source, packages, version, platform, target, requested, cases):
    windows = target["os"] == "windows"
    if sys.platform != ("win32" if windows else "darwin"):
        raise ValueError("Desktop qualification must run on the requested operating system")
    selected = set(requested or target["packages"])
    if not selected <= set(target["packages"]):
        raise ValueError("Requested desktop package is unsupported")
    machine = {"amd64": "x86_64", "arm64": "aarch64"}[target["arch"]]
    checks = []
    with tempfile.TemporaryDirectory(prefix="stogas-consumer-") as temporary:
        work = Path(temporary)
        env = dict(os.environ)
        env.pop("STOGAS_LIVE", None)
        env.update({"GOWORK": "off", "CGO_ENABLED": "1", "GEM_HOME": str(work / "gems"), "GEM_PATH": str(work / "gems"), "DOTNET_CLI_HOME": str(work), "PYTHONNOUSERSITE": "1"})
        def run(arguments, directory=work, environment=None):
            subprocess.run([str(arg) for arg in arguments], cwd=directory, env=environment or env, check=True)
        def runtime_of(*command):
            return subprocess.check_output([str(arg) for arg in command], env=env, text=True, stderr=subprocess.STDOUT).strip()
        # Hosted runners have a network in both cases; live cases use the
        # production gateways. Each case runs every command.
        def qualify_cases(package, runtime, *commands, directory=work, environment=None):
            for case in cases:
                case_environment = {**(environment or env), **({"STOGAS_LIVE": "prod"} if case == "live" else {})}
                outcome = attempt(f"{package}/{case}", lambda: [run(command, directory, case_environment) for command in commands])
                checks.append({"platform": platform, "package": package, "case": case, "runtime": host.platform() + "; " + runtime, "outcome": outcome})
        shutil.copytree(source / "tests/fixtures", work / "tests/fixtures")
        extension = "zip" if windows else "tar.gz"
        unpack(packages / f"stogas-v{version}-{platform}.{extension}", work / "native")
        native = next((work / "native").iterdir())
        if "native" in selected:
            compiler = shutil.which(machine + "-w64-mingw32-clang" if windows else "clang")
            cxx = shutil.which(machine + "-w64-mingw32-clang++" if windows else "clang++")
            if not compiler or not cxx:
                raise ValueError("Native qualification requires the matching C and C++ compilers")
            for name in ("native.c", "native.cpp"):
                shutil.copyfile(source / "release/consumers" / name, native / name)
            suffix = ".exe" if windows else ""
            library = ["stogas_ffi.dll.lib"] if windows else ["-L.", "-lstogas_ffi", "-Wl,-rpath,@loader_path"]
            warnings = ["-Wall", "-Wextra", "-Werror"]
            run([compiler, *warnings, "native.c", *library, *(["-lws2_32"] if windows else []), "-o", f"native-consumer{suffix}"], native)
            run([cxx, *warnings, "native.cpp", *library, "-o", f"native-cpp-consumer{suffix}"], native)
            run([native / f"native-cpp-consumer{suffix}"], native)
            consumers, runtime = [[native / f"native-consumer{suffix}"]], runtime_of(compiler, "--version")
            if windows:
                runtime += "; " + msvc.build(native, target["arch"], env)
                consumers.append([native / "native-msvc.exe"])
            qualify_cases("native", runtime, *consumers, directory=native)
        if "cli" in selected:
            executable = native / ("stogas.exe" if windows else "stogas")
            qualify_cases("cli", runtime_of(executable, "--version"), [sys.executable, "-I", source / "release/consumers/cli.py", executable, version, work / "tests/fixtures"])
        if "python" in selected:
            name = wheel([path.name for path in packages.iterdir()], target)
            run([sys.executable, "-m", "venv", str(work / "python")])
            python = work / ("python/Scripts/python.exe" if windows else "python/bin/python")
            run([python, "-m", "pip", "install", "--no-index", "--no-deps", packages / name])
            shutil.copytree(source / "bindings/python/tests", work / "bindings/python/tests")
            qualify_cases("python", runtime_of(python, "--version"), [python, "-m", "unittest", "discover", "-s", "bindings/python/tests", "-p", "test_package.py", "-v"])
        if "java" in selected:
            maven = shutil.which("mvn")
            if not maven:
                raise ValueError("Java qualification requires Maven and Java 17 or later")
            properties = subprocess.check_output(["java", "-XshowSettings:properties", "-version"], env=env, text=True, stderr=subprocess.STDOUT)
            architecture = re.search(r"^\s*os\.arch = (\S+)\s*$", properties, re.MULTILINE)
            expected = {"amd64": {"amd64", "x86_64"}, "arm64": {"aarch64", "arm64"}}[target["arch"]]
            if not architecture or architecture.group(1) not in expected:
                raise ValueError("The Java runtime architecture does not match the requested platform")
            shutil.copytree(source / "bindings/java/src/test", work / "java/src/test")
            shutil.copyfile(source / "release/consumers/java/pom.xml", work / "java/pom.xml")
            base = [maven, "-B", "-ntp", f"-Dmaven.repo.local={work / 'maven'}"]
            run([*base, "org.apache.maven.plugins:maven-install-plugin:3.1.4:install-file", f"-Dfile={packages / f'stogas-{version}.jar'}", f"-DpomFile={packages / f'stogas-{version}.pom'}"])
            qualify_cases("java", runtime_of("java", "-version"), [*base, "-f", "java/pom.xml", f"-Dstogas.version={version}", "test"])
        if "dotnet" in selected:
            shutil.copytree(source / "bindings/dotnet/tests", work / "dotnet")
            (work / "packages").mkdir()
            shutil.copyfile(packages / f"Stogas.{version}.nupkg", work / "packages" / f"Stogas.{version}.nupkg")
            shutil.copyfile(source / "release/consumers/dotnet/NuGet.Config", work / "dotnet/NuGet.Config")
            run(["dotnet", "restore", "dotnet/Consumer.csproj", "--packages", work / "nuget", "--configfile", "dotnet/NuGet.Config", "--runtime", target["dotnet"], "-p:SelfContained=true"])
            qualify_cases("dotnet", runtime_of("dotnet", "--info"), ["dotnet", "run", "--no-restore", "--self-contained", "--runtime", target["dotnet"], "--project", "dotnet/Consumer.csproj"])
        if "ruby" in selected:
            shutil.copytree(source / "bindings/ruby/test", work / "ruby")
            gem = shutil.which("gem")
            if not gem:
                raise ValueError("Ruby qualification requires Ruby and RubyGems")
            run([gem, "install", "--no-document", packages / f"stogas-{version.replace('-', '.')}-{target['ruby']}.gem"])
            run([gem, "install", "--no-document", "minitest", "--version", "6.0.6"])
            qualify_cases("ruby", runtime_of("ruby", "--version"), ["ruby", "ruby/transport_test.rb"])
        if "go" in selected:
            unpack(packages / f"stogas-go-v{version}.tar.gz", work / "go-package")
            shutil.copytree(source / "tests/fixtures", work / "go-package/tests/fixtures")
            compiler = shutil.which(machine + "-w64-mingw32-clang" if windows else "clang")
            if not compiler:
                raise ValueError("Go qualification requires the matching C compiler")
            qualify_cases("go", runtime_of("go", "version"), ["go", "test", "-count=1", "./..."], directory=work / "go-package/go", environment={**env, "CC": compiler, "GOOS": "windows" if windows else "darwin", "GOARCH": target["arch"]})
        if "swift" in selected:
            unpack(packages / f"stogas-swift-v{version}.tar.gz", work / "swift")
            qualify_cases("swift", runtime_of("swift", "--version"), ["swift", "test", "--package-path", work / "swift/Stogas", "-j", "4"])
    return checks

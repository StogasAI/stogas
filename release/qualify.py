"""Exercise installed release packages with this release's own test code.

Run through `release.py qualify`, which unpacks and authenticates the source
snapshot recorded by the release before starting this file from it.
"""

import argparse
import json
import os
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

sys.dont_write_bytecode = True
from artifacts import unpack, verify_inventory, verify_source, wheel, write_json
from gate import CASES, METADATA, attempt, read_document
from package_bindings import MAVEN, DOTNET, RUBY

ROOT = Path(__file__).resolve().parents[1]

GO = "golang:1.26.5-bookworm@sha256:53eeac89074db483fdf0ab3be1df32bf6e47562263d2d0d6baa7f26acb4957dd"
PYTHON = "quay.io/pypa/manylinux2014_x86_64@sha256:ffd6d1f11237599748657996b750db6b3a5b724fea5a81cd9ea65add4f45b6c9"
SWIFT = "swift@sha256:9bea530093ffff8cf6c259991715ee843fe4d0f932e612f7f4b79cca6e00db87"
GO_MUSL = "golang:1.26.5-alpine3.23@sha256:622e56dbc11a8cfe87cafa2331e9a201877271cbff918af53d3be315f3da88cc"
MAVEN_MUSL = "maven:3.9.11-amazoncorretto-17-alpine@sha256:2d81965c6bfd4e6789a7b278a2a388d84af2925bacb37a20f2eaf59b22af1619"
DOTNET_MUSL = "mcr.microsoft.com/dotnet/sdk:10.0-alpine3.23@sha256:3f9c03432d664163a90d20e3ed0a3784d0aa82c1b9cbd1a7dd4609fede95669e"
RUBY_MUSL = "ruby:3.4.9-alpine3.23@sha256:5262d250d0f79ce3494377cef4218d983588ef61f857d7387308462a3ec57708"
PYTHON_IMAGES = {
    ("glibc", "amd64"): PYTHON,
    ("glibc", "arm64"): "quay.io/pypa/manylinux2014_aarch64@sha256:9026a55e05e76ad74d9a4e6be814a5abda26cde08b1baa659ea4f7ee16b246e3",
    ("musl", "amd64"): "quay.io/pypa/musllinux_1_2_x86_64@sha256:ff786af69d772d7ac3e318c00a2b682428a352cc822d6175f6a0d4b431c0d44d",
    ("musl", "arm64"): "quay.io/pypa/musllinux_1_2_aarch64@sha256:09c35642d008faa6d43a45809ff068e22f37bba801f7d75faf19431aefed579d",
}


def qualify(packages, platform, output, requested=(), device=None, device_farm=None):
    manifest = read_document(packages / "release-manifest.json")
    version = manifest["version"]

    def verify_inputs():
        manifest_sha256 = verify_inventory(packages, manifest, METADATA & {path.name for path in packages.iterdir()})
        verify_source(ROOT, packages / f"stogas-source-v{version}.tar.gz", manifest["source"]["sha256"], f"stogas-v{version}")
        return manifest_sha256

    manifest_sha256 = verify_inputs()
    if platform not in manifest["targets"]:
        raise ValueError("Requested qualification platform was not built")
    if output.exists():
        raise ValueError("Qualification output already exists")
    targets = json.loads((ROOT / "release/targets.json").read_text())["targets"]
    target = targets.get(platform)
    if platform == "portable":
        from qualify_portable import qualify as runner
        checks = runner(ROOT, packages, version, requested)
    elif target["os"] in {"windows", "macos"}:
        from qualify_desktop import qualify as runner
        checks = runner(ROOT, packages, version, platform, target, requested)
    elif target["os"] == "android":
        from qualify_android import qualify as runner
        checks = runner(ROOT, packages, version, platform, target, requested, device, device_farm)
    elif target["os"] == "ios":
        from qualify_ios import qualify as runner
        checks = runner(ROOT, packages, version, platform, target, requested, device, device_farm)
    else:
        checks = qualify_linux(ROOT, packages, version, platform, target, requested)
    if verify_inputs() != manifest_sha256:
        raise ValueError("Packages changed during qualification")
    failed = [f"{check['package']}/{check['case']}" for check in checks if check["outcome"] != "passed"]
    if failed:
        raise SystemExit("Qualification failed: " + ", ".join(failed))
    write_json(output, {"schema": "stogas.sdk-qualification.v1", "environment": "prod", "manifest_sha256": manifest_sha256, "checks": checks})


def qualify_linux(source, packages, version, platform, target, requested):
    selected = set(requested or target["packages"])
    if not selected <= set(target["packages"]):
        raise ValueError("Requested package is not supported on this platform")
    musl = target["libc"] == "musl"
    python_image = PYTHON_IMAGES[(target["libc"], target["arch"])]
    maven_image, dotnet_image, ruby_image = (MAVEN_MUSL, DOTNET_MUSL, RUBY_MUSL) if musl else (MAVEN, DOTNET, RUBY)
    checks = []
    # Never mount a checkout or a compiler target directory into the consumer.
    with tempfile.TemporaryDirectory(prefix="stogas-consumer-") as temporary:
        work = Path(temporary)
        shutil.copytree(packages, work / "packages")
        shutil.copytree(source / "tests/fixtures", work / "tests/fixtures")
        shutil.copytree(source / "bindings/python/tests", work / "bindings/python/tests")
        shutil.copytree(source / "bindings/java/src/test", work / "java/src/test")
        shutil.copyfile(source / "release/consumers/java/pom.xml", work / "java/pom.xml")
        shutil.copytree(source / "bindings/dotnet/tests", work / "dotnet")
        shutil.copyfile(source / "release/consumers/dotnet/NuGet.Config", work / "dotnet/NuGet.Config")
        shutil.copytree(source / "bindings/ruby/test", work / "ruby")
        archive = f"stogas-v{version}-{platform}.tar.gz"
        unpack(packages / archive, work / "native")
        native = next((work / "native").iterdir())
        shutil.copyfile(source / "release/consumers/native.c", native / "native.c")

        # Setup steps use the network. Offline cases have none; live cases use
        # the production gateways.
        def run(image, arguments, *, directory="/work", case=None, environment=()):
            subprocess.run([
                "docker", "run", "--rm", "--init", "--memory", "4g", "--cpus", "4",
                "--platform", "linux/" + target["arch"], "--user", f"{os.getuid()}:{os.getgid()}",
                "--mount", f"type=bind,source={work},target=/work", "--workdir", directory,
                "--env", "HOME=/work", "--env", "MAVEN_OPTS=-Duser.home=/work",
                "--env", "DOTNET_CLI_HOME=/work", "--env", "GEM_HOME=/work/.gem",
                *(["--network", "none"] if case == "offline" else []),
                *[part for entry in (*environment, *(["STOGAS_LIVE=prod"] if case == "live" else [])) for part in ("--env", entry)],
                image, *arguments,
            ], check=True)

        def qualify_case(package, image, arguments, case, **options):
            outcome = attempt(f"{package}/{case}", lambda: run(image, arguments, case=case, **options))
            checks.append({"platform": platform, "package": package, "case": case, "runtime": image, "outcome": outcome})

        relative_native = "/work/" + native.relative_to(work).as_posix()
        if "native" in selected:
            run(python_image, ["cc", "-Wall", "-Wextra", "-Werror", "native.c", "-L.", "-lstogas_ffi", "-o", "native-consumer"], directory=relative_native, case="offline")
            for case in CASES:
                qualify_case("native", python_image, ["./native-consumer"], case, directory=relative_native, environment=["LD_LIBRARY_PATH=."])
        if "cli" in selected:
            shutil.copyfile(source / "release/consumers/cli.py", work / "cli.py")
            for case in CASES:
                qualify_case("cli", python_image, ["/opt/python/cp310-cp310/bin/python", "-I", "/work/cli.py", relative_native + "/stogas", version, "/work/tests/fixtures"], case)
        if "python" in selected:
            python = "/opt/python/cp310-cp310/bin/python"
            name = wheel([path.name for path in packages.iterdir()], target)
            run(python_image, [python, "-m", "pip", "install", "--no-index", "--target", "/work/python", "/work/packages/" + name], case="offline")
            for case in CASES:
                qualify_case("python", python_image, [python, "-m", "unittest", "discover", "-s", "bindings/python/tests", "-p", "test_package.py", "-v"], case, environment=["PYTHONPATH=/work/python"])
        if "java" in selected:
            run(maven_image, ["mvn", "-B", "-ntp", "org.apache.maven.plugins:maven-install-plugin:3.1.4:install-file", f"-Dfile=/work/packages/stogas-{version}.jar", f"-DpomFile=/work/packages/stogas-{version}.pom"])
            test = ["mvn", "-B", "-ntp", "-f", "java/pom.xml", f"-Dstogas.version={version}", "test"]
            # The live run also downloads the test plugins that the offline run uses.
            qualify_case("java", maven_image, test, "live")
            qualify_case("java", maven_image, ["mvn", "-o", *test[1:]], "offline")
        if "dotnet" in selected:
            run(dotnet_image, ["dotnet", "restore", "dotnet/Consumer.csproj", "--configfile", "dotnet/NuGet.Config"])
            for case in CASES:
                qualify_case("dotnet", dotnet_image, ["dotnet", "run", "--no-restore", "--project", "dotnet/Consumer.csproj"], case)
        if "ruby" in selected:
            gem = f"stogas-{version.replace('-', '.')}-{target['ruby']}.gem"
            run(ruby_image, ["gem", "install", "--no-document", "/work/packages/" + gem])
            run(ruby_image, ["gem", "install", "--no-document", "minitest", "--version", "6.0.6"])
            for case in CASES:
                qualify_case("ruby", ruby_image, ["ruby", "ruby/transport_test.rb"], case)
        if "swift" in selected:
            unpack(packages / f"stogas-swift-v{version}.tar.gz", work / "swift")
            for case in CASES:
                qualify_case("swift", SWIFT, ["swift", "test", "--package-path", "swift/Stogas", "-j", "4"], case)
        if "go" in selected:
            unpack(packages / f"stogas-go-v{version}.tar.gz", work / "go-package")
            shutil.copytree(source / "tests/fixtures", work / "go-package/tests/fixtures")
            go_image = GO
            if musl:
                identity = work / "go-image"
                # The manylinux project supplies the real musl C toolchain;
                # retain Go's official binary distribution unchanged.
                (work / "Dockerfile").write_text(f"FROM {GO_MUSL} AS go\nFROM {python_image}\nCOPY --from=go /usr/local/go /usr/local/go\nENV PATH=/usr/local/go/bin:$PATH\n")
                subprocess.run(["docker", "build", "--platform", "linux/" + target["arch"], "--iidfile", str(identity), str(work)], check=True)
                go_image = identity.read_text().strip()
            for case in CASES:
                qualify_case("go", go_image, ["go", "test", "-count=1", *(["-tags", "musl"] if musl else []), "./..."], case, directory="/work/go-package/go", environment=["CGO_ENABLED=1", "GOWORK=off"])
    return checks


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("packages", type=Path)
    parser.add_argument("--platform", required=True)
    parser.add_argument("--out", type=Path, required=True)
    parser.add_argument("--package", action="append", default=[])
    parser.add_argument("--device")
    parser.add_argument("--device-farm")
    args = parser.parse_args()
    qualify(args.packages.resolve(), args.platform, args.out.resolve(), args.package, args.device, args.device_farm)

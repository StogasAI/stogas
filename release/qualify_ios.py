"""Run native and Swift installed-package consumers through Xcode on iOS."""

import json
import os
import shutil
import subprocess
import sys
import tempfile
import uuid
from pathlib import Path

from artifacts import unpack


def qualify(source, packages, version, platform, target, requested, device):
    if sys.platform != "darwin" or not device:
        raise ValueError("iOS qualification requires macOS and --device with an explicit destination UDID")
    selected = set(requested or target["packages"])
    if not selected or not selected <= {"native", "swift"}:
        raise ValueError("Requested iOS package is unsupported")
    xcode = subprocess.check_output(["xcodebuild", "-version"], text=True).strip()
    if xcode != "Xcode 26.3\nBuild version 17C529":
        raise ValueError("iOS qualification requires Xcode 26.3 (17C529)")
    if subprocess.check_output(["xcodegen", "--version"], text=True).strip() != "Version: 2.46.0":
        raise ValueError("iOS qualification requires XcodeGen 2.46.0")
    simulator = target.get("simulator", False)
    architecture = {"amd64": "x86_64", "arm64": "arm64"}[target["arch"]]
    destination = f"platform={'iOS Simulator' if simulator else 'iOS'},id={device}"
    if not simulator and not os.environ.get("DEVELOPMENT_TEAM"):
        raise ValueError("iOS device qualification requires DEVELOPMENT_TEAM and configured Xcode signing")
    with tempfile.TemporaryDirectory(prefix="stogas-ios-consumer-") as temporary:
        work = Path(temporary)
        shutil.copytree(source / "release/consumers/ios", work / "app")
        app = work / "app"
        unpack(packages / f"stogas-swift-v{version}.tar.gz", app / "Vendor")
        unpack(packages / f"stogas-v{version}-{platform}.tar.gz", work / "native")
        native = next((work / "native").iterdir())
        shutil.copytree(native, app / "Native")
        shutil.copyfile(source / "release/consumers/native.c", app / "Native/native.c")
        identifier = "ai.stogas.consumer.q" + uuid.uuid4().hex
        env = {**os.environ, "STOGAS_CONSUMER_ID": identifier}
        env.pop("STOGAS_NATIVE_STAGING_TEST", None)
        subprocess.run(["xcodegen", "generate", "--spec", "project.yml"], cwd=app, env=env, check=True)
        result = work / "Tests.xcresult"
        tests = {"native": "NativeTests", "swift": "SwiftTests"}
        command = [
            "xcodebuild", "test", "-project", "StogasConsumer.xcodeproj", "-scheme", "StogasConsumer",
            "-destination", destination, "-derivedDataPath", str(work / "DerivedData"), "-resultBundlePath", str(result),
            "-parallel-testing-enabled", "NO", f"ARCHS={architecture}", "ONLY_ACTIVE_ARCH=YES",
            *["-only-testing:" + tests[package] for package in sorted(selected)],
            *(["DEVELOPMENT_TEAM=" + env["DEVELOPMENT_TEAM"]] if not simulator else []),
        ]
        try:
            subprocess.run(command, cwd=app, env=env, check=True)
            summary = json.loads(subprocess.check_output(["xcrun", "xcresulttool", "get", "test-results", "summary", "--path", str(result)], text=True))
            if summary.get("passedTests") != len(selected) or summary.get("totalTestCount") != len(selected) or summary.get("failedTests") != 0 or summary.get("skippedTests") != 0:
                raise ValueError("Xcode did not run and pass every selected installed-package test")
        finally:
            if simulator:
                subprocess.run(["xcrun", "simctl", "uninstall", device, identifier + ".Host"], check=False, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    runtime = json.dumps({"xcode": xcode, "destination": destination, "architecture": architecture}, sort_keys=True)
    return [{"platform": platform, "package": package, "case": "installed-contract", "runtime": runtime, "outcome": "passed"} for package in sorted(selected)]

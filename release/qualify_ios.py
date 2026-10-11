"""Run installed native and Swift consumers in the iOS simulator or on a real iPhone."""

import json
import os
import shutil
import subprocess
import sys
import tempfile
import uuid
from pathlib import Path

from artifacts import unpack
from device_farm import run as run_on_phone
from gate import CASES, attempt


def qualify(source, packages, version, platform, target, requested, device, device_farm):
    simulator = target.get("simulator", False)
    if sys.platform != "darwin" or simulator != bool(device) or simulator == bool(device_farm):
        raise ValueError("iOS qualification requires macOS; simulators need --device with a UDID, device slices --device-farm with a project ARN")
    selected = set(requested or target["packages"])
    if not selected or not selected <= {"native", "swift"}:
        raise ValueError("Requested iOS package is unsupported")
    xcode = subprocess.check_output(["xcodebuild", "-version"], text=True).strip()
    if xcode != "Xcode 26.3\nBuild version 17C529":
        raise ValueError("iOS qualification requires Xcode 26.3 (17C529)")
    if subprocess.check_output(["xcodegen", "--version"], text=True).strip() != "Version: 2.46.0":
        raise ValueError("iOS qualification requires XcodeGen 2.46.0")
    architecture = {"amd64": "x86_64", "arm64": "arm64"}[target["arch"]]
    destination = f"platform=iOS Simulator,id={device}" if simulator else "generic/platform=iOS"
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
        subprocess.run(["xcodegen", "generate", "--spec", "project.yml"], cwd=app, env=env, check=True)
        result = work / "Tests.xcresult"
        tests = {"native": "NativeTests", "swift": "SwiftTests"}
        command = [
            "xcodebuild", "test" if simulator else "build-for-testing", "-project", "StogasConsumer.xcodeproj", "-scheme", "StogasConsumer",
            "-destination", destination, "-derivedDataPath", str(work / "DerivedData"), f"ARCHS={architecture}",
            *["-only-testing:" + tests[package] for package in sorted(selected)],
            *(["-resultBundlePath", str(result), "-parallel-testing-enabled", "NO", "ONLY_ACTIVE_ARCH=YES"] if simulator else ["CODE_SIGNING_ALLOWED=NO"]),
        ]
        if not simulator:
            subprocess.run(command, cwd=app, env=env, check=True)
            return run_on_iphones(device_farm, work, selected, tests, platform, target, xcode)
        try:
            subprocess.run(command, cwd=app, env=env, check=True)
            summary = json.loads(subprocess.check_output(["xcrun", "xcresulttool", "get", "test-results", "summary", "--path", str(result)], text=True))
            if summary.get("passedTests") != len(selected) or summary.get("totalTestCount") != len(selected) or summary.get("failedTests") != 0 or summary.get("skippedTests") != 0:
                raise ValueError("Xcode did not run and pass every selected installed-package test")
        finally:
            subprocess.run(["xcrun", "simctl", "uninstall", device, identifier + ".Host"], check=False, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    runtime = json.dumps({"xcode": xcode, "destination": destination, "architecture": architecture}, sort_keys=True)
    # Each package's single test runs its offline checks, then the live ones.
    return [{"platform": platform, "package": package, "case": case, "runtime": runtime, "outcome": "passed"} for package in sorted(selected) for case in CASES]


def run_on_iphones(project, work, selected, tests, platform, target, xcode):
    """Device Farm signs the unsigned test build and runs each test bundle in its host app."""
    host = work / "DerivedData/Build/Products/Debug-iphoneos/Host.app"
    (work / "Payload").mkdir()
    shutil.copytree(host, work / "Payload/Host.app", symlinks=True)
    subprocess.run(["ditto", "-c", "-k", "--keepParent", str(work / "Payload"), str(work / "Host.ipa")], check=True)
    checks = []
    for package in sorted(selected):
        bundle = host / f"PlugIns/{tests[package]}.xctest"
        archive = work / f"{tests[package]}.xctest.zip"
        subprocess.run(["ditto", "-c", "-k", "--keepParent", str(bundle), str(archive)], check=True)
        test = {"native": "InstalledNativeTests/testNativePackage", "swift": "InstalledSwiftTests/testSwiftPackage"}[package]
        phone = {}
        outcome = attempt(package, lambda: phone.update(run_on_phone(project, platform="IOS", os_major=target["minimum"].split(".")[0], architecture="arm64", app=work / "Host.ipa", app_kind="IOS_APP", tests=archive, test_kind="XCTEST_TEST_PACKAGE", test_type="XCTEST", expected=[test])))
        # One test covers both cases, so its outcome applies to each.
        checks.extend({"platform": platform, "package": package, "case": case, "runtime": json.dumps({"xcode": xcode, **phone}, sort_keys=True), "outcome": outcome} for case in CASES)
    return checks

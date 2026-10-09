"""Test packaged native libraries and a Maven AAR on an explicit Android device."""

import json
import os
import re
import shutil
import subprocess
import tempfile
import uuid
from pathlib import Path

from artifacts import unpack


def qualify(source, packages, version, platform, target, requested, device):
    if not device:
        raise ValueError("Android qualification requires --device with an adb serial")
    selected = set(requested or target["packages"])
    if not selected <= set(target["packages"]):
        raise ValueError("Requested Android package is unsupported")
    adb = ["adb", "-s", device]
    def shell(*arguments):
        return subprocess.check_output([*adb, "shell", *arguments], text=True).strip()
    if subprocess.check_output([*adb, "get-state"], text=True).strip() != "device":
        raise ValueError("Android device is not ready")
    if target["android_abi"] not in shell("getprop", "ro.product.cpu.abilist").split(","):
        raise ValueError("Android device does not support the requested ABI")
    api = int(shell("getprop", "ro.build.version.sdk"))
    if api < int(target["minimum"]):
        raise ValueError("Android device is below the SDK minimum")
    page_size = int(shell("getconf", "PAGE_SIZE"))
    case = "installed-contract-16k" if page_size == 16384 else "installed-contract"
    runtime = json.dumps({"fingerprint": shell("getprop", "ro.build.fingerprint"), "abi": target["android_abi"], "api": api, "page_size": page_size}, sort_keys=True)
    checks = []
    with tempfile.TemporaryDirectory(prefix="stogas-android-consumer-") as temporary:
        work = Path(temporary)
        def image(recipe, stage=None):
            identity = work / (recipe + ".image")
            subprocess.run(["docker", "build", *(["--target", stage] if stage else []), "--iidfile", str(identity), "--file", str(source / "release" / recipe), str(source / "release")], check=True)
            return identity.read_text().strip()
        def run(builder, arguments):
            subprocess.run(["docker", "run", "--rm", "--init", "--memory", "4g", "--cpus", "4", "--user", f"{os.getuid()}:{os.getgid()}", "--mount", f"type=bind,source={work},target=/build", "--workdir", "/build", "--env", "HOME=/build", "--entrypoint", arguments[0], builder, *arguments[1:]], check=True)
        if "native" in selected:
            unpack(packages / f"stogas-v{version}-{platform}.tar.gz", work / "native")
            native = next((work / "native").iterdir())
            shutil.copyfile(source / "release/consumers/native.c", native / "native.c")
            directory = "/build/" + native.relative_to(work).as_posix()
            compiler = {"amd64": "x86_64-linux-android", "arm64": "aarch64-linux-android"}[target["arch"]]
            run(image("Dockerfile", "android"), [f"/opt/android-ndk-r30/toolchains/llvm/prebuilt/linux-x86_64/bin/{compiler}{target['minimum']}-clang", "-Wall", "-Wextra", "-Werror", directory + "/native.c", "-L" + directory, "-lstogas_verifier_ffi", "-o", directory + "/native-consumer"])
            remote = "/data/local/tmp/stogas-" + uuid.uuid4().hex
            shell("mkdir", remote)
            try:
                for name in ("native-consumer", "libstogas_verifier_ffi.so"):
                    subprocess.run([*adb, "push", str(native / name), remote + "/" + name], check=True)
                shell("chmod", "700", remote + "/native-consumer")
                shell("env", "LD_LIBRARY_PATH=" + remote, remote + "/native-consumer")
            finally:
                shell("rm", "-rf", remote)
            checks.append({"platform": platform, "package": "native", "case": case, "runtime": runtime, "outcome": "passed"})
        if "android" in selected:
            application = "ai.stogas.consumer.q" + uuid.uuid4().hex
            shutil.copytree(source / "release/consumers/android", work / "app")
            repository = work / "app/repository/ai/stogas/stogas-android" / version
            repository.mkdir(parents=True)
            for suffix in (".aar", ".pom", ".module", "-sources.jar", "-javadoc.jar"):
                name = f"stogas-android-{version}{suffix}"
                shutil.copyfile(packages / name, repository / name)
            builder = image("android.Dockerfile")
            run(builder, ["gradle", "--no-daemon", "--project-dir", "app", f"-PsdkVersion={version}", f"-PtestAbi={target['android_abi']}", f"-PtestApplicationId={application}", "assembleDebug", "assembleDebugAndroidTest"])
            run(builder, ["/opt/android-sdk/build-tools/36.0.0/zipalign", "-c", "-P", "16", "4", "/build/app/build/outputs/apk/debug/stogas-release-consumer-debug.apk"])
            try:
                for path in ("apk/debug/stogas-release-consumer-debug.apk", "apk/androidTest/debug/stogas-release-consumer-debug-androidTest.apk"):
                    subprocess.run([*adb, "install", "-r", "-t", str(work / "app/build/outputs" / path)], check=True)
                result = shell("am", "instrument", "-w", application + ".test/androidx.test.runner.AndroidJUnitRunner")
                print(result, flush=True)
                if not re.search(r"^OK \(2 tests\)$", result, re.MULTILINE):
                    raise ValueError("Installed Android package tests did not pass")
            finally:
                for name in (application + ".test", application):
                    subprocess.run([*adb, "uninstall", name], check=False, stdout=subprocess.DEVNULL)
            checks.append({"platform": platform, "package": "android", "case": case, "runtime": runtime, "outcome": "passed"})
    return checks

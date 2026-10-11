"""Run one installed-package test suite on a real phone in AWS Device Farm.

The AWS CLI supplies credentials from its environment. Each phone runs the
oldest operating system a package supports, because simulators and emulators
already cover the newest ones.
"""

import json
import subprocess
import time
import urllib.request

# Device Farm exists only in us-west-2.
REGION = "us-west-2"


def aws(*arguments):
    return json.loads(subprocess.check_output(["aws", "devicefarm", *arguments, "--region", REGION, "--output", "json"]))


def upload(project, path, kind):
    created = aws("create-upload", "--project-arn", project, "--name", path.name, "--type", kind, "--content-type", "application/octet-stream")["upload"]
    request = urllib.request.Request(created["url"], data=path.read_bytes(), method="PUT", headers={"Content-Type": "application/octet-stream"})
    with urllib.request.urlopen(request, timeout=600):
        pass
    while (status := aws("get-upload", "--arn", created["arn"])["upload"])["status"] in {"INITIALIZED", "PROCESSING"}:
        time.sleep(5)
    if status["status"] != "SUCCEEDED":
        raise ValueError(f"Device Farm rejected {path.name}: {status.get('metadata') or status.get('message')}")
    return created["arn"]


def results(arn):
    """Return a completed run's jobs and test results, printing the output of every test that did not pass."""
    jobs = aws("list-jobs", "--arn", arn)["jobs"]
    outcomes = {}
    for job in jobs:
        for suite in aws("list-suites", "--arn", job["arn"])["suites"]:
            for test in aws("list-tests", "--arn", suite["arn"])["tests"]:
                outcomes[f"{suite['name']}/{test['name']}"] = test["result"]
                if test["result"] == "PASSED":
                    continue
                # Device Farm's result often omits the reason, for example when a test exits.
                for artifact in aws("list-artifacts", "--arn", test["arn"], "--type", "FILE")["artifacts"]:
                    if artifact["type"] in {"AUTOMATION_OUTPUT", "INSTRUMENTATION_OUTPUT"}:
                        with urllib.request.urlopen(artifact["url"], timeout=60) as response:
                            print(response.read(1024 * 1024).decode(errors="replace"), flush=True)
    return jobs, outcomes


def run(project, *, platform, os_major, architecture, app, app_kind, tests, test_kind, test_type, expected):
    """Run `tests` against `app` on one phone and require exactly `expected` to pass."""
    filters = [
        {"attribute": "PLATFORM", "operator": "EQUALS", "values": [platform]},
        {"attribute": "FORM_FACTOR", "operator": "EQUALS", "values": ["PHONE"]},
        {"attribute": "AVAILABILITY", "operator": "EQUALS", "values": ["HIGHLY_AVAILABLE"]},
        {"attribute": "FLEET_TYPE", "operator": "EQUALS", "values": ["PUBLIC"]},
    ]
    phones = [device["arn"] for device in aws("list-devices", "--filters", json.dumps(filters))["devices"] if device["os"].split(".")[0] == os_major and device["cpu"]["architecture"] == architecture]
    if not phones:
        raise ValueError(f"Device Farm has no available {platform} {os_major} {architecture} phone")
    scheduled = aws(
        "schedule-run", "--project-arn", project, "--name", tests.name,
        "--app-arn", upload(project, app, app_kind),
        "--test", json.dumps({"type": test_type, "testPackageArn": upload(project, tests, test_kind)}),
        "--device-selection-configuration", json.dumps({"filters": [{"attribute": "ARN", "operator": "IN", "values": phones}], "maxDevices": 1}),
        "--execution-configuration", json.dumps({"jobTimeoutMinutes": 20, "videoCapture": False}),
    )["run"]
    try:
        while (result := aws("get-run", "--arn", scheduled["arn"])["run"])["status"] != "COMPLETED":
            time.sleep(15)
    except BaseException:
        aws("stop-run", "--arn", scheduled["arn"])
        raise
    jobs, outcomes = results(scheduled["arn"])
    print(json.dumps({"run": scheduled["arn"], "result": result["result"], "tests": outcomes}, indent=1), flush=True)
    passed = {name for name, outcome in outcomes.items() if outcome == "PASSED"}
    if result["result"] != "PASSED" or len(jobs) != 1 or not set(expected) <= passed:
        raise ValueError(f"Device Farm did not pass every installed-package test: {result.get('message', result['result'])}")
    device = jobs[0]["device"]
    return {"device": device["name"], "os": device["os"], "architecture": device["cpu"]["architecture"], "device_farm": device["arn"]}

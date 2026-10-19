"""Exercise an installed Stogas CLI: cli.py STOGAS VERSION FIXTURES.

Without STOGAS_LIVE, test the production binary offline. With
STOGAS_LIVE=staging|prod, probe that environment's gateways and verify its
current evidence from both origins.
"""

import json
import os
import subprocess
import sys
import tempfile
import urllib.request
from pathlib import Path

ORIGINS = {
    "prod": ("https://evidence.stogas.ai", "https://evidence2.stogas.ai"),
    "staging": ("https://evidence-staging.stogas.ai", "https://evidence2-staging.stogas.ai"),
}


def run(cli, *arguments, accepted=True):
    result = subprocess.run([cli, *arguments], capture_output=True, text=True, timeout=60)
    if (result.returncode == 0) != accepted:
        raise SystemExit(f"stogas {arguments[0]} exited {result.returncode}: {(result.stderr or result.stdout).strip()}")
    return result.stdout


def offline(cli, version, fixtures, work):
    if run(cli, "--version").split() != ["stogas", version]:
        raise SystemExit("The CLI reported a different version")
    # Staging evidence fails only on its authority at its own verification time.
    fixture = json.loads((fixtures / "hardware-session-v1.json").read_text())
    evidence = work / "staging-evidence.json"
    evidence.write_text(json.dumps(fixture["evidence"]))
    run(cli, "verify", "--environment", "staging", str(evidence), accepted=False)
    run(cli, "verify", "--now-unix-ms", str(fixture["verified_at_ms"]), str(evidence), accepted=False)
    key = work / "organization.key"
    key_id = run(cli, "encryption-key", "--output", str(key)).strip()
    plaintext = work / "plugins.json"
    plaintext.write_text('{"plugins":[]}')
    envelope = work / "plugins.sealed"
    run(cli, "encrypt", "--key-file", str(key), "--organization", "org_release", "--purpose", "plugins", "--input", str(plaintext), "--output", str(envelope))
    if json.loads(envelope.read_text())["keyId"] != key_id:
        raise SystemExit("The encrypted envelope names a different key")
    (work / "empty").mkdir()
    run(cli, "verify-release", str(work / "empty"), accepted=False)


def live(cli, environment, work):
    for security in ("tls", "e2ee"):
        run(cli, "probe", "--environment", environment, "--security", security)
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))
    for index, origin in enumerate(ORIGINS[environment]):
        evidence = work / f"current-{index}.json"
        with opener.open(f"{origin}/evidence/latest.json", timeout=30) as response:
            evidence.write_bytes(response.read())
        run(cli, "verify", "--environment", environment, "--json", str(evidence))


if __name__ == "__main__":
    cli, version, fixtures = sys.argv[1], sys.argv[2], Path(sys.argv[3])
    environment = os.environ.get("STOGAS_LIVE")
    if environment not in (None, *ORIGINS):
        raise SystemExit("STOGAS_LIVE must be staging or prod")
    with tempfile.TemporaryDirectory(prefix="stogas-cli-") as temporary:
        if environment:
            live(cli, environment, Path(temporary))
        else:
            offline(cli, version, fixtures, Path(temporary))
    print("Installed CLI passed")

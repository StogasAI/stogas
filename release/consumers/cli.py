"""Exercise an installed Stogas CLI: cli.py STOGAS VERSION FIXTURES.

Without STOGAS_LIVE, test the production binary offline. With
STOGAS_LIVE=staging|prod, probe that environment's gateways and verify its
current evidence from both origins.
"""

import json
import os
import queue
import socket
import subprocess
import sys
import tempfile
import threading
import urllib.error
import urllib.parse
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
    run(cli, "encrypt", "--key-file", str(key), "--organization", "0b4f1e2a-3c5d-4e6f-8a7b-9c0d1e2f3a4b", "--purpose", "plugins", "--input", str(plaintext), "--output", str(envelope))
    if json.loads(envelope.read_text())["keyId"] != key_id:
        raise SystemExit("The encrypted envelope names a different key")
    (work / "empty").mkdir()
    run(cli, "verify-release", str(work / "empty"), accepted=False)
    # Without evidence, serve exits without advertising an endpoint. The closed proxy port makes
    # this hold on runners that have a network.
    if "OpenAI base URL" in run(cli, "--proxy", "http://127.0.0.1:9", "serve", "--listen", "127.0.0.1:0", accepted=False):
        raise SystemExit("serve advertised an endpoint without verified evidence")


def serve(cli, environment, security):
    """The CLI's local endpoint answers through the gateway, then closes when its parent's pipe
    does, as an application that starts it relies on."""
    process = subprocess.Popen(
        [cli, "serve", "--environment", environment, "--security", security, "--listen", "127.0.0.1:0", "--exit-on-stdin-close"],
        stdin=subprocess.PIPE, stdout=subprocess.PIPE, text=True,
    )
    try:
        lines = queue.Queue()
        threading.Thread(target=lambda: [lines.put(line) for line in process.stdout], daemon=True).start()
        try:
            line = lines.get(timeout=60)
        except queue.Empty:
            raise SystemExit(f"serve --security {security} named no endpoint within 60 seconds") from None
        if not line.startswith("OpenAI base URL: "):
            raise SystemExit(f"serve --security {security} began with {line.strip()!r}")
        base = line.removeprefix("OpenAI base URL: ").strip()
        request = urllib.request.Request(
            f"{base}/chat/completions", method="POST",
            data=b'{"model":"stogas-status-monitor","messages":[{"role":"user","content":"ping"}]}',
            headers={"Authorization": "Bearer stogas-status-monitor-uncredentialed", "Content-Type": "application/json"},
        )
        try:
            urllib.request.build_opener(urllib.request.ProxyHandler({})).open(request, timeout=60).close()
            raise SystemExit(f"serve --security {security} accepted an invalid key")
        except urllib.error.HTTPError as error:
            with error:
                if error.code != 401 or json.loads(error.read())["error"]["type"] != "authentication_error":
                    raise SystemExit(f"serve --security {security} answered an invalid key with HTTP {error.code}") from None
        process.stdin.close()
        if process.wait(timeout=10) != 0:
            raise SystemExit(f"serve --security {security} exited {process.returncode} when its stdin closed")
        try:
            socket.create_connection(("127.0.0.1", urllib.parse.urlsplit(base).port), timeout=5).close()
        except ConnectionRefusedError:
            return
        raise SystemExit(f"serve --security {security} kept listening after it exited")
    finally:
        process.kill()
        process.wait()


def live(cli, environment, work):
    for security in ("tls", "e2ee"):
        run(cli, "probe", "--environment", environment, "--security", security)
        serve(cli, environment, security)
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

"""Run the symbolic models and deliberately broken controls with ProVerif 2.05.

Usage: python3 tests/security/run-models.py /path/to/proverif
No solver is downloaded, and nothing is added to runtime packages.
"""
import pathlib
import re
import subprocess
import sys
import tempfile

base = pathlib.Path(__file__).parent
setup = (base / "setup.pv").read_text()
recovery = (base / "recovery.pv").read_text()
records = (base / "records.pv").read_text()
variants = {
    "records-live-chain-capture": (records, [True, False, False]),
    "records-initial-retained": (records.replace("(* RETAIN_INITIAL *)", "out(net,initial);"), [False, False, False]),
    "setup-classical-broken": (setup, [True, True]),
    "setup-both-broken": (setup.replace("(* BREAK_BOTH *)", "out(net,pq);"), [False, True]),
    "setup-attestation-broken": (setup.replace("out(net,public(attestation));", "out(net,(public(attestation),attestation));"), [False, False]),
    "setup-exporter-alias": (setup.replace("confirm(exporter,t)", "root(exporter,t)"), [False, True]),
    "setup-unbound-ratchet": (setup.replace("prefix(sid,expiry,ec,ep,ratchet)", "prefix(sid,expiry,ec,ep,boot)").replace("prefix(sid,idle,ec,ep,ratchet)", "prefix(sid,idle,ec,ep,boot)").replace("event accepted((h,p,boot),key)", "event accepted((h,p,boot,ratchet),key)").replace("event issued((h,p,boot),key)", "event issued((h,p,boot,ratchet),key)"), [True, False]),
    "recovery": (recovery, [False, True, True]),
    "recovery-classical-broken": (recovery.replace("(* BREAK_CLASSICAL *)", "out(net,clientdh);"), [False, True, True]),
    "recovery-pq-broken": (recovery.replace("(* BREAK_PQ *)", "out(net,clientkem);"), [False, True, True]),
    "recovery-both-broken": (recovery.replace("(* BREAK_CLASSICAL *)", "out(net,clientdh);").replace("(* BREAK_PQ *)", "out(net,clientkem);"), [False, False, False]),
    "recovery-old-message-retained": (recovery.replace("out(net,nextchain(chain2))", "out(net,chain2)"), [False, False, False]),
}
with tempfile.TemporaryDirectory(prefix="stogas-models-") as directory:
    for name, (source, expected) in variants.items():
        path = pathlib.Path(directory) / f"{name}.pv"
        path.write_text(source)
        result = subprocess.run([sys.argv[1], str(path)], capture_output=True, text=True, timeout=120)
        actual = re.findall(r"^RESULT .* is (true|false)\.$", result.stdout, re.MULTILINE)
        if result.returncode or actual != [str(value).lower() for value in expected]:
            print(result.stdout, result.stderr)
            raise SystemExit(f"{name}: unexpected proof result {actual}, wanted {expected}")
        print(f"{name}: {', '.join(actual)}")

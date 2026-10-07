"""Run a documented CLI consumer against local HTTP/SSE failure fixtures.

Runs each case directly and through the real Rust E2EE record transport. The
encrypted peer uses synthetic setup; hardware appraisal is tested separately.
"""
import json
from contextlib import contextmanager, ExitStack
from itertools import product
from pathlib import Path
from typing import NamedTuple
import queue
import re
import tempfile
import time
import os
import signal
import subprocess
import sys
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

def encrypted_fixture_binary(*, release=False):
    root = Path(__file__).resolve().parents[1]
    build = subprocess.run(
        ["cargo", "test", "--locked", "-p", "stogas", "--lib", "--no-run", "--message-format=json"] + (["--release"] if release else []),
        cwd=root, capture_output=True, text=True, check=True,
    )
    for line in build.stdout.splitlines():
        artifact = json.loads(line)
        if (artifact.get("reason") == "compiler-artifact"
                and artifact.get("target", {}).get("name") == "stogas"
                and artifact.get("target", {}).get("kind") == ["lib"]
                and artifact.get("executable")):
            return artifact["executable"]
    raise RuntimeError("Rust encrypted HTTP fixture binary was not built")


class EncryptedProxy(NamedTuple):
    base_url: str
    process: subprocess.Popen


@contextmanager
def encrypted_proxy(binary, upstream):
    with tempfile.TemporaryFile(mode="w+") as errors:
        with subprocess.Popen(
            [binary, "encrypted_http_client_fixture", "--nocapture", "--test-threads=1"],
            env=dict(os.environ, STOGAS_HTTP_TEST_UPSTREAM=upstream),
            stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=errors, text=True,
        ) as process:
            ready = queue.Queue()
            def read_output():
                for line in process.stdout:
                    match = re.search(r"STOGAS_HTTP_TEST_BASE_URL=(http://[^\s]+)", line)
                    if match:
                        ready.put(match[1])
                ready.put(None)
            reader = threading.Thread(target=read_output, daemon=True)
            reader.start()
            try:
                base_url = ready.get(timeout=30)
                assert base_url and re.fullmatch(r"http://127\.0\.0\.1:[0-9]+/[0-9a-f]{64}/v1", base_url), "invalid encrypted fixture URL"
                yield EncryptedProxy(base_url, process)
            except BaseException:
                errors.seek(0)
                print(errors.read(), file=sys.stderr)
                raise
            finally:
                process.stdin.close()
                try:
                    process.wait(timeout=5)
                except subprocess.TimeoutExpired:
                    process.kill()
                    process.wait()
                reader.join(timeout=2)
                if process.returncode:
                    errors.seek(0)
                    raise RuntimeError(f"encrypted fixture failed: {errors.read()}")


def main():
    command = sys.argv[1:]
    transports = ["http", "e2ee"]
    if command[:1] == ["--transport"]:
        transport = command[1]
        assert transport in transports, "--transport must be http or e2ee"
        transports = [transport]
        command = command[2:]
    typed_status = command[:1] == ["--typed-status"]
    if typed_status:
        command = command[1:]
    cancel = command[:1] == ["--cancel"]
    if cancel:
        command = command[1:]
    unary = command[:1] == ["--unary"]
    if unary:
        command = command[1:]
    framing = command[:1] == ["--sse-framing"]
    if framing:
        command = command[1:]
    if not command:
        raise SystemExit("usage: python check_http_client.py [--transport http|e2ee] [--unary | --sse-framing | --cancel] COMMAND [ARGS...]")

    scenarios = ["success", "quota", "unavailable", "delayed_quota", "disconnected", "stream_error", "truncated", "truncated_chunk"]
    if unary:
        scenarios = ["success", "quota", "unavailable", "delayed_quota", "disconnected", "truncated"]
    if framing:
        scenarios += ["success_crlf", "success_cr", "success_multiline", "malformed", "trailing_json", "missing_terminal"]
    if cancel:
        scenarios = ["cancelled_before_headers", "cancelled"]
    binary = encrypted_fixture_binary() if "e2ee" in transports else None
    for transport, scenario in product(transports, scenarios):
        calls = []
        started, closed = threading.Event(), threading.Event()

        class Handler(BaseHTTPRequestHandler):
            protocol_version = "HTTP/1.1"

            def log_message(self, *_):
                pass

            def do_POST(self):
                if self.headers.get("Transfer-Encoding", "").lower() == "chunked":
                    body = bytearray()
                    while True:
                        size = int(self.rfile.readline().split(b";", 1)[0], 16)
                        assert len(body) + size <= 1024 * 1024
                        if not size:
                            assert self.rfile.readline() == b"\r\n"
                            break
                        body.extend(self.rfile.read(size))
                        assert self.rfile.read(2) == b"\r\n"
                else:
                    body = self.rfile.read(int(self.headers["Content-Length"]))
                calls.append((self.path, self.headers["Authorization"], json.loads(body)))
                if scenario == "cancelled_before_headers":
                    started.set()
                    self.connection.settimeout(10)
                    if not self.rfile.read(1):
                        closed.set()
                    self.close_connection = True
                    return
                if scenario == "disconnected":
                    # The application request arrived, but no response bytes did. Do not replay it.
                    self.close_connection = True
                    return
                responses = self.path.endswith("/responses")
                chunk = json.dumps({"type": "response.output_text.delta", "delta": "Hello"} if responses else
                                   {"id": "example", "object": "chat.completion.chunk", "created": 1,
                                    "model": "example", "choices": [{"index": 0, "delta": {"content": "Hello"}, "finish_reason": None}]})
                prefix = f": STOGAS PROCESSING\n\ndata: {chunk}\n\n".encode()
                if scenario in ("quota", "unavailable", "delayed_quota"):
                    if scenario == "delayed_quota":
                        time.sleep(0.1)
                    self.send_response(503 if scenario == "unavailable" else 429)
                    self.send_header("Retry-After", "0")
                    data = b'{"error":{"message":"unavailable","type":"provider_unavailable"}}'
                    self.send_header("Content-Type", "application/json")
                else:
                    self.send_response(200)
                    if unary:
                        data = json.dumps({"id": "example", "object": "chat.completion", "created": 1,
                                           "model": "example", "choices": [{"index": 0,
                                           "message": {"role": "assistant", "content": "Hello"},
                                           "finish_reason": "stop"}]}).encode()
                    elif scenario == "stream_error":
                        data = prefix + b'data: {"error":{"message":"provider disconnected","type":"provider_unavailable","code":"provider_unavailable"},"choices":[{"index":0,"delta":{},"finish_reason":"error"}]}\n\ndata: [DONE]\n\n'
                    else:
                        terminal = (b'event: response.completed\ndata: {"type":"response.completed","response":{"id":"example","status":"completed"}}\n\n'
                                    if responses else b"data: [DONE]\n\n")
                        data = prefix + (terminal if scenario.startswith("success") else b"")
                        if scenario == "success_crlf":
                            data = data.replace(b"\n", b"\r\n")
                        elif scenario == "success_cr":
                            data = data.replace(b"\n", b"\r")
                        elif scenario == "success_multiline":
                            data = data.replace(b', "', b',\ndata: "')
                        elif scenario == "malformed":
                            data = prefix + b"data: {broken}\n\n" + terminal
                        elif scenario == "trailing_json":
                            data = prefix + b"data: {} unparsed\n\n" + terminal
                    self.send_header("Content-Type", "application/json" if unary else "text/event-stream")
                if scenario in ("truncated_chunk", "cancelled"):
                    self.send_header("Transfer-Encoding", "chunked")
                    # The local verifier proxy aborts a failed stream without the final HTTP chunk.
                    data = f"{len(data):x}\r\n".encode() + data + b"\r\n"
                else:
                    self.send_header("Content-Length", str(len(data) + (100 if scenario == "truncated" else 0)))
                self.send_header("Connection", "close")
                self.end_headers()
                try:
                    self.wfile.write(data)
                    self.wfile.flush()
                    if scenario == "cancelled":
                        started.set()
                        self.connection.settimeout(10)
                        if not self.rfile.read(1):
                            closed.set()
                except BrokenPipeError:
                    pass
                self.close_connection = True

        server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        try:
            with ExitStack() as stack:
                upstream = f"http://127.0.0.1:{server.server_port}/cap"
                base_url = (stack.enter_context(encrypted_proxy(binary, upstream)).base_url
                            if transport == "e2ee" else f"{upstream}/v1")
                environment = dict(os.environ, STOGAS_BASE_URL=base_url,
                                   STOGAS_API_KEY="test-key", STOGAS_MODEL="example")
                if cancel:
                    with subprocess.Popen(command, env=environment, stdout=subprocess.PIPE,
                                          stderr=subprocess.PIPE, text=True) as process:
                        try:
                            assert started.wait(20), "client never started its request"
                            process.send_signal(signal.SIGINT)
                            stdout, stderr = process.communicate(timeout=8)
                            result = subprocess.CompletedProcess(command, process.returncode, stdout, stderr)
                            assert closed.wait(2), "cancelled client left its request open"
                        finally:
                            if process.poll() is None:
                                process.kill()
                                process.wait()
                else:
                    result = subprocess.run(command, env=environment, capture_output=True, text=True, timeout=20)
                assert len(calls) == 1, (scenario, "unexpected dispatch count", len(calls), result.stderr)
                assert calls[0][0] in ("/cap/v1/chat/completions", "/cap/v1/responses"), calls[0][0]
                assert calls[0][1] == "Bearer test-key"
                assert calls[0][2]["model"] == "example"
                assert calls[0][2].get("stream", False) is (not unary)
                if typed_status and scenario in ("quota", "unavailable", "delayed_quota"):
                    expected = 503 if scenario == "unavailable" else 429
                    assert f"HTTP_STATUS={expected}" in result.stderr, (scenario, result.stderr)
                # The gateway emits canonical LF framing. Its encrypted completion
                # guard rejects noncanonical terminal frames; plain HTTP consumers
                # separately exercise the wider SSE line-ending grammar.
                canonical = scenario not in ("success_crlf", "success_cr")
                if scenario.startswith("success") and (transport == "http" or canonical):
                    assert result.returncode == 0 and "Hello" in result.stdout, (scenario, result.returncode, result.stderr)
                else:
                    assert result.returncode != 0, (scenario, "client reported success", result.stdout)
                print(transport, scenario, "passed", flush=True)
        finally:
            server.shutdown()
            server.server_close()
            thread.join()


if __name__ == "__main__":
    main()

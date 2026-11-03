"""Tests against the installed wheel. Only STOGAS_LIVE tests use the network."""

import json
import os
import unittest
import urllib.error
import urllib.parse
import urllib.request
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

from stogas import (
    EvidenceSnapshot,
    EvidenceVerifier,
    StreamContent,
    Transport,
    VerificationError,
    VerifiedBoot,
    request_digest,
    response_digest,
)

# Local offline trust configuration, never accepted by the managed transport.
_root = json.loads((Path(__file__).resolve().parents[3] / "tests/fixtures/hardware-session-v1.json").read_text())["root"]
ROOT = {"root": _root}
SCOPE = {"first_indexes": {"log2025-1.rekor.sigstore.dev": 1}, "opened_from": "2026-10-31T00:00:00Z"}


class PackageTests(unittest.TestCase):
    def test_malformed_evidence_fails_closed(self):
        verifier = EvidenceVerifier(**ROOT)
        for method in (verifier.refresh, verifier.verify_evidence_archive):
            with self.subTest(method=method.__name__):
                with self.assertRaises(VerificationError) as caught:
                    method(b'{"body":')
                self.assertEqual(caught.exception.code, "invalid_evidence")
        # A rejected candidate cannot leave a forged snapshot behind.
        with self.assertRaises(VerificationError):
            verifier.refresh(b'{}')
        with self.assertRaises(VerificationError):
            verifier.verify_boot_archive(b'{}', b'{}')

    def test_content_digests_hold_meaning_and_refuse_what_a_receipt_cannot(self):
        self.assertEqual(len(request_digest(b'{"model":"m"}')), 64)
        # Whitespace, key order and the customer's keys are not part of the request.
        self.assertEqual(
            request_digest(b'{ "b": 1, "a": [1.0, "x"], "encryption_keys": {"default": "k"} }'),
            request_digest(b'{"a":[1,"x"],"b":1}'),
        )
        self.assertEqual(response_digest(b'{"id":"r","stogas":{"receipt":{}}}'), response_digest(b'{"id":"r"}'))
        for body, code in (
            (b'{"seed":9007199254740993}', "inexact_integer"),
            (b"[]", "invalid_content"),
            (b'{"a":1,"a":2}', "invalid_content"),
        ):
            with self.subTest(body=body):
                with self.assertRaises(VerificationError) as caught:
                    request_digest(body)
                self.assertEqual(caught.exception.code, code)

    def test_a_stream_reads_into_the_response_its_receipt_signs(self):
        chunk = lambda text: (
            'data: {"object":"chat.completion.chunk","choices":[{"index":0,"delta":{"content":"%s"}}]}\n\n' % text
        ).encode()
        reader = StreamContent()
        for event in (b": STOGAS PROCESSING\n\n", chunk("Hel"), chunk("lo"), b'data: [DONE]\n\n'):
            reader.push(event)
        self.assertEqual(
            reader.digest(),
            response_digest(b'{"object":"chat.completion","choices":[{"index":0,"message":{"content":"Hello"}}]}'),
        )
        with self.assertRaises(ValueError):
            reader.digest()
        reader = StreamContent()
        with self.assertRaises(VerificationError) as caught:
            reader.push(b'data: {"object":"chat.completion.chunk","created":9007199254740993}\n\n')
        self.assertEqual(caught.exception.code, "inexact_integer")
        with self.assertRaises(ValueError):
            reader.push(chunk("after"))

    def test_offline_authority_is_explicit(self):
        for options in (
            {"environment": "unknown", **ROOT},
            {"root": {"key_id": "partial"}},
            {"root": {"key_id": _root["key_id"], "public_key": _root["public_key"]}},
            {"root": {**_root, "key_id": "invalid", "public_key": "bad-key"}},
            {"root": {**_root, "rekor_public_key": "bad-key"}},
            {"root": {**_root, "unknown": True}},
            {"root": json.dumps(_root)},
            # The scope reaches the core, which rejects an invalid one.
            {"root": {**_root, "rekor_v2": {**SCOPE, "opened_from": "2026-10-31"}}},
            {"root": {**_root, "rekor_v2": {**SCOPE, "first_indexes": {"Log.Example": 1}}}},
            {"root": {**_root, "rekor_v2": {"first_indexes": {}}}},
        ):
            with self.subTest(options=options), self.assertRaises(ValueError):
                EvidenceVerifier(**options)

    def test_root_document_keeps_its_rekor_v2_scope(self):
        EvidenceVerifier(root={**_root, "rekor_v2": SCOPE})

    def test_verified_values_cannot_be_fabricated(self):
        for value in (EvidenceSnapshot, VerifiedBoot):
            with self.subTest(value=value), self.assertRaises(TypeError):
                value()

    def test_evidence_requires_immutable_bytes(self):
        verifier = EvidenceVerifier(**ROOT)
        for value in (bytearray(b'{}'), memoryview(b'{}'), '{}'):
            with self.subTest(value=type(value)), self.assertRaises(TypeError):
                verifier.refresh(value)

    def test_invalid_transport_options_fail_before_acquisition(self):
        for options in (
            {"environment": "unknown"},
            {"security": "both"},
            {"max_connections": 0},
            {"base_url": "http://api.example"},
            {"base_url": "https://key:secret@api.example"},
            {"base_url": "https://api.example/v1"},
        ):
            with self.subTest(options=options), self.assertRaises(ValueError):
                Transport(**options)

    def test_proxy_and_onion_reach_the_native_transport(self):
        for options, message in (
            ({"proxy": "socks5://127.0.0.1:9050"}, "use socks5h://"),
            ({"proxy": "socks5h://127.0.0.1"}, "needs a host and a port"),
            ({"onion": True}, "onion needs a proxy"),
            ({"proxy": "socks5://127.0.0.1:9050", "onion": True}, "use socks5h://"),
        ):
            with self.subTest(options=options), self.assertRaisesRegex(ValueError, message):
                Transport(**options)

    def test_removed_options_do_not_silently_change_trust(self):
        for options in (
            {"bundle_url": "https://attacker.example"},
            {"hardware_policy": {}},
            {"bundle_refresh_interval_seconds": 300},
        ):
            with self.subTest(options=options), self.assertRaises(TypeError):
                Transport(**options)

    @unittest.skipUnless(os.environ.get("STOGAS_LIVE"), "set STOGAS_LIVE to staging or prod")
    def test_live_gateway_rejects_an_invalid_key_through_each_security_mode(self):
        opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))
        body = b'{"model":"stogas-status-monitor","messages":[{"role":"user","content":"ping"}]}'
        headers = {"Authorization": "Bearer stogas-status-monitor-uncredentialed", "Content-Type": "application/json"}
        for security in ("tls", "e2ee"):
            with self.subTest(security=security):
                transport = Transport(environment=os.environ["STOGAS_LIVE"], security=security)
                try:
                    self.assertEqual(urllib.parse.urlsplit(transport.base_url).hostname, "127.0.0.1")
                    request = urllib.request.Request(transport.base_url + "/chat/completions", data=body, headers=headers, method="POST")
                    with self.assertRaises(urllib.error.HTTPError) as caught:
                        opener.open(request, timeout=30)
                    with caught.exception as response:
                        self.assertEqual(response.code, 401)
                        self.assertEqual(json.loads(response.read())["error"]["type"], "authentication_error")
                    with ThreadPoolExecutor(3) as pool:
                        list(pool.map(lambda _: transport.refresh_evidence(), range(3)))
                finally:
                    transport.close()
                transport.close()
                with self.assertRaises(ValueError):
                    transport.refresh_evidence()


if __name__ == "__main__":
    unittest.main()

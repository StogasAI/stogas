"""Positive snapshot ownership through an explicitly staging-enabled wheel."""

import gc
import hashlib
import json
import os
from pathlib import Path
import unittest

from stogas import EvidenceVerifier, VerificationError, request_digest, response_digest


@unittest.skipUnless(os.environ.get("STOGAS_TEST_STAGING") == "1", "requires staging wheel")
class StagingEvidenceTests(unittest.TestCase):
    def test_boot_archive_keeps_receipt_owner_without_restoring_live_permission(self):
        fixture = json.loads(
            (Path(__file__).resolve().parents[3] / "tests/fixtures/hardware-session-v1.json").read_bytes()
        )
        verifier = EvidenceVerifier(
            environment="staging",
            root=fixture["root"],
        )
        registration = json.loads(
            (Path(__file__).resolve().parents[3] / "tests/fixtures/hardware-registration-v1.json").read_bytes()
        )
        boot_bytes = (json.dumps(registration["boot"], sort_keys=True, separators=(",", ":")) + "\n").encode()
        archive = {
            "document": {"schema": "stogas.node-registration.v1", "boot": registration["boot"], "evidence_sha256": registration["inclusion"]["evidence_sha256"]},
            "signature": registration["inclusion"]["signature"],
            "inclusion": registration["inclusion"]["inclusion"],
        }
        evidence = json.dumps(fixture["evidence"]).encode()
        summary = json.loads(verifier.verify_evidence_archive(evidence))
        self.assertEqual(summary["evidence_sha256"], archive["document"]["evidence_sha256"])
        verified = verifier.verify_boot_archive(json.dumps(archive).encode(), evidence)
        archive["document"]["evidence_sha256"] = "0" * 64
        with self.assertRaises(VerificationError):
            verifier.verify_boot_archive(json.dumps(archive).encode(), evidence)
        del verifier
        gc.collect()
        self.assertEqual(json.loads(verified.summary())["boot_sha256"], hashlib.sha256(boot_bytes).hexdigest())
        # Historical handles retain the same receipt verification boundary.
        with self.assertRaises(VerificationError):
            verified.verify_receipt(b'{}', bytes(64), bytes(64))
        vector = json.loads(
            (Path(__file__).resolve().parents[3] / "tests/fixtures/content-receipt-v2.json").read_bytes()
        )
        metadata = {**vector["metadata"], "receipt": vector["receipt"], "salts": vector["salts"]}
        request = request_digest(vector["request"].encode())
        response = response_digest(vector["response"].encode())
        self.assertEqual((request.hex(), response.hex()), (vector["request_digest"], vector["response_digest"]))
        receipt = json.loads(verified.verify_receipt(json.dumps(metadata).encode(), request, response))
        self.assertEqual(receipt["boot_sha256"], hashlib.sha256(boot_bytes).hexdigest())
        self.assertEqual((receipt["request_verified"], receipt["response_verified"]), (True, True))
        # One side proves itself without the other side's content or salt.
        response_only = {**metadata, "salts": {"response": vector["salts"]["response"]}}
        receipt = json.loads(verified.verify_receipt(json.dumps(response_only).encode(), None, response))
        self.assertEqual((receipt["request_verified"], receipt["response_verified"]), (False, True))
        with self.assertRaises(VerificationError) as caught:
            verified.verify_receipt(json.dumps(response_only).encode(), request, response)
        self.assertEqual(caught.exception.code, "receipt_salt")
        # A buffered response carries its bag; the verified bag keeps the receipt but not the salts.
        body = {**json.loads(vector["response"]), "stogas": metadata}
        result = json.loads(verified.verify_response(request, json.dumps(body, indent=2).encode()))
        self.assertEqual(result["metadata"]["receipt"], vector["receipt"])
        self.assertNotIn("salts", result["metadata"])
        with self.assertRaises(VerificationError) as caught:
            verified.verify_response(request_digest(b'{"model":"other"}'), json.dumps(body).encode())
        self.assertEqual(caught.exception.code, "receipt_content")
        metadata["provider"] = {**metadata["provider"], "instance": "substituted"}
        with self.assertRaises(VerificationError) as caught:
            verified.verify_receipt(json.dumps(metadata).encode(), request, response)
        self.assertEqual(caught.exception.code, "receipt_signature")

    def test_snapshot_survives_rejected_refresh_and_verifier_destruction(self):
        fixture = json.loads(
            (Path(__file__).resolve().parents[3] / "tests/fixtures/hardware-session-v1.json").read_bytes()
        )
        verifier = EvidenceVerifier(
            environment="staging",
            root=fixture["root"],
        )
        snapshot = verifier.refresh(json.dumps(fixture["evidence"]).encode())
        expected = json.loads(snapshot.summary())
        self.assertEqual(len(expected["gateways"]), 1)
        self.assertEqual(len(expected["catalogs"]), 2)
        snapshot.require_current_keys()

        with self.assertRaises(VerificationError) as caught:
            verifier.refresh(b'{}')
        self.assertEqual(caught.exception.code, "invalid_evidence")
        del verifier
        gc.collect()
        self.assertEqual(json.loads(snapshot.summary()), expected)
        snapshot.require_current_keys()

        with self.assertRaises(VerificationError) as caught:
            snapshot.verify_logged_boot(b'{}', b'{}')
        self.assertEqual(caught.exception.code, "invalid_attestation")


if __name__ == "__main__":
    unittest.main()

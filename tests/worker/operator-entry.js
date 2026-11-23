import wasmModule from '../../target/operator/stogas_bg.wasm';
import {
	initSync,
	EvidenceVerifier,
	verify_mldsa65_ed25519,
	mldsa65_ed25519_signing_input,
	prepare_rekor_submission
} from '../../target/operator/stogas.js';
import { verify_build_attestation } from '../../packages/sigstore/bindings/worker/worker.js';
import fixtures from './operator-fixtures.js';

initSync({ module: wasmModule });

const bytes = (hex) => Uint8Array.from(hex.match(/../g), (part) => Number.parseInt(part, 16));
const base64 = (value) => Uint8Array.from(atob(value), (character) => character.charCodeAt(0));
const hex = (value) => Array.from(value, (byte) => byte.toString(16).padStart(2, '0')).join('');
const rejects = (operation) => {
	try {
		operation();
		return false;
	} catch {
		return true;
	}
};

// Operator primitives in the Workers runtime that runs them, and the Sigstore
// package beside them. Signatures come from OpenBao Transit vectors; nothing
// here holds a signing private key.
export default {
	async fetch() {
		const { signing, remote, root, manifest, sigstore, alteredSigstore, attestation } = fixtures;
		const message = bytes(signing.message);
		const remoteKey = base64(remote.public_key);
		const representatives = remote.vectors.map((vector) => {
			const [message, signature] = [vector.message, vector.signature].map(base64);
			verify_mldsa65_ed25519(remoteKey, message, signature);
			const input = mldsa65_ed25519_signing_input(remoteKey, message);
			return (
				hex(input.mldsa_mu) === hex(base64(vector.mldsa_mu)) &&
				hex(input.ed25519_message) === hex(base64(vector.ed25519_message))
			);
		});
		// A Rekor key's signature over the document's SHA-256 becomes its exact submission.
		const rekorKey = bytes(signing.rekor_spki);
		const rekorSignature = bytes(signing.rekor_signature);
		const submission = JSON.parse(prepare_rekor_submission(message, rekorKey, rekorSignature));
		const otherDocument = rejects(() =>
			prepare_rekor_submission(message.subarray(1), rekorKey, rekorSignature)
		);
		const verifier = new EvidenceVerifier('staging', root);
		const encoded = (value) => new TextEncoder().encode(JSON.stringify(value));
		const altered = structuredClone(manifest);
		altered.document.generation++;
		const changedProof = JSON.parse(attestation.bundle);
		const proof = changedProof.verificationMaterial.tlogEntries[0].inclusionProof;
		proof.hashes[0] = `${proof.hashes[0].startsWith('A') ? 'B' : 'A'}${proof.hashes[0].slice(1)}`;
		const sigstoreFiles = JSON.stringify(sigstore);
		const attested = (bundle) =>
			verify_build_attestation(
				new TextEncoder().encode(bundle),
				attestation.subjects,
				attestation.policy,
				attestation.trustedRoot
			);
		try {
			return Response.json({
				wrongMessage: rejects(() =>
					verify_mldsa65_ed25519(remoteKey, message, base64(remote.vectors[0].signature))
				),
				representatives,
				rekorSignature: submission.spec.signature.content,
				hash: submission.spec.data.hash,
				otherDocument,
				manifestKey: verifier.verify_key_manifest(encoded(manifest), sigstoreFiles).active_key
					.key_id,
				alteredManifest: rejects(() =>
					verifier.verify_key_manifest(encoded(altered), sigstoreFiles)
				),
				unsignedSigstore: rejects(() =>
					verifier.verify_key_manifest(encoded(manifest), JSON.stringify(alteredSigstore))
				),
				attestedSubjects: attested(attestation.bundle).subjects.length,
				changedInclusion: rejects(() => attested(JSON.stringify(changedProof)))
			});
		} finally {
			verifier.free();
		}
	}
};

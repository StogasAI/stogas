import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import {
	verify_dsse_attestation,
	verify_github_attestation
} from '../../packages/sigstore/bindings/node/node.js';

const attestation = readFileSync(
	new URL('../fixtures/gateway-v0.0.1-attestation.jsonl', import.meta.url)
);
const trustedRoot = readFileSync(
	new URL('../fixtures/sigstore-tuf/trusted_root.json', import.meta.url),
	'utf8'
);
const subjects = [
	{
		name: 'gateway.igvm',
		sha256: '1b75d0ea7f94bc5f5a21080dd30e21370e14278a5b90eb19858c90dcc83a1bc6'
	},
	{
		name: 'gateway-launch-policy.json',
		sha256: '8cc8926592b179283c8cab267a27dfb3df4d1086dff2504e51df5fa12b8ff008'
	}
];
const policy = {
	predicate_type: 'https://slsa.dev/provenance/v1',
	repository: 'https://github.com/StogasAI/gateway',
	source_commit: '27eb4b954a372975c9e7c5dbc77fbf0d0ca53b3f',
	source_ref: 'refs/tags/v0.0.1',
	workflow_identity:
		'https://github.com/StogasAI/gateway/.github/workflows/gateway-igvm-release.yml@refs/tags/v0.0.1'
};

const verified = verify_github_attestation(
	attestation,
	JSON.stringify(subjects),
	JSON.stringify(policy),
	trustedRoot
);
assert.equal(verified.subjects.length, 2);
assert.equal(
	verified.predicate.buildDefinition.buildType,
	'https://actions.github.io/buildtypes/workflow/v1'
);

// The generic check takes any signer's identity and returns the same predicate.
const identity = {
	certificate_identity: policy.workflow_identity,
	certificate_oidc_issuer: 'https://token.actions.githubusercontent.com',
	predicate_type: policy.predicate_type
};
const generic = verify_dsse_attestation(
	attestation,
	JSON.stringify(subjects),
	JSON.stringify(identity),
	trustedRoot
);
assert.deepEqual(generic, verified);
assert.throws(
	() =>
		verify_dsse_attestation(
			attestation,
			JSON.stringify(subjects),
			JSON.stringify({ ...identity, certificate_oidc_issuer: 'https://accounts.google.com' }),
			trustedRoot
		),
	/Sigstore cryptographic verification failed/
);

const mutation = JSON.parse(attestation);
const hash = mutation.verificationMaterial.tlogEntries[0].inclusionProof.hashes[0];
mutation.verificationMaterial.tlogEntries[0].inclusionProof.hashes[0] = `${hash.startsWith('A') ? 'B' : 'A'}${hash.slice(1)}`;
assert.throws(
	() =>
		verify_github_attestation(
			new TextEncoder().encode(JSON.stringify(mutation)),
			JSON.stringify(subjects),
			JSON.stringify(policy),
			trustedRoot
		),
	/Sigstore cryptographic verification failed/
);
// Without Sigstore's keys nothing verifies.
const withoutLogs = JSON.parse(trustedRoot);
withoutLogs.tlogs = [];
assert.throws(() =>
	verify_github_attestation(
		attestation,
		JSON.stringify(subjects),
		JSON.stringify(policy),
		JSON.stringify(withoutLogs)
	)
);
assert.throws(
	() =>
		verify_github_attestation(attestation, JSON.stringify(subjects), JSON.stringify(policy), '{}'),
	/trusted root/i
);

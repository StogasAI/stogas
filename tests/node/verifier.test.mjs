import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import * as publicAPI from 'stogas';
import {
	EvidenceVerifier,
	StogasTransport,
	request_digest,
	response_digest,
	stream_response
} from 'stogas';

for (const retired of [
	'Verifier',
	'verify_bundle',
	'verify_staging_catalog_approval',
	'verify_staging_release_approval'
])
	assert.equal(retired in publicAPI, false);

const { root } = JSON.parse(
	readFileSync(new URL('../fixtures/hardware-session-v1.json', import.meta.url), 'utf8')
);
const verifier = new EvidenceVerifier('prod', root);
try {
	assert.throws(() => verifier.refresh(new TextEncoder().encode('{"document":')));
} finally {
	verifier.free();
}
// A root document keeps its Rekor v2 scope, so an invalid scope fails as the core rejects it.
const scope = {
	first_indexes: { 'log2025-1.rekor.sigstore.dev': 1 },
	opened_from: '2026-10-31T00:00:00Z'
};
new EvidenceVerifier('prod', { ...root, rekor_v2: scope }).free();
for (const invalid of [
	{ ...root, rekor_v2: { ...scope, opened_from: '2026-10-31' } },
	{ ...root, rekor_v2: { ...scope, first_indexes: { 'Log.Example': 1 } } },
	{ ...root, rekor_v2: { first_indexes: {} } },
	{ ...root, unknown: true },
	{ key_id: root.key_id, public_key: root.public_key },
	{ ...root, rekor_public_key: 'bad-key' },
	JSON.stringify(root)
])
	assert.throws(() => new EvidenceVerifier('prod', invalid));
assert.throws(() => new StogasTransport({ maxConnections: 0 }), /positive safe integer/);

// A saved request and response hash as their receipt signs them, whatever their formatting.
const sample = JSON.parse(
	readFileSync(new URL('../fixtures/content-receipt-v2.json', import.meta.url), 'utf8')
);
const bytes = (text) => new TextEncoder().encode(text);
const hex = (digest) => Buffer.from(digest).toString('hex');
assert.equal(hex(request_digest(bytes(sample.request))), sample.request_digest);
assert.equal(hex(response_digest(bytes(sample.response))), sample.response_digest);
// A response hashes the same with the `stogas` object that carried its receipt.
const carried = { ...JSON.parse(sample.response), stogas: { receipt: sample.receipt } };
assert.equal(hex(response_digest(bytes(JSON.stringify(carried)))), sample.response_digest);
assert.throws(() => request_digest(bytes('[]')), { code: 'invalid_content' });
assert.throws(() => stream_response(bytes('data: {"id":"cut"}\n\n')), { code: 'invalid_receipt' });

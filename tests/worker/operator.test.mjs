import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { readFile } from 'node:fs/promises';
import { resolve } from 'node:path';
import { test } from 'node:test';
import { Miniflare } from 'miniflare';

const root = resolve(import.meta.dirname, '../..');
const json = async (path) => JSON.parse(await readFile(resolve(root, path), 'utf8'));

// The operator build runs in Stogas services and the CLI, never in customer
// packages. Run it in workerd, the runtime that uses it.
test('operator Worker verifies remote signatures, Rekor submissions, key manifests and releases', async () => {
	const signing = await json('tests/fixtures/mldsa65-v1.json');
	const fixtures = {
		signing,
		remote: await json('tests/fixtures/mldsa65-remote-v1.json'),
		manifest: await json('tests/fixtures/staging-key-manifest.json'),
		attestation: {
			bundle: await readFile(
				resolve(root, 'tests/fixtures/gateway-v0.0.1-attestation.jsonl'),
				'utf8'
			),
			now: 1_784_246_400_000,
			subjects: [
				{
					name: 'gateway.igvm',
					sha256: '1b75d0ea7f94bc5f5a21080dd30e21370e14278a5b90eb19858c90dcc83a1bc6'
				},
				{
					name: 'gateway-launch-policy.json',
					sha256: '8cc8926592b179283c8cab267a27dfb3df4d1086dff2504e51df5fa12b8ff008'
				}
			],
			policy: {
				predicate_type: 'https://slsa.dev/provenance/v1',
				repository: 'https://github.com/StogasAI/gateway',
				require_github_hosted: true,
				source_commit: '27eb4b954a372975c9e7c5dbc77fbf0d0ca53b3f',
				source_ref: 'refs/tags/v0.0.1',
				workflow_identity:
					'https://github.com/StogasAI/gateway/.github/workflows/gateway-igvm-release.yml@refs/tags/v0.0.1'
			}
		}
	};
	const module = async (name) => ({
		type: name.endsWith('.wasm') ? 'wasm' : 'esm',
		contents: await readFile(resolve(root, name), name.endsWith('.wasm') ? undefined : 'utf8')
	});
	const runtime = new Miniflare({
		cf: false,
		telemetry: { enabled: false },
		workers: [
			{
				config: {
					name: 'operator',
					compatibilityDate: '2026-09-21',
					manifest: {
						mainModule: 'tests/worker/operator-entry.js',
						modules: {
							'tests/worker/operator-entry.js': await module('tests/worker/operator-entry.js'),
							'target/operator/stogas_verifier.js': await module(
								'target/operator/stogas_verifier.js'
							),
							'target/operator/stogas_verifier_bg.wasm': await module(
								'target/operator/stogas_verifier_bg.wasm'
							),
							'tests/worker/operator-fixtures.js': {
								type: 'esm',
								contents: `export default ${JSON.stringify(fixtures)};`
							}
						}
					}
				}
			}
		]
	});
	try {
		const response = await runtime.dispatchFetch('http://operator/');
		assert.equal(response.status, 200, await response.clone().text());
		assert.deepEqual(await response.json(), {
			wrongContext: true,
			representatives: [true, true, true],
			rekorPublicKey: signing.rekor_spki,
			rekorSignature: Buffer.from(signing.rekor_signature, 'hex').toString('base64'),
			hash: {
				algorithm: 'sha512',
				value: createHash('sha512').update(Buffer.from(signing.message, 'hex')).digest('hex')
			},
			stable: true,
			erased: true,
			badSeed: true,
			manifestKey: fixtures.manifest.document.active_key.key_id,
			alteredManifest: true,
			attestedSubjects: 2,
			changedInclusion: true
		});
	} finally {
		await runtime.dispose();
	}
});

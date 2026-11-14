import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';
import { resolve } from 'node:path';
import { test } from 'node:test';
import { Miniflare } from 'miniflare';

const root = resolve(import.meta.dirname, '../..');
const read = (path, encoding) => readFile(resolve(root, path), encoding);

test('the SEV-SNP and Sigstore packages verify through their Worker entry points', async () => {
	const names = [
		'tests/worker/packages-entry.js',
		...['sev-snp', 'sigstore'].flatMap((name) => {
			const module = `stogas_${name.replace('-', '_')}`;
			return [
				`packages/${name}/bindings/worker/worker.js`,
				`packages/${name}/pkg/browser/${module}.js`,
				`packages/${name}/pkg/browser/${module}_bg.wasm`
			];
		})
	];
	const modules = Object.fromEntries(
		await Promise.all(
			names.map(async (name) => {
				const wasm = name.endsWith('.wasm');
				return [
					name,
					{ type: wasm ? 'wasm' : 'esm', contents: await read(name, wasm ? undefined : 'utf8') }
				];
			})
		)
	);
	const runtime = new Miniflare({
		cf: false,
		telemetry: { enabled: false },
		workers: [
			{
				config: {
					name: 'packages',
					compatibilityDate: '2026-09-21',
					manifest: { mainModule: 'tests/worker/packages-entry.js', modules }
				}
			}
		]
	});
	try {
		const base64 = async (path) => (await read(path)).toString('base64');
		const body = {
			report: await base64('tests/fixtures/sev-snp/gcp-milan/report-vmpl0.bin'),
			table: await base64('tests/fixtures/sev-snp/gcp-milan/certificates.bin'),
			// 2026-11-14T00:00:00Z, when the VCEK is valid.
			now: 1_794_614_400,
			attestation: await base64('tests/fixtures/gateway-v0.0.1-attestation.jsonl'),
			trusted_root: await read('tests/fixtures/sigstore-tuf/trusted_root.json', 'utf8'),
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
				source_commit: '27eb4b954a372975c9e7c5dbc77fbf0d0ca53b3f',
				source_ref: 'refs/tags/v0.0.1',
				workflow_identity:
					'https://github.com/StogasAI/gateway/.github/workflows/gateway-igvm-release.yml@refs/tags/v0.0.1'
			}
		};
		const response = await runtime.dispatchFetch('http://packages/', {
			method: 'POST',
			body: JSON.stringify(body)
		});
		assert.equal(response.status, 200, await response.clone().text());
		assert.deepEqual(await response.json(), { product: 'Milan', subjects: 2 });
	} finally {
		await runtime.dispose();
	}
});

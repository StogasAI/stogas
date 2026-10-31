import { expect, test } from '@playwright/test';
import { readFile } from 'node:fs/promises';
import { createServer } from 'node:http';
import type { AddressInfo } from 'node:net';
import { extname, resolve } from 'node:path';

const ROOT = resolve(import.meta.dirname, '../..');
const GLUE = resolve(ROOT, 'target/browser/stogas.js');
const WASM = resolve(ROOT, 'target/browser/stogas_bg.wasm');
const SIGSTORE_GLUE = resolve(ROOT, 'target/sigstore-browser/stogas_sigstore.js');
const SIGSTORE_WASM = resolve(ROOT, 'target/sigstore-browser/stogas_sigstore_bg.wasm');
const FIXTURE = resolve(ROOT, 'tests/fixtures/gateway-v0.0.1-attestation.jsonl');
const TRUSTED_ROOT = resolve(ROOT, 'tests/fixtures/sigstore-tuf/trusted_root.json');
const SUBJECTS = [
	{
		name: 'gateway.igvm',
		sha256: '1b75d0ea7f94bc5f5a21080dd30e21370e14278a5b90eb19858c90dcc83a1bc6'
	},
	{
		name: 'gateway-launch-policy.json',
		sha256: '8cc8926592b179283c8cab267a27dfb3df4d1086dff2504e51df5fa12b8ff008'
	}
];
const POLICY = {
	predicate_type: 'https://slsa.dev/provenance/v1',
	repository: 'https://github.com/StogasAI/gateway',
	source_commit: '27eb4b954a372975c9e7c5dbc77fbf0d0ca53b3f',
	source_ref: 'refs/tags/v0.0.1',
	workflow_identity:
		'https://github.com/StogasAI/gateway/.github/workflows/gateway-igvm-release.yml@refs/tags/v0.0.1'
};

test('browser boot history remains offline and separate from current evidence', async ({
	page
}) => {
	const requests = await initialize(page);
	const fixture = JSON.parse(
		await readFile(resolve(ROOT, 'tests/fixtures/hardware-session-v1.json'), 'utf8')
	);
	const registration = JSON.parse(
		await readFile(resolve(ROOT, 'tests/fixtures/hardware-registration-v1.json'), 'utf8')
	);
	const archive = {
		document: {
			schema: 'stogas.node-registration.v1',
			boot: registration.boot,
			evidence_sha256: registration.inclusion.evidence_sha256
		},
		signature: registration.inclusion.signature,
		inclusion: registration.inclusion.inclusion
	};
	const result = await page.evaluate(
		({ fixture, archive }) => {
			const api = (
				globalThis as unknown as {
					stogasVerifierBindings: typeof import('../../pkg/browser/stogas.js');
				}
			).stogasVerifierBindings;
			const core = new api.EvidenceVerifier(
				'staging',
				fixture.root.key_id,
				fixture.root.public_key,
				fixture.root.rekor_public_key
			);
			const encode = (value: unknown) => new TextEncoder().encode(JSON.stringify(value));
			const previousNow = Date.now;
			Date.now = () => fixture.verified_at_ms + 366 * 24 * 60 * 60 * 1000;
			try {
				const verified = core.verify_boot_archive(encode(archive), encode(fixture.evidence));
				archive.document.evidence_sha256 = '0'.repeat(64);
				let rejected = false;
				try {
					core.verify_boot_archive(encode(archive), encode(fixture.evidence));
				} catch {
					rejected = true;
				}
				return { digest: verified.boot_sha256, rejected };
			} finally {
				core.free();
				Date.now = previousNow;
			}
		},
		{ fixture, archive }
	);
	expect(result).toEqual({
		digest: JSON.parse(
			await readFile(resolve(ROOT, 'tests/fixtures/content-receipt-v1.json'), 'utf8')
		).hardware_receipt.boot_sha256,
		rejected: true
	});
	expect(requests).toEqual([]);
});

test('encrypted setup cannot release a browser session without its own verified exchange', async ({
	page
}) => {
	const requests = await initialize(page);
	const fixture = JSON.parse(
		await readFile(resolve(ROOT, 'tests/fixtures/hardware-session-v1.json'), 'utf8')
	);
	const result = await page.evaluate((fixture) => {
		const api = (
			globalThis as unknown as {
				stogasVerifierBindings: typeof import('../../pkg/browser/stogas.js');
			}
		).stogasVerifierBindings;
		const platformNow = Date.now;
		Date.now = () => fixture.verified_at_ms;
		const verifier = new api.EvidenceVerifier(
			'staging',
			fixture.root.key_id,
			fixture.root.public_key,
			fixture.root.rekor_public_key
		);
		let snapshot: InstanceType<typeof api.EvidenceSnapshot> | undefined;
		let pending: InstanceType<typeof api.EncryptedSetup> | undefined;
		let second: InstanceType<typeof api.EncryptedSetup> | undefined;
		try {
			snapshot = verifier.refresh(new TextEncoder().encode(JSON.stringify(fixture.evidence)));
			pending = new api.EncryptedSetup('staging');
			second = new api.EncryptedSetup('staging');
			const hello = pending.hello;
			const response = Uint8Array.from(
				atob(fixture.e2ee.response.replaceAll('-', '+').replaceAll('_', '/')),
				(value) => value.charCodeAt(0)
			);
			let rejected = 0;
			// The archived response has genuine hardware evidence, but belongs to another
			// client's hello. Neither that evidence nor malformed framing can create keys.
			for (const candidate of [
				response,
				response.slice(0, -1),
				new Uint8Array(),
				new Uint8Array(64 * 1024)
			]) {
				try {
					pending.complete(candidate, snapshot);
				} catch {
					rejected++;
				}
			}
			const secondHello = second.hello;
			const retainedHello = pending.hello;
			return {
				helloLength: hello.length,
				fresh: !hello.every((value: number, index: number) => value === secondHello[index]),
				retainedHello: hello.every(
					(value: number, index: number) => value === retainedHello[index]
				),
				noPrematureSeal: !('seal' in pending),
				rejected
			};
		} finally {
			pending?.free();
			second?.free();
			snapshot?.free();
			verifier.free();
			Date.now = platformNow;
		}
	}, fixture);
	expect(result).toEqual({
		helloLength: 1255,
		fresh: true,
		retainedHello: true,
		noPrematureSeal: true,
		rejected: 4
	});
	expect(requests).toEqual([]);
});

async function initializeModule(
	page: import('@playwright/test').Page,
	gluePath: string,
	wasmPath: string,
	globalName: string
) {
	const source = await readFile(gluePath, 'utf8');
	const encoded = (await readFile(wasmPath)).toString('base64');
	const server = createServer((request, response) => {
		response.setHeader(
			'content-type',
			request.url === '/module.js' ? 'text/javascript' : 'text/html'
		);
		response.end(
			request.url === '/module.js' ? source : '<!doctype html><title>SDK consumer</title>'
		);
	});
	await new Promise<void>((resolve) => server.listen(0, '127.0.0.1', resolve));
	try {
		const origin = `http://127.0.0.1:${(server.address() as AddressInfo).port}`;
		await page.goto(origin);
		await page.evaluate(
			async ({ encoded, globalName, origin }) => {
				const bindings = await import(`${origin}/module.js`);
				const binary = Uint8Array.from(atob(encoded), (character) => character.charCodeAt(0));
				await bindings.default({ module_or_path: binary });
				(globalThis as unknown as Record<string, unknown>)[globalName] = bindings;
			},
			{ encoded, globalName, origin }
		);
	} finally {
		server.closeAllConnections();
		await new Promise<void>((resolve, reject) =>
			server.close((error) => (error ? reject(error) : resolve()))
		);
	}
	const requests: string[] = [];
	await page.route('**/*', async (route) => {
		requests.push(route.request().url());
		await route.abort('blockedbyclient');
	});
	return requests;
}

function initialize(page: import('@playwright/test').Page) {
	return initializeModule(page, GLUE, WASM, 'stogasVerifierBindings');
}

function initializeSigstore(page: import('@playwright/test').Page) {
	return initializeModule(page, SIGSTORE_GLUE, SIGSTORE_WASM, 'stogasSigstoreBindings');
}

test('standalone lightweight package verifies GitHub evidence with networking disabled', async ({
	page
}) => {
	const requests = await initializeSigstore(page);
	const fixture = await readFile(FIXTURE, 'utf8');
	const trustedRoot = await readFile(TRUSTED_ROOT, 'utf8');
	const result = await page.evaluate(
		({ fixture, subjects, policy, trustedRoot }) => {
			const api = (
				globalThis as typeof globalThis & {
					stogasSigstoreBindings: {
						verify_github_attestation(
							bundle: Uint8Array,
							subjects: string,
							policy: string,
							trustedRoot: string
						): { subjects: unknown[] };
					};
				}
			).stogasSigstoreBindings;
			return api.verify_github_attestation(
				new TextEncoder().encode(fixture),
				JSON.stringify(subjects),
				JSON.stringify(policy),
				trustedRoot
			);
		},
		{ fixture, subjects: SUBJECTS, policy: POLICY, trustedRoot }
	);
	expect(result.subjects).toHaveLength(2);
	expect(requests).toEqual([]);
});

test('concurrent initialization instantiates the browser package once', async ({ page }) => {
	const types: Record<string, string> = { '.js': 'text/javascript', '.wasm': 'application/wasm' };
	let wasmRequests = 0;
	const server = createServer((request, response) => {
		const path = new URL(request.url ?? '/', 'http://127.0.0.1').pathname;
		if (path === '/') return response.end('<!doctype html><title>SDK consumer</title>');
		const type = types[extname(path)];
		if (!type || !/^\/(bindings|pkg\/browser)\//.test(path)) {
			response.statusCode = 404;
			return response.end();
		}
		if (type === 'application/wasm') wasmRequests += 1;
		readFile(resolve(ROOT, `.${path}`)).then(
			(body) => response.setHeader('content-type', type).end(body),
			() => {
				response.statusCode = 404;
				response.end();
			}
		);
	});
	await new Promise<void>((done) => server.listen(0, '127.0.0.1', done));
	try {
		const origin = `http://127.0.0.1:${(server.address() as AddressInfo).port}`;
		await page.goto(origin);
		const shared = await page.evaluate(async (origin) => {
			const sdk = await import(`${origin}/bindings/browser/browser.js`);
			const [first, second] = await Promise.all([sdk.default(), sdk.default()]);
			return first === second && (await sdk.default()) === first;
		}, origin);
		expect(shared).toBe(true);
		expect(wasmRequests).toBe(1);
	} finally {
		server.closeAllConnections();
		await new Promise<void>((done, fail) =>
			server.close((error) => (error ? fail(error) : done()))
		);
	}
});

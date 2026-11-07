import assert from 'node:assert/strict';
import { test } from 'node:test';
import { createTransportClass } from '../../bindings/shared/transport.js';

// Lifecycle doubles; cryptographic checks use the real Wasm core in browser tests.
function binding(refresh) {
	let freed = 0;
	const Transport = createTransportClass({
		transport_configuration(environment) {
			assert.equal(environment, 'prod');
			return {
				environment,
				e2ee_origin: 'https://e2ee.example',
				evidence_origins: ['https://r2.example/evidence', 'https://aws.example/evidence']
			};
		},
		EvidenceVerifier: class {
			static for_stogas() {
				return new this();
			}
			refresh(bytes) {
				if (refresh) return refresh(bytes);
				assert.equal(new TextDecoder().decode(bytes), '{}');
				return {
					summary: () => ({ document: { revision: 1 } }),
					same_as: () => false,
					require_current_keys() {},
					free() {}
				};
			}
			free() {
				freed++;
			}
		},
		EncryptedSetup: class {}
	});
	return {
		Transport,
		get freed() {
			return freed;
		}
	};
}

test('options are explicit and confidential fetch never falls through to ordinary requests', async () => {
	const { Transport } = binding();
	for (const options of [
		{ maxConnections: 0 },
		{ maxConnections: 1.5 },
		{ maxConnections: Infinity },
		{ bundleRefreshIntervalSeconds: 300 },
		{ security: 'both' },
		{ proxied: 'yes' },
		{ proxied: 1 }
	])
		assert.throws(() => new Transport(options), /Unsupported|positive safe integer|boolean/);
	for (const proxied of [true, false, undefined]) new Transport({ proxied }).close();
	for (const baseURL of [
		'http://e2ee.example/v1',
		'https://user@e2ee.example/v1',
		'https://e2ee.example/v1?',
		'https://e2ee.example/v1#',
		'https://e2ee.example/other'
	])
		assert.throws(() => new Transport({ baseURL }), /HTTPS/);
	let calls = 0;
	const transport = new Transport({
		fetch: async () => {
			calls++;
			throw new Error('must not send');
		}
	});
	for (const url of [
		'https://unrelated.example/v1/chat/completions',
		'https://e2ee.example/v1/models',
		'https://e2ee.example/v1/files',
		'https://e2ee.example/v1/chat/completions?key=secret'
	])
		await assert.rejects(
			transport.fetch(url, {
				method: 'POST',
				headers: { authorization: 'Bearer secret' },
				body: '{}'
			}),
			(error) => error.submission === 'not_sent'
		);
	await assert.rejects(
		transport.fetch('https://e2ee.example/v1/chat/completions'),
		(error) => error.submission === 'not_sent'
	);
	assert.equal(calls, 0);
	const options = transport.openAIOptions('secret');
	assert.equal(options.baseURL, 'https://e2ee.example/v1');
	assert.equal('maxRetries' in options, false);
	assert.equal(options.fetch, transport.fetch);
	await transport.close();
	await assert.rejects(
		transport.fetch('https://e2ee.example/v1/chat/completions', { method: 'POST' }),
		(error) => error.submission === 'not_sent'
	);
});

// Through a proxy, such as Tor, every time limit is four times as long: here the hedge before the
// replica starts.
test('a proxied transport waits four times as long', { timeout: 15_000 }, async () => {
	for (const [proxied, hedge] of [
		[false, 1_000],
		[true, 4_000]
	]) {
		const fixture = binding();
		const started = performance.now();
		let replica;
		const transport = new fixture.Transport({
			proxied,
			fetch: (url, { signal }) => {
				if (url.includes('r2'))
					return new Promise((_, reject) =>
						signal.addEventListener('abort', () => reject(signal.reason), { once: true })
					);
				replica = performance.now() - started;
				return Promise.resolve(new Response('{}'));
			}
		});
		await transport.refreshEvidence();
		assert.ok(replica >= hedge - 2 && replica < hedge + 250, `replica at ${replica} ms`);
		await transport.close();
	}
});

test('explicit refresh shares acquisition, exposes frozen evidence, and isolates failed observers', async () => {
	const fixture = binding();
	const attempts = [];
	const transport = new fixture.Transport({
		fetch: async (url, options) => {
			attempts.push(url);
			assert.equal(options.credentials, 'omit');
			assert.equal(options.redirect, 'manual');
			assert.equal(new Headers(options.headers).has('authorization'), false);
			return url.includes('r2') ? new Response(null, { status: 503 }) : new Response('{}');
		}
	});
	let observed = 0;
	transport.subscribe(() => {
		observed++;
		if (observed > 1) throw new Error('observer');
	});
	const [first, second] = await Promise.all([
		transport.refreshEvidence(),
		transport.refreshEvidence()
	]);
	assert.deepEqual(first, second);
	assert.deepEqual(attempts, ['https://r2.example/evidence', 'https://aws.example/evidence']);
	assert.equal(observed, 2);
	const snapshot = transport.evidenceSnapshot;
	assert.equal(snapshot.status, 'ready');
	assert.equal(transport.evidenceSnapshot, snapshot);
	assert.throws(() => {
		snapshot.evidence.document.revision = 999;
	}, TypeError);
	assert.equal(transport.evidenceSnapshot.evidence.document.revision, 1);
	assert.deepEqual(transport.evidenceURLs, attempts);
	await transport.close();
	await transport.close();
	assert.equal(fixture.freed, 1);
});

test("a failed refresh reports the verifier's code, or evidence_unavailable", async () => {
	const failure = Object.assign(
		new Error('this version reads stogas.evidence.v1, not the newer stogas.evidence.v2'),
		{ name: 'EvidenceVerificationError', code: 'newer_format' }
	);
	for (const [refresh, status, code] of [
		[
			() => {
				throw failure;
			},
			200,
			'newer_format'
		],
		[undefined, 503, 'evidence_unavailable']
	]) {
		const transport = new (binding(refresh).Transport)({
			fetch: async () => new Response(status === 200 ? '{}' : null, { status })
		});
		await assert.rejects(transport.refreshEvidence());
		assert.equal(transport.evidenceSnapshot.status, 'error');
		assert.equal(transport.evidenceSnapshot.errorCode, code);
		await transport.close();
	}
});

test('disposal aborts acquisition and failed creation frees the compiled verifier', async () => {
	const fixture = binding();
	let started;
	const waiting = new Promise((resolve) => {
		started = resolve;
	});
	let aborted = false;
	const transport = new fixture.Transport({
		fetch: (_url, options) =>
			new Promise((_resolve, reject) => {
				options.signal.addEventListener(
					'abort',
					() => {
						aborted = true;
						reject(options.signal.reason);
					},
					{ once: true }
				);
				started();
			})
	});
	const refresh = transport.refreshEvidence();
	await waiting;
	await transport.close();
	await assert.rejects(refresh, /closed/i);
	assert.equal(aborted, true);
	assert.equal(fixture.freed, 1);
	await assert.rejects(
		fixture.Transport.create({ fetch: async () => new Response(null, { status: 503 }) }),
		/503/
	);
	assert.equal(fixture.freed, 2);
});

import assert from 'node:assert/strict';
import { test } from 'node:test';
import { SessionTransport } from '../../bindings/shared/session-transport.js';
import { SESSION_CONTENT_TYPE } from '../../bindings/shared/channel-http.js';
import { Exchange, record, response } from './channel-fixture.mjs';

function fixture({
	fetchResponse,
	maxSessions = 1,
	verify = () => {},
	request = () => {},
	fetchSetup,
	nodeID = (index) => `node-${index}`
} = {}) {
	const cores = [];
	const exchanges = [];
	const nodes = [];
	let setups = 0;
	let setupFreed = 0;
	let requests = 0;
	let closeRequests = 0;
	let snapshots = 1;
	let acquisitions = 0;
	const evidence = {
		check(check) {
			return check(snapshots);
		},
		async acquire(_signal, check = () => {}) {
			acquisitions++;
			snapshots++;
			return check(snapshots);
		}
	};
	class Setup {
		hello = new Uint8Array([99]);
		complete(bytes, snapshot) {
			verify(bytes, snapshot);
			const owner = {
				closed: false,
				freed: false,
				node_id: nodeID(cores.length),
				idle_seconds: 10,
				request(snapshot) {
					assert.equal(this.closed, false);
					request(snapshot, this);
					const exchange = new Exchange();
					exchanges.push(exchange);
					return exchange;
				},
				close() {
					this.closed = true;
				},
				free() {
					assert.equal(this.freed, false);
					this.freed = true;
				}
			};
			cores.push(owner);
			return owner;
		}
		free() {
			setupFreed++;
		}
	}
	const transport = new SessionTransport({
		Setup,
		evidence,
		environment: 'staging',
		endpoint: 'https://e2ee.example/v1/session',
		maxSessions,
		fetch: async (url, options) => {
			assert.equal(url, 'https://e2ee.example/v1/session');
			assert.equal(options.headers.authorization, undefined);
			if (options.body instanceof Uint8Array) {
				setups++;
				assert.deepEqual([...options.body], [99]);
				assert.equal(options.headers['Stogas-Node-ID'], undefined);
				return fetchSetup
					? fetchSetup(options)
					: new Response(new Uint8Array([12]), {
							headers: { 'content-type': SESSION_CONTENT_TYPE }
						});
			}
			const bytes = new Uint8Array(await options.body.arrayBuffer());
			// The boundary double emits no DATA record for the authenticated close.
			if (bytes.length === 5) {
				closeRequests++;
				return response([record(1, '{"status":204,"headers":{}}'), record(3)]);
			}
			requests++;
			nodes.push(options.headers['Stogas-Node-ID']);
			return fetchResponse
				? fetchResponse(options, requests)
				: response([
						record(1, '{"status":200,"headers":{"content-type":"application/json"}}'),
						record(2, '{"ok":true}'),
						record(3)
					]);
		}
	});
	return {
		transport,
		cores,
		exchanges,
		nodes,
		get setups() {
			return setups;
		},
		get setupFreed() {
			return setupFreed;
		},
		get requests() {
			return requests;
		},
		get closeRequests() {
			return closeRequests;
		},
		get acquisitions() {
			return acquisitions;
		},
		send(signal, onProgress) {
			return transport.send(
				new Request('https://e2ee.example/v1/chat/completions', {
					method: 'POST',
					headers: { authorization: 'Bearer private-key' },
					body: '{}',
					signal
				}),
				onProgress
			);
		}
	};
}

test('concurrent requests share one verified setup and explicit close sends one authenticated disposal', async () => {
	const state = fixture();
	const results = await Promise.all(
		Array.from({ length: 20 }, async () => (await state.send()).json())
	);
	assert.deepEqual(results, Array(20).fill({ ok: true }));
	assert.equal(state.setups, 1);
	assert.equal(state.setupFreed, 1);
	assert.equal(state.requests, 20);
	assert.equal(state.cores[0].freed, false);
	await state.transport.close();
	await state.transport.close();
	assert.equal(state.closeRequests, 1);
	assert.equal(state.cores[0].freed, true);
	await assert.rejects(state.send(), { submission: 'not_sent' });
});

test('canceling the first waiter preserves shared setup for another request', async () => {
	let markReady, finishSetup;
	const ready = new Promise((resolve) => {
		markReady = resolve;
	});
	const setup = new Promise((resolve) => {
		finishSetup = resolve;
	});
	let setupSignal;
	const state = fixture({
		fetchSetup: ({ signal }) => {
			setupSignal = signal;
			markReady();
			return setup;
		}
	});
	const controller = new AbortController();
	const first = state.send(controller.signal);
	const rejected = assert.rejects(first, { submission: 'not_sent' });
	await ready;
	const second = state.send();
	controller.abort();
	await rejected;
	assert.equal(setupSignal.aborted, false);
	finishSetup(
		new Response(new Uint8Array([12]), { headers: { 'content-type': SESSION_CONTENT_TYPE } })
	);
	assert.deepEqual(await (await second).json(), { ok: true });
	assert.equal(state.setups, 1);
	assert.equal(state.requests, 1);
	assert.equal(state.setupFreed, 1);
	await state.transport.close();
});

test('a session takes requests for one idle hint after the last one began; open streams finish on it', async () => {
	const originalNow = Date.now;
	let now = 100_000;
	Date.now = () => now;
	try {
		const state = fixture();
		const open = await state.send();
		now += 9_999;
		await (await state.send()).text();
		now += 9_999;
		await (await state.send()).text();
		assert.equal(state.setups, 1);
		// The gateway may expire a session one idle hint after its last request
		// ends, so an open stream does not make the session safe for new work.
		now += 10_000;
		const next = await state.send();
		assert.equal(state.setups, 2);
		assert.equal(state.cores[0].closed, true);
		assert.equal(state.cores[0].freed, false);
		assert.deepEqual(await open.json(), { ok: true });
		assert.equal(state.cores[0].freed, true);
		await next.text();
		// A clock that moved back cannot show the session is still fresh.
		now -= 1;
		await (await state.send()).text();
		assert.equal(state.setups, 3);
		await state.transport.close();
	} finally {
		Date.now = originalNow;
	}
});

const pending = () =>
	Object.assign(new Error('pending'), { name: 'EncryptedChannelError', code: 'pending' });
const refusal = () =>
	response([
		record(4),
		record(1, '{"status":503,"headers":{"retry-after":"1"},"refused":true}'),
		record(2, '{"error":"gateway_draining"}'),
		record(3)
	]);
const admitted = () =>
	response([record(1, '{"status":200,"headers":{}}'), record(2, 'admitted'), record(3)]);

test('a refused request goes once through a new session and retires every session on the refusing gateway', async () => {
	let output;
	const state = fixture({
		maxSessions: 3,
		nodeID: (index) => (index < 2 ? 'draining' : 'other'),
		// Each draining session takes one request, so the second request opens another.
		request(_snapshot, core) {
			if (core.node_id !== 'draining') return;
			if (core.taken) throw pending();
			core.taken = true;
		},
		fetchResponse(options, count) {
			if (count === 1)
				return new Response(
					new ReadableStream({
						start(controller) {
							output = controller;
							controller.enqueue(record(1, '{"status":200,"headers":{}}'));
						}
					}),
					{ headers: { 'content-type': SESSION_CONTENT_TYPE } }
				);
			return options.headers['Stogas-Node-ID'] === 'draining' ? refusal() : admitted();
		}
	});
	const open = await state.send();
	const phases = [];
	const resent = await state.send(undefined, (phase) => phases.push(phase));
	assert.equal(resent.status, 200);
	assert.equal(await resent.text(), 'admitted');
	assert.deepEqual(state.nodes, ['draining', 'draining', 'other']);
	assert.equal(state.setups, 3);
	// The resend carries the same request, and progress reports each phase once.
	assert.deepEqual(state.exchanges[2].sealed, state.exchanges[1].sealed);
	assert.deepEqual(phases, ['securing', 'encrypting', 'sending', 'acknowledged']);
	assert.deepEqual(
		state.cores.map((core) => [core.closed, core.freed]),
		[
			[true, false],
			[true, true],
			[false, false]
		]
	);
	// Work admitted before the refusal still finishes on its session.
	output.enqueue(record(2, 'open'));
	output.enqueue(record(3));
	output.close();
	assert.equal(await open.text(), 'open');
	assert.equal(state.cores[0].freed, true);
	await (await state.send()).text();
	assert.equal(state.setups, 3);
	await state.transport.close();
});

test('the refusal stands when no other session can start', async () => {
	const state = fixture({
		fetchSetup: () =>
			state.setups === 1
				? new Response(new Uint8Array([12]), { headers: { 'content-type': SESSION_CONTENT_TYPE } })
				: new Response(null, { status: 503 }),
		fetchResponse: refusal
	});
	const refused = await state.send();
	assert.equal(refused.status, 503);
	assert.equal(refused.headers.get('retry-after'), '1');
	assert.deepEqual(await refused.json(), { error: 'gateway_draining' });
	assert.equal(state.setups, 2);
	assert.equal(state.requests, 1);
	assert.equal(state.cores[0].freed, true);
	await state.transport.close();
});

test('a request is resent at most once and never after an ordinary 503', async () => {
	const state = fixture({ fetchResponse: refusal });
	const refused = await state.send();
	assert.equal(refused.status, 503);
	await refused.text();
	assert.deepEqual(state.nodes, ['node-0', 'node-1']);
	await state.transport.close();

	const busy = fixture({
		fetchResponse: () =>
			response([record(1, '{"status":503,"headers":{"retry-after":"1"}}'), record(3)])
	});
	assert.equal((await busy.send()).status, 503);
	assert.equal(busy.requests, 1);
	assert.equal(busy.cores[0].closed, false);
	await busy.transport.close();
});

test('evidence recovery verifies the same setup before any application credentials leave', async () => {
	let verified = 0;
	const state = fixture({
		verify(bytes, snapshot) {
			verified++;
			assert.deepEqual([...bytes], [12]);
			if (snapshot === 1)
				throw Object.assign(new Error('missing release'), { name: 'EvidenceVerificationError' });
		}
	});
	await (await state.send()).text();
	assert.equal(state.setups, 1);
	assert.equal(state.requests, 1);
	assert.equal(state.acquisitions, 1);
	assert.equal(verified, 2);
	await state.transport.close();
});

test('invalid setup possession fails closed without refreshing or sending inference', async () => {
	const state = fixture({
		verify() {
			throw new Error('invalid confirmation');
		}
	});
	await assert.rejects(state.send(), { submission: 'not_sent' });
	assert.equal(state.requests, 0);
	assert.equal(state.acquisitions, 0);
	assert.equal(state.setupFreed, 1);
	await state.transport.close();
});

test('a lost request is never retried; subsequent new work establishes another owner', async () => {
	const state = fixture({
		fetchResponse: async (_options, count) =>
			count === 1
				? new Response(null, { status: 503 })
				: response([record(1, '{"status":200,"headers":{}}'), record(3)])
	});
	await assert.rejects(state.send(), { submission: 'execution_unknown' });
	assert.equal(state.requests, 1);
	await (await state.send()).text();
	assert.equal(state.requests, 2);
	assert.equal(state.setups, 2);
	assert.equal(state.cores[0].freed, true);
	await state.transport.close();
});

test('midstream failure retires only future use while admitted responses keep their keys', async () => {
	const state = fixture({
		fetchResponse: async (_options, count) =>
			count === 2
				? response([record(1, '{"status":200,"headers":{}}'), record(2, 'partial')])
				: response([record(1, '{"status":200,"headers":{}}'), record(3)])
	});
	const first = await state.send();
	const broken = await state.send();
	await assert.rejects(broken.text(), { submission: 'execution_unknown' });
	assert.equal(state.cores[0].closed, true);
	assert.equal(state.cores[0].freed, false);
	await (await state.send()).text();
	assert.equal(state.setups, 2);
	await first.text();
	assert.equal(state.cores[0].freed, true);
	await state.transport.close();
});

test('session growth follows actual replay-window pressure and honors the caller maximum', async () => {
	const pending = new Set();
	const state = fixture({
		maxSessions: 2,
		request(_snapshot, owner) {
			if (pending.has(owner.node_id))
				throw Object.assign(new Error('pending'), {
					name: 'EncryptedChannelError',
					code: 'pending'
				});
		}
	});
	await (await state.send()).text();
	pending.add('node-0');
	await (await state.send()).text();
	assert.equal(state.setups, 2);
	pending.add('node-1');
	const cancel = new AbortController();
	let returned = false;
	const waiting = state.send(cancel.signal).finally(() => {
		returned = true;
	});
	await new Promise((resolve) => setImmediate(resolve));
	assert.equal(returned, false);
	cancel.abort();
	await assert.rejects(waiting, { submission: 'not_sent' });
	assert.equal(state.requests, 2);
	assert.equal(state.setups, 2);
	pending.clear();
	await state.transport.close();
});

test('an authenticated ACK releases pool capacity before provider headers or body completion', async () => {
	let pending = false;
	let output;
	let started;
	const entered = new Promise((resolve) => {
		started = resolve;
	});
	const state = fixture({
		request() {
			if (pending)
				throw Object.assign(new Error('pending'), {
					name: 'EncryptedChannelError',
					code: 'pending'
				});
			pending = true;
		},
		fetchResponse(_options, count) {
			if (count !== 1) {
				pending = false;
				return response([record(1, '{"status":200,"headers":{}}'), record(3)]);
			}
			return new Response(
				new ReadableStream({
					start(controller) {
						output = controller;
						started();
					}
				}),
				{ headers: { 'content-type': SESSION_CONTENT_TYPE } }
			);
		}
	});
	let firstReturned = false;
	const first = state.send().then((response) => {
		firstReturned = true;
		return response;
	});
	await entered;
	const second = state.send();
	await new Promise((resolve) => setImmediate(resolve));
	assert.equal(state.requests, 1);
	pending = false;
	output.enqueue(record(4));
	await (await second).text();
	assert.equal(state.requests, 2);
	assert.equal(state.setups, 1);
	assert.equal(firstReturned, false);
	output.enqueue(record(1, '{"status":200,"headers":{}}'));
	output.enqueue(record(3));
	output.close();
	await (await first).text();
	await state.transport.close();
});

test('local cancellation after authenticated feedback keeps the session for independent requests', async () => {
	const state = fixture({
		fetchResponse(_options, count) {
			if (count !== 1) return response([record(1, '{"status":200,"headers":{}}'), record(3)]);
			return new Response(
				new ReadableStream({
					start(controller) {
						controller.enqueue(record(4));
						controller.enqueue(record(1, '{"status":200,"headers":{}}'));
						controller.enqueue(record(2, 'partial'));
					}
				}),
				{ headers: { 'content-type': SESSION_CONTENT_TYPE } }
			);
		}
	});
	const cancel = new AbortController();
	const partial = await state.send(cancel.signal);
	cancel.abort();
	await assert.rejects(partial.text(), { submission: 'execution_unknown' });
	assert.equal(state.cores[0].closed, false);
	await (await state.send()).text();
	assert.equal(state.setups, 1);
	assert.equal(state.requests, 2);
	await state.transport.close();
});

test('close aborts a pending setup and never releases application bytes', async () => {
	let aborted = 0;
	let started;
	const ready = new Promise((resolve) => {
		started = resolve;
	});
	const state = fixture({
		fetchSetup: ({ signal }) =>
			new Promise((_resolve, reject) => {
				signal.addEventListener(
					'abort',
					() => {
						aborted++;
						reject(signal.reason);
					},
					{ once: true }
				);
				started();
			})
	});
	const waiting = state.send();
	await ready;
	await state.transport.close();
	await assert.rejects(waiting, { submission: 'not_sent' });
	assert.equal(aborted, 1);
	assert.equal(state.requests, 0);
	assert.equal(state.setupFreed, 1);
});

test('setup carriage accepts the full hybrid evidence bound and rejects one extra byte before verification', async () => {
	// 2378-byte server prefix, 32-byte confirmation, 4-byte evidence length,
	// and the shared 58-KiB evidence maximum. The core tests validate contents.
	const maximum = 2378 + 32 + 4 + 58 * 1024;
	for (const size of [maximum, maximum + 1]) {
		let checked = 0;
		const state = fixture({
			fetchSetup: () =>
				new Response(new Uint8Array(size), { headers: { 'content-type': SESSION_CONTENT_TYPE } }),
			verify: (bytes) => {
				checked++;
				assert.equal(bytes.byteLength, maximum);
			}
		});
		if (size === maximum) {
			assert.deepEqual(await (await state.send()).json(), { ok: true });
			assert.equal(checked, 1);
		} else {
			await assert.rejects(state.send(), { submission: 'not_sent' });
			assert.equal(checked, 0);
			assert.equal(state.requests, 0);
		}
		assert.equal(state.setupFreed, 1);
		await state.transport.close();
	}
});

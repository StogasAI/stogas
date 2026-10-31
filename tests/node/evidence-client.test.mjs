import assert from 'node:assert/strict';
import { test } from 'node:test';
import { EvidenceClient } from '../../bindings/shared/evidence-client.js';

const origins = [
	'https://evidence.example/evidence/latest.json',
	'https://replica.example/evidence/latest.json'
];
// Only delivery/ownership is doubled here. Signed decision and CRL behavior is
// exercised by Rust and packaged Wasm tests against genuine evidence.
function verifier() {
	let retired = false;
	let current;
	return {
		freed: false,
		refresh(bytes) {
			assert.equal(this.freed, false);
			const text = new TextDecoder().decode(bytes);
			const { revision, invalid, retire } = JSON.parse(text);
			if (retire) retired = true;
			if (invalid) throw new Error('invalid evidence');
			// As in Rust, repeated bytes return another handle to the current snapshot.
			if (current?.text !== text) current = { text };
			const core = current;
			return {
				revision,
				core,
				freed: false,
				same_as(other) {
					return other.core === core;
				},
				require_current_keys() {
					assert.equal(this.freed, false);
					if (retired) throw new Error('retired key');
				},
				summary() {
					return { revision };
				},
				free() {
					assert.equal(this.freed, false);
					this.freed = true;
				}
			};
		},
		free() {
			assert.equal(this.freed, false);
			this.freed = true;
		}
	};
}
function response(revision, etag, extra = {}) {
	return Response.json({ revision, ...extra }, { headers: etag ? { etag } : {} });
}
const requireRevision = (revision) => (snapshot) => {
	if (snapshot.revision < revision) throw new Error('unknown release');
	return snapshot.revision;
};

test('R2-first recovery checks progress before accepting 200/304 and keeps origin ETags separate', async () => {
	const calls = [];
	let stage = 0;
	const client = new EvidenceClient(verifier(), origins, async (url, options) => {
		calls.push({ url, options });
		if (url === origins[0])
			return stage === 0 ? response(1, 'r2-1') : new Response(null, { status: 304 });
		return response(2, 'aws-2');
	});
	assert.deepEqual(await client.acquire(), { revision: 1 });
	stage = 1;
	assert.equal(await client.acquire(undefined, requireRevision(2)), 2);
	assert.deepEqual(
		calls.map((call) => call.url),
		[origins[0], origins[0], origins[1]]
	);
	assert.equal(calls[1].options.headers['if-none-match'], 'r2-1');
	assert.equal(calls[2].options.headers['if-none-match'], undefined);
	assert.equal(
		calls.every(({ options }) => options.credentials === 'omit' && options.redirect === 'manual'),
		true
	);
	client.close();
});

test('concurrent misses share acquisition and reuse its verified result', async () => {
	let calls = 0;
	let release;
	const waiting = new Promise((resolve) => {
		release = resolve;
	});
	const client = new EvidenceClient(verifier(), origins, async () => {
		calls++;
		await waiting;
		return response(2);
	});
	const requests = Array.from({ length: 20 }, () => client.acquire(undefined, requireRevision(2)));
	release();
	assert.deepEqual(await Promise.all(requests), Array(20).fill(2));
	assert.equal(calls, 1);
	client.close();
});

test('one canceled waiter does not cancel another caller acquisition', async () => {
	let release;
	const waiting = new Promise((resolve) => {
		release = resolve;
	});
	const client = new EvidenceClient(verifier(), origins, async () => {
		await waiting;
		return response(1);
	});
	const first = client.acquire();
	const abort = new AbortController();
	const other = client.acquire(abort.signal);
	abort.abort();
	await assert.rejects(other, { name: 'AbortError' });
	release();
	assert.deepEqual(await first, { revision: 1 });
	client.close();
});

test('invalid delivery preserves usable state but authentic retirement still constrains it', async () => {
	let mode = 'normal';
	const client = new EvidenceClient(verifier(), origins, async () =>
		response(1, undefined, mode === 'normal' ? {} : { invalid: true, retire: mode === 'retire' })
	);
	await client.acquire();
	mode = 'invalid';
	await assert.rejects(client.acquire(), /invalid evidence/);
	assert.equal(client.check(requireRevision(1)), 1);
	client.close();
	const revoked = new EvidenceClient(verifier(), origins, async () =>
		response(1, undefined, mode === 'normal' ? {} : { invalid: true, retire: true })
	);
	mode = 'normal';
	await revoked.acquire();
	mode = 'retire';
	await assert.rejects(revoked.acquire(), /invalid evidence/);
	assert.throws(() => revoked.check(requireRevision(1)), /retired key/);
	revoked.close();
});

test('304 without origin representation fails and failed lookups share a cooldown', async (t) => {
	let wall = 1_800_000_000_000;
	t.mock.method(Date, 'now', () => wall);
	let calls = 0;
	const client = new EvidenceClient(verifier(), origins, async () => {
		calls++;
		return new Response(null, { status: 304 });
	});
	await assert.rejects(client.acquire(), /HTTP 304/);
	wall += 4_499;
	await assert.rejects(client.acquire(), /cooling down/);
	assert.equal(calls, 2);
	// A clock that moved back ends the cooldown instead of extending it.
	wall -= 3_600_000;
	await assert.rejects(client.acquire(), /HTTP 304/);
	await assert.rejects(client.acquire(), /cooling down/);
	assert.equal(calls, 4);
	wall += 5_501;
	await assert.rejects(client.acquire(), /HTTP 304/);
	assert.equal(calls, 6);
	client.close();
});

test('a slow primary starts the replica after a second, and the first verified answer wins', async () => {
	await Promise.all(
		origins.map(async (winner, index) => {
			const answers = new Map();
			const canceled = [];
			let replicaStarted;
			const replica = new Promise((resolve) => {
				replicaStarted = resolve;
			});
			const client = new EvidenceClient(
				verifier(),
				origins,
				(url, { signal }) =>
					new Promise((resolve, reject) => {
						answers.set(url, resolve);
						if (url === origins[1]) replicaStarted(performance.now());
						signal.addEventListener(
							'abort',
							() => {
								canceled.push(url);
								reject(signal.reason);
							},
							{ once: true }
						);
					})
			);
			const started = performance.now();
			const loading = client.acquire();
			assert.deepEqual([...answers.keys()], [origins[0]]);
			// Well before the primary's own five-second limit.
			const delay = (await replica) - started;
			assert.ok(delay >= 900 && delay < 4_000, `replica started after ${delay} ms`);
			answers.get(winner)(response(index + 1));
			assert.deepEqual(await loading, { revision: index + 1 });
			assert.deepEqual(
				canceled,
				origins.filter((url) => url !== winner)
			);
			client.close();
		})
	);
});

test('closing during acquisition cancels network work before freeing the verifier', async () => {
	let aborted = 0;
	const core = verifier();
	const client = new EvidenceClient(
		core,
		origins,
		async (_url, { signal }) =>
			new Promise((_resolve, reject) => {
				signal.addEventListener(
					'abort',
					() => {
						aborted++;
						reject(signal.reason);
					},
					{ once: true }
				);
			})
	);
	const loading = client.acquire();
	client.close();
	await assert.rejects(loading, { name: 'AbortError' });
	assert.equal(aborted, 1);
	assert.equal(core.freed, true);
	client.close();
});

test('measured checks follow actual verification and observer failures cannot reject evidence', async () => {
	const core = verifier();
	const refresh = core.refresh.bind(core);
	core.refresh = (bytes, observe) => {
		observe({ step: 'key_manifest', reference: null, cached: false });
		const snapshot = refresh(bytes);
		observe({ step: 'accepted', reference: null, cached: false });
		return snapshot;
	};
	let snapshot;
	const client = new EvidenceClient(
		core,
		origins,
		async () => response(7),
		(value) => {
			snapshot = value;
			throw new Error('display failed');
		}
	);
	assert.deepEqual(await client.acquire(), { revision: 7 });
	assert.deepEqual(
		snapshot.verificationChecks.map((check) => check.step),
		['key_manifest', 'accepted']
	);
	assert.ok(
		snapshot.verificationChecks.every(
			(check) => Number.isFinite(check.durationMs) && check.durationMs >= 0
		)
	);
	assert.ok(
		snapshot.verificationDurationMs >=
			snapshot.verificationChecks.reduce((total, check) => total + check.durationMs, 0)
	);
	client.close();
});

test('fetch and verification timings include fallback work, and a repeated delivery keeps its report', async (t) => {
	let now = 0;
	t.mock.method(performance, 'now', () => now);
	const core = verifier();
	const refresh = core.refresh.bind(core);
	let warm = false;
	core.refresh = (bytes, observe) => {
		now += warm ? 3 : 12;
		observe({ step: 'gateway_release', reference: 'release', cached: warm });
		return refresh(bytes);
	};
	const snapshots = [];
	let revision = 2;
	const client = new EvidenceClient(
		core,
		origins,
		async (url, options) => {
			now += 20;
			if (url === origins[0]) return response(1, undefined, { invalid: true });
			if (warm && revision === 2) {
				assert.equal(options.headers['if-none-match'], 'accepted');
				return new Response(null, { status: 304 });
			}
			return response(revision, 'accepted');
		},
		(snapshot) => snapshots.push(snapshot)
	);
	await client.acquire();
	assert.equal(snapshots[0].fetchDurationMs, 40);
	assert.equal(snapshots[0].verificationDurationMs, 24);
	assert.equal(snapshots[0].verificationChecks[0].durationMs, 12);
	warm = true;
	assert.equal(await client.acquire(), snapshots[0].evidence);
	// The 304 repeats the accepted bytes, so the summary and report stay the same objects.
	assert.equal(snapshots[1].fetchDurationMs, 40);
	assert.equal(snapshots[1].evidence, snapshots[0].evidence);
	assert.equal(snapshots[1].verificationChecks, snapshots[0].verificationChecks);
	assert.equal(snapshots[1].verificationDurationMs, 24);
	assert.ok(
		Object.isFrozen(snapshots[1].evidence) && Object.isFrozen(snapshots[1].verificationChecks[0])
	);
	revision = 3;
	await client.acquire();
	assert.deepEqual(snapshots[2].evidence, { revision: 3 });
	assert.equal(snapshots[2].verificationDurationMs, 6);
	assert.equal(snapshots[2].verificationChecks[0].cached, true);
	assert.equal(snapshots[2].verificationChecks[0].durationMs, 3);
	client.close();
});

test('a failed candidate never replaces accepted evidence while the replica is verified', async () => {
	const core = verifier();
	const refresh = core.refresh.bind(core);
	core.refresh = (bytes, observe) => {
		observe({ step: 'decode', reference: null, cached: false });
		const snapshot = refresh(bytes);
		observe({ step: 'accepted', reference: null, cached: false });
		return snapshot;
	};
	const accepted = [];
	const retained = [];
	let revision = 7;
	let invalid = false;
	const client = new EvidenceClient(
		core,
		origins,
		async (url) => {
			if (url === origins[1]) retained.push(client.check((current) => current.revision));
			return response(revision, undefined, { invalid: invalid && url === origins[0] });
		},
		(snapshot) => accepted.push(snapshot)
	);
	await client.acquire();
	invalid = true;
	revision = 8;
	await client.acquire();
	assert.deepEqual(retained, [7]);
	assert.deepEqual(
		accepted.map((snapshot) => snapshot.evidence),
		[{ revision: 7 }, { revision: 8 }]
	);
	assert.deepEqual(
		accepted[1].verificationChecks.map((check) => check.step),
		['decode', 'accepted']
	);
	client.close();
});

// What each origin does with every request of a case. The fake verifier takes no time, so real
// timers give the race's exact timing.
const BEHAVIORS = [
	'fresh',
	'stale',
	'corrupt',
	'unavailable',
	'missing',
	'oversized',
	'unmodified',
	'refused',
	'slow',
	'hung'
];
const SLOW_MS = 2_000;
const HEDGE_MS = 1_000;
const ORIGIN_MS = 5_000;
// Revision 2 satisfies a check that needs it; revision 1 verifies without satisfying it.
const ETAGS = { 1: '"old"', 2: '"latest"' };

function serve(behavior, etag, signal) {
	switch (behavior) {
		case 'fresh':
		case 'stale': {
			const revision = behavior === 'fresh' ? 2 : 1;
			return etag === ETAGS[revision]
				? new Response(null, { status: 304 })
				: response(revision, ETAGS[revision]);
		}
		case 'corrupt':
			return response(9, '"corrupt"', { invalid: true });
		case 'unavailable':
			return new Response(null, { status: 503 });
		case 'missing':
			return new Response(null, { status: 404 });
		case 'oversized':
			return new Response(new Uint8Array(1), {
				headers: { 'content-length': String(16 * 1024 * 1024 + 1) }
			});
		case 'unmodified':
			return new Response(null, { status: 304 });
		case 'refused':
			throw new TypeError('fetch failed');
		default:
			return new Promise((resolve, reject) => {
				const timer =
					behavior === 'slow' ? setTimeout(() => resolve(response(2, ETAGS[2])), SLOW_MS) : 0;
				signal.addEventListener(
					'abort',
					() => {
						clearTimeout(timer);
						reject(signal.reason);
					},
					{ once: true }
				);
			});
	}
}

function failureOf(error) {
	if (error?.name === 'TimeoutError') return 'deadline';
	if (error instanceof TypeError) return 'delivery';
	const message = String(error?.message);
	if (/unknown release|invalid evidence/.test(message)) return 'verification';
	if (/byte limit/.test(message)) return 'too large';
	if (/cooling down/.test(message)) return 'cooldown';
	const status = /HTTP (\d+)/.exec(message);
	if (status) return `http ${status[1]}`;
	throw error;
}

// The model of the hedged race, as the Rust client's test states it.
function expected({ behaviors, check, warm }) {
	const held = [warm ? 1 : undefined, undefined];
	const answer = (index, start) => {
		const [after, delivered] = {
			fresh: [0, { revision: 2 }],
			stale: [0, { revision: 1 }],
			corrupt: [0, { failure: 'verification' }],
			unavailable: [0, { failure: 'http 503' }],
			missing: [0, { failure: 'http 404' }],
			oversized: [0, { failure: 'too large' }],
			unmodified: [0, held[index] ? { revision: held[index] } : { failure: 'http 304' }],
			refused: [0, { failure: 'delivery' }],
			slow: [SLOW_MS, { revision: 2 }],
			hung: [ORIGIN_MS, { failure: 'deadline' }]
		}[behaviors[index]];
		const satisfied = check && delivered.revision === 1 ? { failure: 'verification' } : delivered;
		return { at: start + after, index, delivered, satisfied };
	};
	const primary = answer(0, 0);
	// The replica starts when the primary fails or at the hedge delay, whichever is first.
	const replicaStart =
		primary.satisfied.failure || primary.at >= HEDGE_MS ? Math.min(primary.at, HEDGE_MS) : null;
	const answers = [primary];
	if (replicaStart !== null) answers.push(answer(1, replicaStart));
	// Stable, so a primary that fails at once is handled before the replica it starts.
	answers.sort((a, b) => a.at - b.at);
	let current = held[0];
	const cached = held.map((revision) => ETAGS[revision] ?? null);
	let outcome;
	for (const next of answers) {
		// Every verified copy becomes current and makes its origin's next request conditional.
		if (next.delivered.revision) {
			current = Math.max(current ?? 0, next.delivered.revision);
			cached[next.index] = ETAGS[next.delivered.revision];
		}
		outcome = next;
		if (!next.satisfied.failure) break;
	}
	const requests = [[0, ETAGS[held[0]] ?? null]];
	if (replicaStart !== null) requests.push([1, null]);
	return {
		state: { result: outcome.satisfied, requests, current },
		cached,
		elapsed: outcome.at
	};
}

test('every pair of origin behaviors follows the hedged acquisition model', async (t) => {
	const realNow = Date.now.bind(Date);
	let skipped = 0;
	t.mock.method(Date, 'now', () => realNow() + skipped);
	const cases = BEHAVIORS.flatMap((primary) =>
		BEHAVIORS.flatMap((replica) =>
			[false, true].flatMap((check) =>
				[false, true].map((warm) => ({ behaviors: [primary, replica], check, warm }))
			)
		)
	);
	assert.equal(cases.length, 400);
	const run = async (kase) => {
		const log = [];
		let behaviors = ['stale', 'stale'];
		const client = new EvidenceClient(verifier(), origins, async (url, { signal, headers }) => {
			const index = origins.indexOf(url);
			const etag = headers['if-none-match'] ?? null;
			log.push([index, etag]);
			return serve(behaviors[index], etag, signal);
		});
		if (kase.warm) await client.acquire();
		log.length = 0;
		behaviors = kase.behaviors;
		const { state, cached, elapsed } = expected(kase);
		const check = kase.check ? requireRevision(2) : undefined;
		const started = performance.now();
		let result;
		try {
			const value = await client.acquire(undefined, check);
			result = { revision: kase.check ? value : value.revision };
		} catch (error) {
			result = { failure: failureOf(error) };
		}
		const took = performance.now() - started;
		let current;
		try {
			current = client.check((snapshot) => snapshot.revision);
		} catch {
			current = undefined;
		}
		const label = JSON.stringify(kase);
		assert.deepEqual({ result, requests: log.splice(0), current }, state, label);
		assert.ok(took >= elapsed - 2 && took < elapsed + 250, `${label} took ${took} ms`);
		if (result.failure) {
			// A failed acquisition pauses every caller without contacting either origin.
			await assert.rejects(client.acquire(undefined, check), /cooling down/, label);
			assert.equal(log.length, 0, label);
		}
		// After every pause, a request to each origin shows the copy the client kept for it.
		return async () => {
			behaviors = ['unavailable', 'unavailable'];
			await assert.rejects(client.acquire(), /HTTP 503/, label);
			assert.deepEqual(log.splice(0), [
				[0, cached[0]],
				[1, cached[1]]
			]);
			client.close();
		};
	};
	const probes = await Promise.all(cases.map(run));
	skipped = 60_000;
	await Promise.all(probes.map((probe) => probe()));
});

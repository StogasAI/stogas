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
	return {
		freed: false,
		refresh(bytes) {
			assert.equal(this.freed, false);
			const { revision, invalid, retire } = JSON.parse(new TextDecoder().decode(bytes));
			if (retire) retired = true;
			if (invalid) throw new Error('invalid evidence');
			return {
				revision,
				freed: false,
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

test('304 without origin representation fails and failed lookups share a cooldown', async () => {
	let calls = 0;
	const client = new EvidenceClient(verifier(), origins, async () => {
		calls++;
		return new Response(null, { status: 304 });
	});
	await assert.rejects(client.acquire(), /HTTP 304/);
	await assert.rejects(client.acquire(), /cooling down/);
	assert.equal(calls, 2);
	client.close();
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
		observe({ step: 'signing_manifest', reference: null, cached: false });
		const snapshot = refresh(bytes);
		observe({ step: 'accepted', reference: null, cached: false });
		return snapshot;
	};
	const progress = [];
	let snapshot;
	const client = new EvidenceClient(
		core,
		origins,
		async () => response(7),
		(value) => {
			snapshot = value;
		},
		(checks) => {
			progress.push(checks);
			throw new Error('display failed');
		}
	);
	assert.deepEqual(await client.acquire(), { revision: 7 });
	assert.deepEqual(
		progress.map((checks) => checks.length),
		[1, 2]
	);
	assert.deepEqual(
		snapshot.verificationChecks.map((check) => check.step),
		['signing_manifest', 'accepted']
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

test('fetch and verification timings include fallback work but exclude observers on warm refresh', async (t) => {
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
	const client = new EvidenceClient(
		core,
		origins,
		async (url, options) => {
			now += 20;
			if (url === origins[0]) return response(1, undefined, { invalid: true });
			if (warm) {
				assert.equal(options.headers['if-none-match'], 'accepted');
				return new Response(null, { status: 304 });
			}
			return response(2, 'accepted');
		},
		(snapshot) => snapshots.push(snapshot),
		() => {
			now += 100;
		}
	);
	await client.acquire();
	assert.equal(snapshots[0].fetchDurationMs, 40);
	assert.equal(snapshots[0].verificationDurationMs, 24);
	assert.equal(snapshots[0].verificationChecks[0].durationMs, 12);
	warm = true;
	await client.acquire();
	assert.equal(snapshots[1].fetchDurationMs, 40);
	assert.equal(snapshots[1].verificationDurationMs, 6);
	assert.equal(snapshots[1].verificationChecks[0].cached, true);
	assert.equal(snapshots[1].verificationChecks[0].durationMs, 3);
	client.close();
});

test('failed candidate progress clears before replica verification without replacing accepted evidence', async () => {
	const core = verifier();
	const refresh = core.refresh.bind(core);
	core.refresh = (bytes, observe) => {
		observe({ step: 'decode', reference: null, cached: false });
		const snapshot = refresh(bytes);
		observe({ step: 'accepted', reference: null, cached: false });
		return snapshot;
	};
	const progress = [];
	const accepted = [];
	const retained = [];
	let invalid = false;
	const client = new EvidenceClient(
		core,
		origins,
		async (url) => response(7, undefined, { invalid: invalid && url === origins[0] }),
		(snapshot) => accepted.push(snapshot),
		(checks) => {
			progress.push(checks?.map((check) => check.step) ?? null);
			if (checks === null) retained.push(client.check((current) => current.summary()));
		}
	);
	await client.acquire();
	progress.length = 0;
	invalid = true;
	await client.acquire();
	assert.deepEqual(progress, [['decode'], null, ['decode'], ['decode', 'accepted']]);
	assert.equal(accepted.length, 2);
	assert.deepEqual(retained, [{ revision: 7 }]);
	assert.deepEqual(
		accepted[1].verificationChecks.map((check) => check.step),
		['decode', 'accepted']
	);
	client.close();
});

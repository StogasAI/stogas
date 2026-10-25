import { readBoundedBody } from './http.js';

const MAX_EVIDENCE_BYTES = 16 * 1024 * 1024;
const ORIGIN_TIMEOUT_MS = 5_000;
export const SETUP_TIMEOUT_MS = 15_000;

export function deadlineSignal(signal, milliseconds) {
	const controller = new AbortController();
	const abort = () => controller.abort(signal.reason);
	signal?.addEventListener('abort', abort, { once: true });
	const timeout = setTimeout(
		() => controller.abort(new DOMException('Setup deadline expired', 'TimeoutError')),
		Math.max(0, milliseconds)
	);
	timeout.unref?.();
	if (signal?.aborted) abort();
	return {
		signal: controller.signal,
		dispose() {
			clearTimeout(timeout);
			signal?.removeEventListener('abort', abort);
		}
	};
}

export function waitWithSignal(promise, signal) {
	if (!signal) return promise;
	return new Promise((resolve, reject) => {
		const abort = () => reject(signal.reason);
		signal.addEventListener('abort', abort, { once: true });
		if (signal.aborted) abort();
		promise.then(resolve, reject).finally(() => signal.removeEventListener('abort', abort));
	});
}

// Every observer receives the same summary, so none of them can change it.
function deepFreeze(value) {
	if (value && typeof value === 'object' && !Object.isFrozen(value)) {
		Object.freeze(value);
		for (const child of Object.values(value)) deepFreeze(child);
	}
	return value;
}

// One network acquisition, two origin-specific representations and one current
// Rust snapshot. No polling, third-party fetches or per-missing-object registry.
export class EvidenceClient {
	#verifier;
	#fetch;
	#origins;
	#representations;
	#current;
	// The current snapshot's frozen summary and the report of the verification that accepted it.
	#accepted;
	#pending;
	#onSnapshot;
	#retryAt = 0;
	#closed = new AbortController();

	constructor(verifier, origins, fetch, onSnapshot = () => {}) {
		this.#verifier = verifier;
		this.#fetch = fetch;
		this.#origins = origins;
		this.#representations = origins.map(() => undefined);
		this.#onSnapshot = onSnapshot;
	}

	check(check) {
		if (!this.#current) throw new Error('evidence has not been initialized');
		this.#current.require_current_keys();
		return check(this.#current);
	}

	// Check is synchronous and must not consume a setup secret on failure. A
	// successful check may return its newly verified session directly.
	async acquire(signal, check) {
		const deadline = deadlineSignal(signal, SETUP_TIMEOUT_MS);
		const combined = AbortSignal.any([deadline.signal, this.#closed.signal]);
		try {
			combined.throwIfAborted();
			if (check && this.#current) {
				try {
					this.#current.require_current_keys();
					return check(this.#current);
				} catch {
					/* Try current evidence once. */
				}
			}
			const previous = this.#current;
			while (this.#pending) {
				await waitWithSignal(
					this.#pending.catch(() => {}),
					combined
				);
				combined.throwIfAborted();
				if (this.#current) {
					if (check) {
						try {
							this.#current.require_current_keys();
							return check(this.#current);
						} catch {
							/* The other caller may have needed different evidence. */
						}
					} else if (this.#current !== previous) {
						return this.#accepted.evidence;
					}
				}
			}
			if (Date.now() < this.#retryAt) throw new Error('evidence recovery is cooling down');
			const pending = this.#load(combined, check);
			this.#pending = pending;
			try {
				return await pending;
			} finally {
				if (this.#pending === pending) this.#pending = undefined;
			}
		} finally {
			deadline.dispose();
		}
	}

	async #load(signal, check) {
		let failure;
		let fetchDurationMs = 0;
		let verificationDurationMs = 0;
		for (let index = 0; index < this.#origins.length; index++) {
			signal.throwIfAborted();
			const attempt = deadlineSignal(signal, ORIGIN_TIMEOUT_MS);
			try {
				const fetching = performance.now();
				let representation;
				try {
					representation = await this.#loadRepresentation(index, attempt.signal);
				} finally {
					fetchDurationMs += performance.now() - fetching;
				}
				attempt.signal.throwIfAborted();
				// Rust retains authentic revocations even if another candidate object
				// fails validation. A 304 still rechecks time and those decisions.
				const started = performance.now();
				let checkpoint = started;
				const verificationChecks = [];
				const observe = (check) => {
					const finished = performance.now();
					verificationChecks.push(Object.freeze({ ...check, durationMs: finished - checkpoint }));
					checkpoint = finished;
				};
				let snapshot;
				try {
					snapshot = this.#verifier.refresh(representation.bytes, observe);
				} finally {
					verificationDurationMs += performance.now() - started;
				}
				this.#representations[index] = representation;
				const old = this.#current;
				// Repeated bytes return the current snapshot, which keeps its summary and the
				// report of the verification that accepted it.
				if (!old?.same_as(snapshot)) {
					this.#accepted = {
						evidence: deepFreeze(snapshot.summary()),
						verificationDurationMs,
						verificationChecks: Object.freeze(verificationChecks)
					};
				}
				this.#current = snapshot;
				old?.free(); // Requests own independent Arc-backed snapshot handles.
				try {
					this.#onSnapshot({
						...this.#accepted,
						evidenceURL: this.#origins[index],
						fetchedAtUnixMs: Date.now(),
						fetchDurationMs
					});
				} catch {
					/* An observer cannot change authenticated state or delivery. */
				}
				snapshot.require_current_keys();
				const result = check ? check(snapshot) : this.#accepted.evidence;
				this.#retryAt = 0;
				return result;
			} catch (error) {
				failure = error;
			} finally {
				attempt.dispose();
			}
		}
		signal.throwIfAborted();
		this.#retryAt = Date.now() + 4_500 + Math.floor(Math.random() * 1_001);
		throw failure;
	}

	async #loadRepresentation(index, signal) {
		const cached = this.#representations[index];
		const response = await this.#fetch(this.#origins[index], {
			method: 'GET',
			credentials: 'omit',
			redirect: 'manual',
			signal,
			headers: {
				accept: 'application/json',
				...(cached?.etag ? { 'if-none-match': cached.etag } : {})
			}
		});
		if (response.status === 304 && cached) {
			await response.body?.cancel().catch(() => {});
			return cached;
		}
		if (response.status === 200) {
			const bytes = await readBoundedBody(response, MAX_EVIDENCE_BYTES, signal);
			return { bytes, etag: response.headers.get('etag') };
		}
		await response.body?.cancel().catch(() => {});
		throw new Error(`evidence origin returned HTTP ${response.status}`);
	}

	close() {
		if (this.#closed.signal.aborted) return;
		this.#closed.abort(new DOMException('Transport closed', 'AbortError'));
		this.#representations = [];
		this.#current?.free();
		this.#current = undefined;
		this.#accepted = undefined;
		this.#verifier.free();
	}
}

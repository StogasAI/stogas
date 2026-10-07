import { TransportError, readBoundedBody, notifyRequestProgress } from './http.js';
import {
	MAX_SETUP_RESPONSE_BYTES,
	SESSION_CONTENT_TYPE,
	sendSessionRequest
} from './channel-http.js';
import { SETUP_TIMEOUT_MS, deadlineSignal, waitWithSignal } from './evidence-client.js';

// The injected setup constructor is the fixed Rust verification implementation.
// This module only schedules requests and owns HTTP/session lifetimes.
export class SessionTransport {
	#Setup;
	#evidence;
	#environment;
	#endpoint;
	#fetch;
	#maximum;
	#onMetadata;
	#sessions = [];
	#opening;
	#closing;
	#closed = false;
	#shutdown = new AbortController();
	#changed = {};
	#waiters = new Set();

	constructor({ Setup, evidence, environment, endpoint, fetch, maxSessions = 1, onMetadata }) {
		if (!Number.isSafeInteger(maxSessions) || maxSessions <= 0)
			throw new RangeError('maxSessions must be a positive safe integer');

		this.#Setup = Setup;
		this.#evidence = evidence;
		this.#environment = environment;
		this.#endpoint = endpoint;
		this.#fetch = fetch;
		this.#maximum = maxSessions;
		this.#onMetadata = onMetadata;
	}

	async send(request, onProgress) {
		let selected;
		try {
			notifyRequestProgress(onProgress, 'securing');
			selected = await this.#select(
				request.signal,
				request.headers.get('Stogas-Metadata') === 'v1'
			);
		} catch (error) {
			throw new TransportError('Encrypted setup failed', 'not_sent', error);
		}
		const { owner, exchange } = selected;
		if (this.#closed) {
			exchange.free();
			this.#release(owner);
			throw new TransportError('Transport closed', 'not_sent');
		}
		return sendSessionRequest({
			exchange,
			nodeID: owner.core.node_id,
			endpoint: this.#endpoint,
			request,
			fetch: this.#fetch,
			release: () => this.#release(owner),
			retire: () => this.#retire(owner),
			onProgress: (phase) => {
				if (phase === 'acknowledged') this.#notify();
				notifyRequestProgress(onProgress, phase);
			},
			onMetadata: this.#onMetadata
		});
	}

	async #select(signal, receipt) {
		const deadline = deadlineSignal(
			AbortSignal.any([signal, this.#shutdown.signal].filter(Boolean)),
			SETUP_TIMEOUT_MS
		);
		try {
			for (;;) {
				const changed = this.#changed;
				deadline.signal.throwIfAborted();
				if (this.#closed) throw new Error('Transport closed');
				const eligible = this.#sessions
					.filter((owner) => !owner.retired)
					.sort((a, b) => a.active - b.active);
				for (const owner of eligible) {
					if (
						owner.active === 0 &&
						(Date.now() < owner.idleSince ||
							Date.now() - owner.idleSince >= owner.core.idle_seconds * 1_000)
					) {
						this.#retire(owner);
						continue;
					}
					try {
						const allocate = (snapshot) => owner.core.request(snapshot, receipt);
						let exchange;
						try {
							exchange = this.#evidence.check(allocate);
						} catch (error) {
							if (error.name === 'EncryptedChannelError') throw error;
							exchange = await this.#evidence.acquire(deadline.signal, allocate);
						}
						if (this.#closed || owner.retired) {
							exchange.free();
							throw new Error('Transport closed during setup');
						}
						owner.active++;
						this.#notify();
						return { owner, exchange };
					} catch (error) {
						if (error.name === 'EncryptedChannelError' && error.code === 'pending') {
							continue;
						}
						this.#retire(owner);
						if (error.name !== 'EncryptedChannelError' || !['closed', 'limit'].includes(error.code))
							throw error;
					}
				}
				if (this.#opening) {
					await waitWithSignal(this.#opening, deadline.signal);
					continue;
				}
				if (
					this.#sessions.filter((owner) => !owner.retired).length >= this.#maximum ||
					this.#sessions.length >= this.#maximum + 1
				) {
					await this.#wait(changed, deadline.signal);
					continue;
				}
				// Setup belongs to the transport. Canceling one waiter must not
				// cancel a shared handshake needed by another request.
				const setupDeadline = deadlineSignal(this.#shutdown.signal, SETUP_TIMEOUT_MS);
				const opening = this.#open(setupDeadline.signal).finally(() => {
					setupDeadline.dispose();
					if (this.#opening === opening) this.#opening = undefined;
					this.#notify();
				});
				this.#opening = opening;
				await waitWithSignal(opening, deadline.signal);
			}
		} finally {
			deadline.dispose();
		}
	}

	async #open(signal) {
		const setup = new this.#Setup(this.#environment);
		try {
			// Initialize evidence before setup. Acquiring it does not release any
			// application credentials and shares the same absolute setup deadline.
			try {
				this.#evidence.check(() => {});
			} catch {
				await this.#evidence.acquire(signal);
			}
			const response = await this.#fetch(this.#endpoint, {
				method: 'POST',
				body: setup.hello,
				credentials: 'omit',
				redirect: 'manual',
				signal,
				headers: { 'content-type': SESSION_CONTENT_TYPE, accept: SESSION_CONTENT_TYPE }
			});
			if (
				response.status !== 200 ||
				response.headers.get('content-type') !== SESSION_CONTENT_TYPE
			) {
				await response.body?.cancel().catch(() => {});
				throw new Error('origin did not return an encrypted setup');
			}
			const bytes = await readBoundedBody(response, MAX_SETUP_RESPONSE_BYTES, signal);
			const verify = (snapshot) => setup.complete(bytes, snapshot);
			let core;
			try {
				core = this.#evidence.check(verify);
			} catch (error) {
				// Only evidence appraisal preserves the pending setup secret. Failed
				// possession/framing is terminal and cannot become a refresh loop.
				if (error.name !== 'EvidenceVerificationError') throw error;
				core = await this.#evidence.acquire(signal, verify);
			}
			if (signal.aborted || this.#closed) {
				core.close();
				core.free();
				signal.throwIfAborted();
				throw new Error('Transport closed');
			}
			this.#sessions.push({ core, active: 0, retired: false, idleSince: Date.now() });
		} finally {
			setup.free();
		}
	}

	#retire(owner) {
		if (owner.retired) return;
		owner.retired = true;
		owner.core.close();
		if (owner.active === 0) this.#remove(owner);
		this.#notify();
	}
	#remove(owner) {
		const index = this.#sessions.indexOf(owner);
		if (index < 0) return;
		this.#sessions.splice(index, 1);
		owner.core.free();
	}
	#release(owner) {
		owner.active--;
		if (owner.active === 0) {
			owner.idleSince = Date.now();
			if (owner.retired) this.#remove(owner);
		}
		this.#notify();
	}

	#notify() {
		this.#changed = {};
		const next = this.#waiters.values().next().value;
		if (next) {
			this.#waiters.delete(next);
			next();
		}
	}

	async #wait(changed, signal) {
		if (changed !== this.#changed) return;
		let notify;
		const available = new Promise((resolve) => {
			notify = resolve;
		});
		this.#waiters.add(notify);
		try {
			await waitWithSignal(available, signal);
		} catch (error) {
			// A cancelled waiter must not consume another request's wakeup.
			this.#waiters.delete(notify);
			this.#notify();
			throw error;
		} finally {
			this.#waiters.delete(notify);
		}
	}

	// Explicit close erases local chains immediately after creating each optional
	// close exchange. Existing requests own their directional keys independently.
	close() {
		if (this.#closing) return this.#closing;
		this.#closed = true;
		this.#shutdown.abort(new DOMException('Transport closed', 'AbortError'));
		const closing = [];
		if (this.#opening) closing.push(this.#opening.catch(() => {}));
		for (const owner of [...this.#sessions]) {
			if (!owner.retired) {
				let exchange;
				try {
					exchange = this.#evidence.check((snapshot) => owner.core.request(snapshot, false));
				} catch {
					/* Idle cleanup covers lost close messages. */
				}
				if (exchange) {
					owner.active++;
					const deadline = deadlineSignal(undefined, SETUP_TIMEOUT_MS);
					closing.push(
						sendSessionRequest({
							exchange,
							nodeID: owner.core.node_id,
							endpoint: this.#endpoint,
							request: new Request(this.#endpoint, { method: 'DELETE' }),
							fetch: this.#fetch,
							signal: deadline.signal,
							release: () => this.#release(owner)
						})
							.then((response) => response.body?.cancel())
							.catch(() => {})
							.finally(() => deadline.dispose())
					);
				}
			}
			this.#retire(owner);
		}
		this.#closing = Promise.all(closing).then(() => {});
		return this.#closing;
	}
}

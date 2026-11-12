import { EvidenceClient } from './evidence-client.js';
import { SessionTransport } from './session-transport.js';
import { TransportError } from './http.js';

const PATHS = new Set([
	'/v1/chat/completions',
	'/v1/responses',
	'/v1/policies/validate',
	'/v1/policies/simulate'
]);
const OPTIONS = new Set([
	'environment',
	'baseURL',
	'maxConnections',
	'fetch',
	'onMetadata',
	'proxied',
	'encryptionKeys'
]);
// Through a proxy, such as Tor, each request crosses several relays and may wait for a new circuit,
// so every time limit is four times as long, as the Rust SDK's are through a proxy.
const PROXIED_PATIENCE = 4;

function baseURL(value) {
	let url;
	try {
		url = new URL(value);
	} catch {
		throw new TypeError('baseURL must be an HTTPS /v1 URL');
	}
	if (
		url.protocol !== 'https:' ||
		url.username ||
		url.password ||
		/[?#]/.test(url.href) ||
		!/^\/v1\/?$/.test(url.pathname)
	)
		throw new TypeError('baseURL must be an HTTPS /v1 URL without credentials, query or fragment');
	return `${url.origin}/v1`;
}

// Adds `member`, a transport's `encryption_keys`, to a JSON object that has none. The rest of the
// body keeps its text, and the gateway answers for a body that is no JSON object.
export function withEncryptionKeys(text, member) {
	let parsed;
	try {
		parsed = JSON.parse(text);
	} catch {
		return text;
	}
	if (
		parsed === null ||
		typeof parsed !== 'object' ||
		Array.isArray(parsed) ||
		Object.hasOwn(parsed, 'encryption_keys')
	)
		return text;
	const open = text.indexOf('{') + 1;
	const comma = Object.keys(parsed).length ? ',' : '';
	return `${text.slice(0, open)}${member}${comma}${text.slice(open)}`;
}

// The same Fetch adapter runs in browsers, Node and Workers. All cryptographic
// state and trust choices come from the compiled Wasm core. `proxied` is the default of the option
// of that name, such as true on a page served from an onion address.
export function createTransportClass({
	EvidenceVerifier,
	EncryptedSetup,
	transport_configuration,
	proxied: proxiedByDefault = false
}) {
	return class StogasTransport {
		#baseURL;
		#origins;
		#evidence;
		#sessions;
		#listeners = new Set();
		#closed = false;
		#closing;
		#refresh;
		// The `encryption_keys` member that requests without one receive.
		#encryptionKeys;
		// Snapshots and everything in them are frozen, so every listener shares one.
		#snapshot = Object.freeze({
			evidence: null,
			evidenceURL: null,
			error: null,
			errorCode: null,
			fetchedAtUnixMs: null,
			fetchDurationMs: null,
			verificationDurationMs: null,
			verificationChecks: Object.freeze([]),
			status: 'idle'
		});

		constructor(options = {}) {
			if (
				!options ||
				typeof options !== 'object' ||
				Array.isArray(options) ||
				Object.keys(options).some((key) => !OPTIONS.has(key))
			)
				throw new TypeError('Unsupported transport option');
			const maximum = options.maxConnections ?? 4;
			if (!Number.isSafeInteger(maximum) || maximum < 1)
				throw new RangeError('maxConnections must be a positive safe integer');
			const fetch = options.fetch ?? ((input, init) => globalThis.fetch(input, init));
			if (
				typeof fetch !== 'function' ||
				(options.onMetadata !== undefined && typeof options.onMetadata !== 'function')
			)
				throw new TypeError('fetch and onMetadata must be functions');
			const proxied = options.proxied ?? proxiedByDefault;
			if (typeof proxied !== 'boolean') throw new TypeError('proxied must be a boolean');
			const keys = options.encryptionKeys ?? {};
			if (
				!keys ||
				typeof keys !== 'object' ||
				Array.isArray(keys) ||
				Object.entries(keys).some(([label, key]) => !label || typeof key !== 'string' || !key)
			)
				throw new TypeError('encryptionKeys must give a key for each label');
			if (Object.keys(keys).length)
				this.#encryptionKeys = `"encryption_keys":${JSON.stringify(keys)}`;
			const patience = proxied ? PROXIED_PATIENCE : 1;
			const config = transport_configuration(options.environment ?? 'prod');
			this.#baseURL = baseURL(options.baseURL ?? `${config.e2ee_origin}/v1`);
			this.#origins = config.evidence_origins;
			const core = EvidenceVerifier.for_stogas(config.environment);
			this.#evidence = new EvidenceClient(
				core,
				this.#origins,
				fetch,
				(snapshot) => this.#publish({ ...snapshot, status: 'ready', error: null, errorCode: null }),
				patience
			);
			this.#sessions = new SessionTransport({
				Setup: EncryptedSetup,
				evidence: this.#evidence,
				environment: config.environment,
				endpoint: `${this.#baseURL}/session`,
				fetch,
				maxSessions: maximum,
				onMetadata: options.onMetadata,
				patience
			});
			this.fetch = this.fetch.bind(this);
		}

		static async create(options = {}) {
			const transport = new this(options);
			try {
				await transport.refreshEvidence();
				return transport;
			} catch (error) {
				await transport.close();
				throw error;
			}
		}

		get baseURL() {
			return this.#baseURL;
		}
		get evidenceURLs() {
			return [...this.#origins];
		}
		get evidenceSnapshot() {
			return this.#snapshot;
		}

		openAIOptions(apiKey) {
			this.#assertOpen();
			if (typeof apiKey !== 'string' || !apiKey) throw new TypeError('apiKey is required');
			return {
				apiKey,
				baseURL: this.#baseURL,
				dangerouslyAllowBrowser: true,
				fetch: this.fetch
			};
		}

		subscribe(listener) {
			this.#assertOpen();
			if (typeof listener !== 'function') throw new TypeError('listener must be a function');
			this.#listeners.add(listener);
			try {
				listener(this.evidenceSnapshot);
			} catch {
				this.#listeners.delete(listener);
			}
			return () => this.#listeners.delete(listener);
		}

		async refreshEvidence() {
			this.#assertOpen();
			if (this.#refresh) return this.#refresh;
			this.#publish({ ...this.#snapshot, status: 'refreshing', error: null, errorCode: null });
			const refresh = this.#evidence
				.acquire()
				.catch((error) => {
					if (!this.#closed)
						this.#publish({
							...this.#snapshot,
							status: 'error',
							error: String(error.message ?? error),
							// The verifier's own code, or evidence_unavailable when the last origin
							// delivered nothing to check.
							errorCode:
								error?.name === 'EvidenceVerificationError' ? error.code : 'evidence_unavailable'
						});
					throw error;
				})
				.finally(() => {
					if (this.#refresh === refresh) this.#refresh = undefined;
				});
			this.#refresh = refresh;
			return refresh;
		}

		async fetch(input, init) {
			this.#assertOpen();
			if (init?.onProgress !== undefined && typeof init.onProgress !== 'function')
				throw new TypeError('onProgress must be a function');
			const request = new Request(input, init);
			const url = new URL(request.url);
			if (
				url.origin !== new URL(this.#baseURL).origin ||
				!PATHS.has(url.pathname) ||
				request.method !== 'POST' ||
				url.search ||
				url.hash ||
				url.username ||
				url.password
			) {
				await request.body?.cancel().catch(() => {});
				throw new TransportError(
					'Unsupported confidential request origin, method or path',
					'not_sent'
				);
			}
			// Routing simulation takes labels and no keys.
			const keyed =
				this.#encryptionKeys && url.pathname !== '/v1/policies/simulate'
					? await this.#withEncryptionKeys(request)
					: request;
			return this.#sessions.send(keyed, init?.onProgress);
		}

		async #withEncryptionKeys(request) {
			const headers = new Headers(request.headers);
			headers.delete('content-length');
			return new Request(request.url, {
				method: 'POST',
				headers,
				body: withEncryptionKeys(await request.text(), this.#encryptionKeys),
				signal: request.signal
			});
		}

		close() {
			if (this.#closing) return this.#closing;
			this.#closed = true;
			this.#listeners.clear();
			// Close exchanges are constructed while current evidence is still owned.
			this.#closing = this.#sessions.close().finally(() => this.#evidence.close());
			return this.#closing;
		}

		#assertOpen() {
			if (this.#closed) throw new TransportError('Transport closed', 'not_sent');
		}
		#publish(snapshot) {
			if (this.#closed) return;
			this.#snapshot = Object.freeze(snapshot);
			for (const listener of this.#listeners) {
				try {
					listener(this.#snapshot);
				} catch {
					this.#listeners.delete(listener);
				}
			}
		}
	};
}

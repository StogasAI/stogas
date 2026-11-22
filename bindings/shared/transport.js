import { EvidenceClient } from './evidence-client.js';
import { SessionTransport } from './session-transport.js';
import { TransportError } from './http.js';

const PATHS = new Set([
	'/v1/chat/completions',
	'/v1/responses',
	'/v1/messages',
	'/v1/policies/validate',
	'/v1/policies/simulate'
]);
/** Whether a GET of the path reads the public catalog: the root, the model list or one part. */
const isCatalogRead = (path) =>
	path === '/v1/catalog' ||
	path === '/v1/models' ||
	/^\/v1\/catalog\/parts\/[0-9a-f]{64}$/.test(path);
// The gateway ignores a catalog read's query, such as the `limit` that Anthropic's SDKs add to a
// model list, and reads the `beta=true` that they add to a Messages request from their beta methods
// as no query. The transport sends neither, since E2EE carries no query.
const isIgnoredQuery = (url) =>
	isCatalogRead(url.pathname) || (url.pathname === '/v1/messages' && url.search === '?beta=true');
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

// The most that a request body holds, and that the gateway decodes.
const MAX_REQUEST_BYTES = 128 * 1024 * 1024;

// The body to send with `member`, a transport's `encryption_keys`, which a JSON object that has
// none gains after decoding from the gzip or deflate that `coding` names, if any. Every runtime's
// DecompressionStream reads those two. Such a body goes uncompressed and keeps the rest of its
// text. Any other body is null and goes unchanged, so the gateway answers for a body that it
// cannot read or that is no JSON object.
export async function withEncryptionKeys(bytes, coding, member) {
	let text;
	try {
		if (coding !== null) {
			const name = coding.trim().toLowerCase();
			if (name !== 'gzip' && name !== 'deflate') return null;
			bytes = await decompressed(bytes, name);
			if (bytes === null) return null;
		}
		text = new TextDecoder('utf-8', { fatal: true, ignoreBOM: true }).decode(bytes);
	} catch {
		return null;
	}
	let parsed;
	try {
		parsed = JSON.parse(text);
	} catch {
		return null;
	}
	if (
		parsed === null ||
		typeof parsed !== 'object' ||
		Array.isArray(parsed) ||
		Object.hasOwn(parsed, 'encryption_keys')
	)
		return null;
	const open = text.indexOf('{') + 1;
	const comma = Object.keys(parsed).length ? ',' : '';
	return `${text.slice(0, open)}${member}${comma}${text.slice(open)}`;
}

// The decoded bytes, or null past the gateway's limit.
async function decompressed(bytes, coding) {
	const reader = new Blob([bytes])
		.stream()
		.pipeThrough(new DecompressionStream(coding))
		.getReader();
	const chunks = [];
	let size = 0;
	for (let read = await reader.read(); !read.done; read = await reader.read()) {
		size += read.value.byteLength;
		if (size > MAX_REQUEST_BYTES) {
			await reader.cancel();
			return null;
		}
		chunks.push(read.value);
	}
	return new Uint8Array(await new Blob(chunks).arrayBuffer());
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
				request.method !== (isCatalogRead(url.pathname) ? 'GET' : 'POST') ||
				(request.method === 'POST' && !PATHS.has(url.pathname)) ||
				(url.search && !isIgnoredQuery(url)) ||
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
			// A catalog read takes no keys, and routing simulation takes labels and no keys.
			const keyed =
				this.#encryptionKeys &&
				request.method === 'POST' &&
				url.pathname !== '/v1/policies/simulate';
			const sent =
				keyed || url.search
					? await this.#rewritten(request, `${url.origin}${url.pathname}`, keyed)
					: request;
			return this.#sessions.send(sent, init?.onProgress);
		}

		// The request at `target`, the URL without its query, with the transport's keys when
		// `keyed`.
		async #rewritten(request, target, keyed) {
			const headers = new Headers(request.headers);
			if (request.method === 'GET') return new Request(target, { headers, signal: request.signal });
			const bytes = new Uint8Array(await request.arrayBuffer());
			const withKeys = keyed
				? await withEncryptionKeys(
						bytes,
						request.headers.get('content-encoding'),
						this.#encryptionKeys
					)
				: null;
			headers.delete('content-length');
			if (withKeys !== null) headers.delete('content-encoding');
			return new Request(target, {
				method: 'POST',
				headers,
				body: withKeys ?? bytes,
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

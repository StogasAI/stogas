export { default } from '../../pkg/browser/stogas.js';

export interface StogasTransportOptions {
	baseURL?: string;
	environment?: 'prod' | 'staging';
	/** One initial session, growing on capacity pressure to this maximum. Default: four. */
	maxConnections?: number;
	/** Carries every request, evidence included. One that uses a proxy, such as Tor, sends them all through it. */
	fetch?: typeof globalThis.fetch;
	/** Delivered only after the requested terminal content receipt verifies. */
	onMetadata?: (metadata: unknown) => void;
}

/** Frozen, with everything in it, and shared by every listener. */
export interface StogasEvidenceSnapshot {
	readonly evidence: unknown | null;
	readonly evidenceURL: string | null;
	readonly error: string | null;
	readonly fetchedAtUnixMs: number | null;
	readonly status: 'idle' | 'refreshing' | 'ready' | 'error';
	/** Time spent waiting for origins, from the start of acquisition until this delivery,
	 * excluding verification. A slow or failed first origin is included. */
	readonly fetchDurationMs: number | null;
	/** Local verifier work that accepted the current evidence, across attempted origins. May
	 * reuse authenticated artifacts. A refresh that delivers the same bytes keeps it. */
	readonly verificationDurationMs: number | null;
	/** The checks that accepted the current evidence; a refresh that delivers the same bytes keeps them. */
	readonly verificationChecks: readonly StogasVerificationCheck[];
}

/** A completed local check; only an accepted snapshot establishes complete evidence trust. */
export interface StogasVerificationCheck {
	readonly step:
		| 'decode'
		| 'sigstore'
		| 'key_manifest'
		| 'vendor_revocations'
		| 'signature'
		| 'gateway_release'
		| 'catalog_release'
		| 'hardware_policy'
		| 'vendor_collateral'
		| 'onion_services'
		| 'accepted';
	readonly reference: string | null;
	/** Reused authenticated artifact bytes; current selection is still checked. */
	readonly cached: boolean;
	readonly durationMs: number;
}

export interface StogasOpenAIOptions {
	apiKey: string;
	baseURL: string;
	dangerouslyAllowBrowser: true;
	fetch: typeof globalThis.fetch;
}

export type StogasRequestPhase = 'securing' | 'encrypting' | 'sending' | 'acknowledged';

export interface StogasRequestInit extends RequestInit {
	/** Local setup/encryption/send progress, then one authenticated response start.
	 * Acknowledgement can precede inner headers; it does not imply authorization,
	 * complete upload or provider acceptance. Observer errors are ignored.
	 * Use the request's AbortSignal to cancel. */
	onProgress?: (phase: StogasRequestPhase) => void;
}

export declare class StogasTransport {
	constructor(options?: StogasTransportOptions);
	static create(options?: StogasTransportOptions): Promise<StogasTransport>;
	readonly baseURL: string;
	readonly evidenceSnapshot: StogasEvidenceSnapshot;
	readonly evidenceURLs: string[];
	readonly fetch: (input: RequestInfo | URL, init?: StogasRequestInit) => Promise<Response>;
	openAIOptions(apiKey: string): StogasOpenAIOptions;
	refreshEvidence(): Promise<unknown>;
	subscribe(listener: (snapshot: StogasEvidenceSnapshot) => void): () => void;
	close(): Promise<void>;
}

export {
	EvidenceVerifier,
	EvidenceSnapshot,
	inspect_snp_report
} from '../../pkg/browser/stogas.js';

export {
	EncryptedSetup,
	EncryptedSession,
	EncryptedRequest,
	ResponseReceipt
} from '../../pkg/browser/stogas.js';

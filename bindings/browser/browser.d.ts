export { default } from '../../pkg/browser/stogas_verifier.js';

export interface StogasTransportOptions {
	baseURL?: string;
	environment?: 'prod' | 'staging';
	/** One initial session, growing on capacity pressure to this maximum. Default: four. */
	maxConnections?: number;
	fetch?: typeof globalThis.fetch;
	/** Delivered only after the requested terminal content receipt verifies. */
	onMetadata?: (metadata: unknown) => void;
}

export interface StogasBundleSnapshot {
	bundle: unknown | null;
	bundleURL: string | null;
	error: string | null;
	fetchedAtUnixMs: number | null;
	status: 'idle' | 'refreshing' | 'ready' | 'error';
	/** Network acquisition and body reading across attempted origins, excluding verification. */
	fetchDurationMs: number | null;
	/** Local verifier work across attempted origins, excluding progress observers. May reuse authenticated artifacts. */
	verificationDurationMs: number | null;
	verificationChecks: StogasVerificationCheck[];
	/** In-progress candidate checks; never a substitute for the accepted bundle. */
	verificationProgress: StogasVerificationCheck[] | null;
}

/** A completed local check; only an accepted snapshot establishes complete bundle trust. */
export interface StogasVerificationCheck {
	step:
		| 'decode'
		| 'sigstore'
		| 'signing_manifest'
		| 'vendor_revocations'
		| 'envelope'
		| 'release_policy'
		| 'gateway_release'
		| 'catalog_release'
		| 'hardware_policy'
		| 'vendor_collateral'
		| 'accepted';
	reference: string | null;
	/** Reused authenticated artifact bytes; current selection is still checked. */
	cached: boolean;
	durationMs: number;
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
	readonly bundleSnapshot: StogasBundleSnapshot;
	readonly bundleURLs: string[];
	readonly fetch: (input: RequestInfo | URL, init?: StogasRequestInit) => Promise<Response>;
	openAIOptions(apiKey: string): StogasOpenAIOptions;
	refreshBundle(): Promise<unknown>;
	subscribe(listener: (snapshot: StogasBundleSnapshot) => void): () => void;
	close(): Promise<void>;
}

export {
	EvidenceVerifier,
	EvidenceSnapshot,
	inspect_snp_report
} from '../../pkg/browser/stogas_verifier.js';

export {
	EncryptedSetup,
	EncryptedSession,
	EncryptedRequest,
	ResponseReceipt
} from '../../pkg/browser/stogas_verifier.js';

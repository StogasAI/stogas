import wasmModule from '../../pkg/browser/stogas_bg.wasm';
import { initSync } from '../../pkg/browser/stogas.js';

initSync({ module: wasmModule });

export { StogasTransport } from '../browser/browser.js';

export {
	EvidenceVerifier,
	EvidenceSnapshot,
	request_digest,
	response_digest,
	stream_response
} from '../../pkg/browser/stogas.js';

export {
	EncryptedSetup,
	EncryptedSession,
	EncryptedRequest,
	ResponseReceipt
} from '../../pkg/browser/stogas.js';

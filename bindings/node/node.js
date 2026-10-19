import { readFileSync } from 'node:fs';
import { initSync } from '../../pkg/browser/stogas.js';

const wasm = readFileSync(new URL('../../pkg/browser/stogas_bg.wasm', import.meta.url));
initSync({ module: wasm });

export { StogasTransport } from '../browser/browser.js';

export { EvidenceVerifier, EvidenceSnapshot } from '../../pkg/browser/stogas.js';

export {
	EncryptedSetup,
	EncryptedSession,
	EncryptedRequest,
	ResponseReceipt
} from '../../pkg/browser/stogas.js';

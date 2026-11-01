import initModule, {
	EvidenceVerifier,
	EvidenceSnapshot,
	EncryptedSetup,
	EncryptedSession,
	EncryptedRequest,
	ResponseReceipt,
	inspect_snp_report,
	transport_configuration
} from '../../pkg/browser/stogas.js';
import { createTransportClass } from '../shared/transport.js';

let initialization;

// The generated init returns early only after it finishes. Overlapping calls would each
// instantiate the module, and the last one would replace memory that live objects use.
export default function init(options) {
	initialization ??= initModule(options).catch((error) => {
		initialization = undefined;
		throw error;
	});
	return initialization;
}
export {
	EvidenceVerifier,
	EvidenceSnapshot,
	EncryptedSetup,
	EncryptedSession,
	EncryptedRequest,
	ResponseReceipt,
	inspect_snp_report
};
// A page served from an onion address reaches every origin through Tor, where each request
// crosses several relays and may wait for a new circuit. As the Rust SDK does through a proxy,
// every time limit is then four times as long.
function onOnionAddress() {
	try {
		return globalThis.location?.hostname.endsWith('.onion') === true;
	} catch {
		// Deno throws when a script started without --location reads its location.
		return false;
	}
}

export const StogasTransport = createTransportClass({
	EvidenceVerifier,
	EncryptedSetup,
	transport_configuration,
	patience: onOnionAddress() ? 4 : 1
});

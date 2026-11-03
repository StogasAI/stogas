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
// A page served from an onion address reaches every origin through Tor, so its transports are
// proxied unless their options say otherwise. A host name may end with the root's dot.
function onOnionAddress() {
	try {
		return /\.onion\.?$/.test(globalThis.location?.hostname ?? '');
	} catch {
		// Deno throws when a script started without --location reads its location.
		return false;
	}
}

export const StogasTransport = createTransportClass({
	EvidenceVerifier,
	EncryptedSetup,
	transport_configuration,
	proxied: onOnionAddress()
});

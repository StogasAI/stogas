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
export const StogasTransport = createTransportClass({
	EvidenceVerifier,
	EncryptedSetup,
	transport_configuration
});

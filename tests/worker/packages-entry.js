import {
	certificate_table_endorsements,
	verify
} from '../../packages/sev-snp/bindings/worker/worker.js';
import { verify_build_attestation } from '../../packages/sigstore/bindings/worker/worker.js';

const bytes = (base64) => Uint8Array.from(atob(base64), (character) => character.charCodeAt(0));

// Each lightweight package's Worker entry point verifies the fixture that the test posts.
export default {
	async fetch(request) {
		const input = await request.json();
		const report = bytes(input.report);
		const endorsements = certificate_table_endorsements(bytes(input.table), report);
		const verified = verify(report, endorsements, { vmpl: 0 }, input.now);
		const attestation = verify_build_attestation(
			bytes(input.attestation),
			input.subjects,
			input.policy,
			input.trusted_root
		);
		return Response.json({ product: verified.product, subjects: attestation.subjects.length });
	}
};

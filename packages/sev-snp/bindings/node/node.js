import { readFileSync } from 'node:fs';
import {
	certificate_table_endorsements,
	crl_url,
	initSync,
	parse_report,
	vcek_url,
	verify,
	verify_crl
} from '../../pkg/browser/stogas_sev_snp.js';

const wasm = readFileSync(new URL('../../pkg/browser/stogas_sev_snp_bg.wasm', import.meta.url));
initSync({ module: wasm });

export { certificate_table_endorsements, crl_url, parse_report, vcek_url, verify, verify_crl };

import wasmModule from '../../pkg/browser/stogas_sev_snp_bg.wasm';
import {
	certificate_table_endorsements,
	crl_url,
	initSync,
	parse_report,
	vcek_url,
	verify,
	verify_crl
} from '../../pkg/browser/stogas_sev_snp.js';

initSync({ module: wasmModule });

export { certificate_table_endorsements, crl_url, parse_report, vcek_url, verify, verify_crl };

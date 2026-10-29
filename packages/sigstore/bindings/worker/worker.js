import wasmModule from '../../pkg/browser/stogas_sigstore_bg.wasm';
import { initSync, verify_github_attestation } from '../../pkg/browser/stogas_sigstore.js';

initSync({ module: wasmModule });

export { verify_github_attestation };

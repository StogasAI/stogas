//! Verification of real reports and certificates: captures from AWS and Google Cloud, AMD's KDS,
//! and the test data of go-sev-guest, the `sev` crate, Trustee, attestation-rs and Automata.
//! `tests/fixtures/sev-snp/*/provenance.json` names each file's source and license.

mod crls;
#[cfg(not(target_arch = "wasm32"))]
mod differential;
mod endorsements;
mod fixtures;
mod json;
mod kds;
mod policies;
mod reports;

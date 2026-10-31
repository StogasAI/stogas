//! Registration, sealing, release and publication checks for the operator build
//! used by Stogas's own services and CLI. Customer packages never enable it.
use stogas_core::{
    authority::{SigstoreFiles, VerifiedSigstore},
    secret_release,
};
use wasm_bindgen::prelude::*;

use super::{parse_unix_ms, to_js_value, verified_sigstore};

/// Report whether this artifact contains the private staging provenance policy.
#[wasm_bindgen(js_name = verifierSupportsStagingProvenance)]
#[must_use]
#[expect(
    clippy::missing_const_for_fn,
    reason = "wasm-bindgen rejects const exported functions"
)]
pub fn verifier_supports_staging_provenance() -> bool {
    cfg!(feature = "staging")
}

/// Verify a production SDK release's GitHub build proof and root-authorized Stogas signature
/// with Sigstore's keys from the given TUF files.
///
/// # Errors
/// Rejects invalid Sigstore files, release identity, build provenance, signing authority or
/// publication time.
#[wasm_bindgen]
pub fn verify_sdk_release(
    manifest: &[u8],
    github_attestation: &[u8],
    qualification: &[u8],
    signature: &[u8],
    sigstore_files_json: &str,
) -> Result<(), JsError> {
    let sigstore = verified_sigstore(sigstore_files_json)?;
    stogas_core::sdk_release::verify(
        manifest,
        github_attestation,
        qualification,
        signature,
        &sigstore,
    )
    .map(drop)
    .map_err(|error| JsError::new(&error.to_string()))
}

/// Seal one boot's provisioning envelope to its attested X-Wing public key.
///
/// # Errors
///
/// Returns a JavaScript error for an invalid key, digest or secret, or an encryption failure.
#[wasm_bindgen]
pub fn seal_boot_provisioning(
    public_key: &[u8],
    boot_sha256: &[u8],
    plaintext: &[u8],
) -> Result<JsValue, JsError> {
    let boot_sha256 = boot_sha256
        .try_into()
        .map_err(|_| JsError::new("boot digest must contain 32 bytes"))?;
    let sealed = secret_release::seal_provisioning(public_key, boot_sha256, plaintext)
        .map_err(|error| JsError::new(&error.to_string()))?;
    to_js_value(&sealed)
}

/// Check Sigstore files fetched for new evidence against Sigstore's current timestamp and
/// snapshot, and return their digest and versions.
///
/// # Errors
///
/// Returns a JavaScript error for malformed, unsigned, inconsistent or stale metadata.
#[wasm_bindgen]
pub fn verify_current_sigstore_files(
    files_json: &str,
    snapshot: &[u8],
    timestamp: &[u8],
    now_unix_ms: f64,
) -> Result<JsValue, JsError> {
    let files: SigstoreFiles = serde_json::from_str(files_json)
        .map_err(|error| JsError::new(&format!("invalid Sigstore files: {error}")))?;
    let verified = VerifiedSigstore::verify_current(
        &files,
        snapshot,
        timestamp,
        parse_unix_ms(now_unix_ms, "now_unix_ms")?,
    )
    .map_err(|error| JsError::new(&error.to_string()))?;
    to_js_value(&verified.summary())
}

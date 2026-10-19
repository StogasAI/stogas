//! Registration, sealing, release and publication checks for the operator build
//! used by Stogas's own services and CLI. Customer packages never enable it.
use serde::Deserialize;
use stogas_core::{
    authority::{SigstoreFiles, VerifiedSigstore},
    secret_release,
};
use stogas_sigstore::{GithubPolicy, Subject, TrustedRoot, verify_github_attestation};
use wasm_bindgen::prelude::*;

use super::{parse_unix_ms, to_js_value};

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

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct OwnedSubject {
    name: String,
    sha256: String,
}

/// Verify a production SDK release's GitHub build proof and root-authorized Stogas signature.
///
/// # Errors
/// Rejects invalid release identity, build provenance, signing authority or publication time.
#[wasm_bindgen]
pub fn verify_sdk_release(
    manifest: &[u8],
    github_attestation: &[u8],
    qualification: &[u8],
    signature: &[u8],
    now_unix_ms: f64,
) -> Result<(), JsError> {
    stogas_core::sdk_release::verify(
        manifest,
        github_attestation,
        qualification,
        signature,
        parse_unix_ms(now_unix_ms, "current time")?,
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

/// Verify the networkless Sigstore profile directly. This is also the browser conformance seam.
///
/// # Errors
///
/// Returns a JavaScript error for malformed policy, time, or untrusted evidence.
#[wasm_bindgen]
pub fn verify_sigstore_github_attestation(
    bundle: &[u8],
    expected_subjects_json: &str,
    policy_json: &str,
    now_unix_ms: f64,
) -> Result<JsValue, JsError> {
    let now_unix_ms = parse_unix_ms(now_unix_ms, "now_unix_ms")?;
    let owned: Vec<OwnedSubject> = serde_json::from_str(expected_subjects_json)
        .map_err(|error| JsError::new(&format!("invalid subjects: {error}")))?;
    let subjects = owned
        .iter()
        .map(|subject| Subject {
            name: &subject.name,
            sha256: &subject.sha256,
        })
        .collect::<Vec<_>>();
    let policy: GithubPolicy = serde_json::from_str(policy_json)
        .map_err(|error| JsError::new(&format!("invalid policy: {error}")))?;
    let trust = TrustedRoot::embedded().map_err(|error| JsError::new(&error.to_string()))?;
    let output = verify_github_attestation(trust, bundle, &subjects, &policy, now_unix_ms)
        .map_err(|error| JsError::new(&error.to_string()))?;
    to_js_value(&output)
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

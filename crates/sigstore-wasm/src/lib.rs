//! Small browser, Worker, Node, and Bun adapter for the generic offline Sigstore verifier.

use serde::{Deserialize, Serialize};
use stogas_sigstore::{
    Error, GithubPolicy, IdentityPolicy, Subject, TrustedRoot, VerifiedAttestation,
    verify_dsse_attestation as verify_dsse, verify_github_attestation as verify_github,
};
use wasm_bindgen::prelude::*;

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct OwnedSubject {
    name: String,
    sha256: String,
}

fn to_js_value<T: Serialize>(value: &T) -> Result<JsValue, JsError> {
    value
        .serialize(&serde_wasm_bindgen::Serializer::json_compatible())
        .map_err(|error| JsError::new(&error.to_string()))
}

/// Verify a GitHub/Sigstore attestation against Sigstore's `trusted_root.json`.
///
/// The caller vouches for the trusted root. Signed log and timestamp times decide validity, so
/// the result does not depend on the platform clock.
///
/// # Errors
///
/// Returns a JavaScript error for a malformed trusted root or policy, or untrusted evidence.
#[wasm_bindgen]
pub fn verify_github_attestation(
    bundle: &[u8],
    expected_subjects_json: &str,
    policy_json: &str,
    trusted_root_json: &str,
) -> Result<JsValue, JsError> {
    let policy: GithubPolicy = serde_json::from_str(policy_json)
        .map_err(|error| JsError::new(&format!("invalid policy: {error}")))?;
    verify(
        expected_subjects_json,
        trusted_root_json,
        |trust, subjects| verify_github(trust, bundle, subjects, &policy),
    )
}

/// Verify any signer's DSSE attestation against an exact certificate identity and OIDC issuer.
///
/// The result carries the statement's predicate, to which the caller applies its own policy.
///
/// # Errors
///
/// Returns a JavaScript error for a malformed trusted root or policy, or untrusted evidence.
#[wasm_bindgen]
pub fn verify_dsse_attestation(
    bundle: &[u8],
    expected_subjects_json: &str,
    policy_json: &str,
    trusted_root_json: &str,
) -> Result<JsValue, JsError> {
    let policy: IdentityPolicy = serde_json::from_str(policy_json)
        .map_err(|error| JsError::new(&format!("invalid policy: {error}")))?;
    verify(
        expected_subjects_json,
        trusted_root_json,
        |trust, subjects| verify_dsse(trust, bundle, subjects, &policy),
    )
}

fn verify(
    expected_subjects_json: &str,
    trusted_root_json: &str,
    check: impl FnOnce(&TrustedRoot, &[Subject<'_>]) -> Result<VerifiedAttestation, Error>,
) -> Result<JsValue, JsError> {
    let trust = TrustedRoot::from_json(trusted_root_json)
        .map_err(|error| JsError::new(&error.to_string()))?;
    let owned: Vec<OwnedSubject> = serde_json::from_str(expected_subjects_json)
        .map_err(|error| JsError::new(&format!("invalid subjects: {error}")))?;
    let subjects = owned
        .iter()
        .map(|subject| Subject {
            name: &subject.name,
            sha256: &subject.sha256,
        })
        .collect::<Vec<_>>();
    let output = check(&trust, &subjects).map_err(|error| JsError::new(&error.to_string()))?;
    to_js_value(&output)
}

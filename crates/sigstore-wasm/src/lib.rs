//! Small browser, Worker, Node, and Bun adapter for the generic offline Sigstore verifier.

use serde::{Deserialize, Serialize};
use stogas_sigstore::{
    GithubPolicy, Subject, TrustedRoot, verify_github_attestation as verify_core,
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

/// Verify a GitHub/Sigstore attestation. Signed log and timestamp times decide validity, so the
/// result does not depend on the platform clock.
///
/// # Errors
///
/// Returns a JavaScript error for malformed policy or untrusted evidence.
#[wasm_bindgen]
pub fn verify_github_attestation(
    bundle: &[u8],
    expected_subjects_json: &str,
    policy_json: &str,
) -> Result<JsValue, JsError> {
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
    let output = verify_core(trust, bundle, &subjects, &policy)
        .map_err(|error| JsError::new(&error.to_string()))?;
    to_js_value(&output)
}

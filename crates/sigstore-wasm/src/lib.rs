//! Browser, Worker, Node, Bun and Deno bindings for `stogas-sigstore`.

use serde::{Deserialize, Serialize, de::DeserializeOwned};
use stogas_sigstore::{
    BuildPolicy, Error, IdentityPolicy, Subject, TrustedRoot, VerifiedAttestation,
    verify_build_attestation as verify_build, verify_dsse_attestation as verify_dsse,
};
use wasm_bindgen::prelude::*;

#[wasm_bindgen(typescript_custom_section)]
const TYPES: &str = r#"
/** A file that the attestation must name, with its lowercase SHA-256 digest. */
export interface Subject {
	name: string;
	sha256: string;
}
/**
 * The repository, workflow or pipeline file, ref and commit whose GitHub Actions or GitLab.com CI
 * job made the attestation. The repository's host selects the provider.
 */
export interface BuildPolicy {
	repository: string;
	workflow_identity: string;
	source_ref: string;
	source_commit: string;
	predicate_type: string;
}
/** Any signer's exact certificate identity and OIDC issuer. */
export interface IdentityPolicy {
	certificate_identity: string;
	certificate_oidc_issuer: string;
	predicate_type: string;
}
export interface VerifiedAttestation {
	/** When Rekor or a timestamp authority recorded the signature, in seconds since the UNIX epoch. */
	integrated_time: number;
	predicate_type: string;
	/** `[name, sha256]` */
	subjects: [string, string][];
	/** The statement's predicate, as its signer wrote it. */
	predicate: unknown;
}
"#;

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

/// Read an object through JSON, so that unknown fields fail as they do in Rust. A direct
/// conversion reads only the fields it knows and would ignore a misspelled requirement.
fn from_js<T: DeserializeOwned>(value: &JsValue, label: &str) -> Result<T, JsError> {
    let json = js_sys::JSON::stringify(value)
        .ok()
        .and_then(|json| json.as_string())
        .ok_or_else(|| JsError::new(&format!("invalid {label}: expected an object")))?;
    serde_json::from_str(&json).map_err(|error| JsError::new(&format!("invalid {label}: {error}")))
}

/// Verify a build attestation from a GitHub Actions or GitLab.com hosted runner against
/// Sigstore's `trusted_root.json`.
///
/// The caller vouches for the trusted root. Signed log and timestamp times decide validity, so
/// the result does not depend on the platform clock.
///
/// # Errors
///
/// Returns a JavaScript error for a malformed trusted root or policy, or untrusted evidence.
#[wasm_bindgen(unchecked_return_type = "VerifiedAttestation")]
pub fn verify_build_attestation(
    bundle: &[u8],
    #[wasm_bindgen(unchecked_param_type = "Subject[]")] subjects: &JsValue,
    #[wasm_bindgen(unchecked_param_type = "BuildPolicy")] policy: &JsValue,
    trusted_root_json: &str,
) -> Result<JsValue, JsError> {
    let policy: BuildPolicy = from_js(policy, "policy")?;
    verify(subjects, trusted_root_json, |trust, subjects| {
        verify_build(trust, bundle, subjects, &policy)
    })
}

/// Verify any signer's DSSE attestation against an exact certificate identity and OIDC issuer.
///
/// The result carries the statement's predicate, to which the caller applies its own policy.
///
/// # Errors
///
/// Returns a JavaScript error for a malformed trusted root or policy, or untrusted evidence.
#[wasm_bindgen(unchecked_return_type = "VerifiedAttestation")]
pub fn verify_dsse_attestation(
    bundle: &[u8],
    #[wasm_bindgen(unchecked_param_type = "Subject[]")] subjects: &JsValue,
    #[wasm_bindgen(unchecked_param_type = "IdentityPolicy")] policy: &JsValue,
    trusted_root_json: &str,
) -> Result<JsValue, JsError> {
    let policy: IdentityPolicy = from_js(policy, "policy")?;
    verify(subjects, trusted_root_json, |trust, subjects| {
        verify_dsse(trust, bundle, subjects, &policy)
    })
}

fn verify(
    subjects: &JsValue,
    trusted_root_json: &str,
    check: impl FnOnce(&TrustedRoot, &[Subject<'_>]) -> Result<VerifiedAttestation, Error>,
) -> Result<JsValue, JsError> {
    let trust = TrustedRoot::from_json(trusted_root_json)
        .map_err(|error| JsError::new(&error.to_string()))?;
    let owned: Vec<OwnedSubject> = from_js(subjects, "subjects")?;
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

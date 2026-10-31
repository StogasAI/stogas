//! Publication primitives for remote signers; no network or stored keys.

use js_sys::{Object, Reflect, Uint8Array};
use stogas_core::signing;
use wasm_bindgen::prelude::*;
use zeroize::Zeroizing;

/// Verify a composite ML-DSA-65 and Ed25519 signature with a DER public key.
///
/// # Errors
/// Rejects other algorithms, malformed encodings or a signature mismatch.
#[wasm_bindgen]
pub fn verify_mldsa65_ed25519(
    public_key_spki: &[u8],
    message: &[u8],
    signature: &[u8],
) -> Result<(), JsError> {
    if message.len() > stogas_core::MAX_INPUT_BYTES {
        return Err(JsError::new("signature message exceeds the input limit"));
    }
    let key = signing::public_key_from_spki(public_key_spki).map_err(error)?;
    signing::verify(key, message, signature).map_err(error)
}

/// Prepare composite signing by two remote component keys: ML-DSA-65 signs
/// `mldsa_mu` and Ed25519 signs `ed25519_message`. Callers join the signatures in
/// that order and verify the result.
///
/// # Errors
/// Rejects malformed public keys and oversized messages.
#[wasm_bindgen(unchecked_return_type = "{ mldsa_mu: Uint8Array; ed25519_message: Uint8Array }")]
pub fn mldsa65_ed25519_signing_input(
    public_key_spki: &[u8],
    message: &[u8],
) -> Result<JsValue, JsError> {
    let key = signing::public_key_from_spki(public_key_spki).map_err(error)?;
    let input = signing::remote_signing_input(key, message).map_err(error)?;
    let output = Object::new();
    for (name, value) in [
        ("mldsa_mu", input.mldsa_mu.as_slice()),
        ("ed25519_message", input.ed25519_message.as_slice()),
    ] {
        Reflect::set(&output, &name.into(), &Uint8Array::from(value))
            .map_err(|_| JsError::new("signing input could not be returned"))?;
    }
    Ok(output.into())
}

/// Read the public identity of a separate Rekor submission seed. This supports
/// non-exportable document signers without exporting their private keys.
/// The binding erases its own copy; callers erase theirs.
///
/// # Errors
/// Rejects seeds other than 32 bytes or public-key encoding failures.
#[wasm_bindgen]
pub fn rekor_public_key_from_seed(seed: Vec<u8>) -> Result<Vec<u8>, JsError> {
    signing::RekorSubmissionKey::from_seed(&Zeroizing::new(seed))
        .and_then(|key| key.public_key_spki())
        .map_err(error)
}

/// Prepare Rekor v1 inclusion using a separate submission seed. The binding
/// erases its own copy; callers erase theirs. The signed document's own
/// signature remains independently mandatory.
///
/// # Errors
/// Rejects malformed seeds, oversized input and signing failures.
#[wasm_bindgen]
pub fn prepare_rekor_submission_with_seed(
    seed: Vec<u8>,
    signed_document: &[u8],
) -> Result<String, JsError> {
    signing::RekorSubmissionKey::from_seed(&Zeroizing::new(seed))
        .and_then(|key| key.prepare_submission(signed_document))
        .map_err(error)
}

/// Verify that the `submitter` Ed25519 `SubjectPublicKeyInfo` DER logged exact signed bytes,
/// and return the log time in Unix seconds. Sigstore's keys come from the given TUF files. This
/// does not establish document authorship, nor check a Rekor v2 entry against the root's Rekor
/// v2 scope, outside which clients reject it.
///
/// # Errors
/// Rejects invalid Sigstore files, malformed proofs, changed documents, other submitters and
/// invalid log signatures.
#[wasm_bindgen]
pub fn verify_rekor_document_inclusion(
    bundle: &[u8],
    signed_document: &[u8],
    submitter: &[u8],
    sigstore_files_json: &str,
) -> Result<f64, JsError> {
    let sigstore = super::verified_sigstore(sigstore_files_json)?;
    let time = stogas_sigstore::verify_rekor_document_inclusion(
        sigstore.trusted_root(),
        bundle,
        signed_document,
        submitter,
    )
    .map_err(|error| JsError::new(&error.to_string()))?
    .time;
    // JavaScript numbers represent every whole number below 2^53 exactly.
    if time >= 1 << 53 {
        return Err(JsError::new("Rekor log time is out of range"));
    }
    #[allow(clippy::cast_precision_loss)]
    Ok(time as f64)
}

fn error(error: signing::Error) -> JsError {
    JsError::new(&error.to_string())
}

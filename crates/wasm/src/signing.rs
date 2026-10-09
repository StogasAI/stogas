//! Publication primitives for remote signers; no network or stored keys.

use stogas_verifier::signing;
use wasm_bindgen::prelude::*;
use zeroize::Zeroize as _;

/// Verify an exact ML-DSA-65 message/context with a DER public key.
///
/// # Errors
/// Rejects other algorithms, malformed encodings or a signature mismatch.
#[wasm_bindgen]
pub fn verify_mldsa65(
    public_key_spki: &[u8],
    message: &[u8],
    context: &[u8],
    signature: &[u8],
) -> Result<(), JsError> {
    if message.len() > stogas_verifier::MAX_INPUT_BYTES {
        return Err(JsError::new("signature message exceeds the input limit"));
    }
    let key = signing::public_key_from_spki(public_key_spki).map_err(error)?;
    signing::verify(key, message, context, signature).map_err(error)
}

/// Compute FIPS 204's message representative for a remote ML-DSA-65 signer.
/// Callers must independently verify the returned signature on the original bytes.
///
/// # Errors
/// Rejects malformed public keys, oversized messages and contexts.
#[wasm_bindgen]
pub fn mldsa65_message_representative(
    public_key_spki: &[u8],
    message: &[u8],
    context: &[u8],
) -> Result<Vec<u8>, JsError> {
    let key = signing::public_key_from_spki(public_key_spki).map_err(error)?;
    signing::message_representative(key, message, context)
        .map(|mu| mu.to_vec())
        .map_err(error)
}

/// Read the public identity of a separate Rekor submission seed. This supports
/// non-exportable document signers without exporting their ML-DSA private key.
/// The input seed is erased on success and failure.
///
/// # Errors
/// Rejects seeds other than 32 bytes or public-key encoding failures.
#[wasm_bindgen]
pub fn rekor_public_key_from_seed(seed: &mut [u8]) -> Result<Vec<u8>, JsError> {
    let key = signing::RekorSubmissionKey::from_seed(seed);
    seed.zeroize();
    key.map_err(error)?.public_key_spki().map_err(error)
}

/// Prepare Rekor v1 inclusion using a separate submission seed, erasing the input.
/// The signed document's ML-DSA signature remains independently mandatory.
///
/// # Errors
/// Rejects malformed seeds, oversized input and signing failures.
#[wasm_bindgen]
pub fn prepare_rekor_submission_with_seed(
    seed: &mut [u8],
    signed_document: &[u8],
) -> Result<String, JsError> {
    let key = signing::RekorSubmissionKey::from_seed(seed);
    seed.zeroize();
    key.map_err(error)?
        .prepare_submission(signed_document)
        .map_err(error)
}

/// Verify inclusion of exact signed bytes; this does not establish document authorship.
///
/// # Errors
/// Rejects malformed proofs, changed documents and invalid log signatures or times.
#[wasm_bindgen]
pub fn verify_rekor_document_inclusion(
    bundle: &[u8],
    signed_document: &[u8],
    now_unix_ms: f64,
) -> Result<f64, JsError> {
    let now = super::parse_unix_ms(now_unix_ms, "now_unix_ms")?;
    let time =
        stogas_offline_sigstore::verify_rekor_document_inclusion(bundle, signed_document, now)
            .map_err(|error| JsError::new(&error.to_string()))?;
    // A verified seconds value is bounded by the safe-integer millisecond input above.
    #[allow(clippy::cast_precision_loss)]
    Ok(time as f64)
}

fn error(error: signing::Error) -> JsError {
    JsError::new(&error.to_string())
}

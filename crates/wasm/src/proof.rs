//! Saved receipts and request record proofs, checked against the archived boot that signed them.

use stogas_core::{
    evidence,
    log_batch::{self, Proof},
    receipt::{self, ContentDigest},
};
use wasm_bindgen::prelude::*;

use crate::evidence::{EvidenceVerifier, coded_error, verification_error};

#[wasm_bindgen(typescript_custom_section)]
const SAVED_STREAM: &str = r"
/** A saved stream's parts, as its receipt signs them. */
export interface SavedStream {
    /** The response that the stream adds up to, as JSON. */
    response: Uint8Array;
    /** The stream's `stogas` object, as JSON. */
    stogas: Uint8Array;
}
";

#[wasm_bindgen(js_class = EvidenceVerifier)]
impl EvidenceVerifier {
    /// Verify a saved `stogas` object, salts included, under the archived boot that its receipt
    /// names. Each digest comes from `request_digest` or `response_digest` and is 64 bytes, or
    /// empty to leave that side unchecked. This establishes neither current authorization nor
    /// when inference ran.
    ///
    /// # Errors
    /// Rejects an archive that fails historical appraisal, another boot's receipt, changed
    /// content or metadata, a checked side without its salt and a failed signature.
    pub fn verify_receipt_archive(
        &self,
        archive: &[u8],
        evidence: &[u8],
        stogas: &[u8],
        request_digest: &[u8],
        response_digest: &[u8],
    ) -> Result<JsValue, JsValue> {
        let request = content_digest(request_digest, "request")?;
        let response = content_digest(response_digest, "response")?;
        let boot = self.archived_boot(archive, evidence)?;
        let verified = receipt::verify_metadata(stogas, &boot, request.as_ref(), response.as_ref())
            .map_err(|error| coded_error(&error.to_string(), error.code()))?;
        Ok(super::to_js_value(&verified.receipt)?)
    }

    /// Verify a request record's proof under the archived boot that its batch names. It does not show
    /// that analytics holds every row the batch counts.
    ///
    /// # Errors
    /// Rejects a row that does not reach its batch's root, before the archive is read, then an
    /// archive that fails historical appraisal, another boot's batch and a failed signature.
    pub fn verify_log_proof_archive(
        &self,
        archive: &[u8],
        evidence: &[u8],
        proof: &[u8],
    ) -> Result<JsValue, JsValue> {
        let log_error = |error: log_batch::Error| coded_error(&error.to_string(), error.code());
        let proof = Proof::parse(proof).map_err(log_error)?;
        proof.verify_inclusion().map_err(log_error)?;
        let boot = self.archived_boot(archive, evidence)?;
        Ok(super::to_js_value(
            &proof.verify(&boot).map_err(log_error)?,
        )?)
    }

    fn archived_boot(
        &self,
        archive: &[u8],
        evidence: &[u8],
    ) -> Result<evidence::boot::VerifiedBoot, JsValue> {
        self.core
            .verify_boot_archive(archive, evidence, super::wall_clock_ms()?)
            .map_err(|error| verification_error(&error))
    }
}

/// SHA-512 of a request as its receipt signs it: the RFC 8785 form of the body without its
/// top-level `encryption_keys`.
///
/// # Errors
/// Rejects anything but one JSON object without duplicate keys and with exact integers.
#[wasm_bindgen]
pub fn request_digest(body: &[u8]) -> Result<Vec<u8>, JsValue> {
    receipt::request_digest(body)
        .map(Vec::from)
        .map_err(|error| content_error(error.into()))
}

/// SHA-512 of a buffered response as its receipt signs it: the RFC 8785 form of the body without
/// its top-level `stogas` object.
///
/// # Errors
/// Rejects anything but one JSON object without duplicate keys and with exact integers.
#[wasm_bindgen]
pub fn response_digest(body: &[u8]) -> Result<Vec<u8>, JsValue> {
    receipt::response_digest(body)
        .map(Vec::from)
        .map_err(|error| content_error(error.into()))
}

/// The response that a complete saved stream adds up to, and the stream's `stogas` object. Pass
/// the response to `response_digest`.
///
/// # Errors
/// Rejects incomplete or malformed streams.
#[wasm_bindgen(unchecked_return_type = "SavedStream")]
pub fn stream_response(stream: &[u8]) -> Result<JsValue, JsValue> {
    let (response, stogas) = receipt::stream_response(stream).map_err(content_error)?;
    let response =
        serde_json::to_vec(&response).map_err(|_| content_error(receipt::Error::Invalid))?;
    let saved = js_sys::Object::new();
    for (name, bytes) in [("response", response), ("stogas", stogas)] {
        // Fixed own properties on a newly constructed object.
        let _ = js_sys::Reflect::set(
            &saved,
            &JsValue::from_str(name),
            &js_sys::Uint8Array::from(bytes.as_slice()),
        );
    }
    Ok(saved.into())
}

#[allow(clippy::needless_pass_by_value)]
fn content_error(error: receipt::Error) -> JsValue {
    coded_error(&error.to_string(), error.code())
}

/// A side's 64-byte content digest, or `None` for a side the caller leaves unchecked.
fn content_digest(bytes: &[u8], side: &str) -> Result<Option<ContentDigest>, JsValue> {
    if bytes.is_empty() {
        return Ok(None);
    }
    ContentDigest::try_from(bytes).map(Some).map_err(|_| {
        coded_error(
            &format!("{side} digest must be 64 bytes or empty"),
            "invalid_operation",
        )
    })
}

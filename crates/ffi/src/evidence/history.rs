//! Archive appraisal shares the core's isolated historical authority.

use super::{AbiError, StogasEvidence, content_digest, input_slice, response_coded};
use std::{ffi::c_char, sync::MutexGuard};
use stogas_core::{evidence, receipt::canonical::DIGEST_BYTES};

unsafe fn verifier<'a>(
    handle: *const StogasEvidence,
) -> Result<MutexGuard<'a, evidence::Verifier>, AbiError> {
    // SAFETY: the public ABI requires a live handle throughout the call.
    unsafe { handle.as_ref() }
        .ok_or_else(|| "evidence handle is null".to_owned())?
        .core
        .lock()
        .map_err(|_| "evidence lock is poisoned".to_owned().into())
}

/// Authenticate archived evidence without changing current trust or revocation state.
///
/// # Safety
/// Handle must be live. Input must address its declared readable length.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn stogas_evidence_verify_archive(
    handle: *const StogasEvidence,
    evidence: *const u8,
    evidence_len: usize,
    now_unix_ms: i64,
) -> *mut c_char {
    response_coded(|| {
        // SAFETY: the caller retains the live handle and input through this operation.
        let (verifier, evidence) = unsafe {
            (
                verifier(handle)?,
                input_slice(
                    evidence,
                    evidence_len,
                    stogas_core::MAX_INPUT_BYTES,
                    "evidence",
                )?,
            )
        };
        Ok(verifier.verify_evidence_archive(evidence, now_unix_ms)?)
    })
}

/// Appraise archived boot evidence at its authenticated log time. Grants no live permission.
///
/// # Safety
/// Handle must be live. Every input must address its declared readable length.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn stogas_evidence_verify_boot_archive(
    handle: *const StogasEvidence,
    archive: *const u8,
    archive_len: usize,
    evidence: *const u8,
    evidence_len: usize,
    now_unix_ms: i64,
) -> *mut c_char {
    response_coded(|| {
        // SAFETY: the caller retains the live handle and inputs through this operation.
        let (verifier, archive, evidence) = unsafe {
            (
                verifier(handle)?,
                input_slice(
                    archive,
                    archive_len,
                    evidence::MAX_ARCHIVE_BYTES,
                    "boot archive",
                )?,
                input_slice(
                    evidence,
                    evidence_len,
                    stogas_core::MAX_INPUT_BYTES,
                    "evidence",
                )?,
            )
        };
        Ok(verifier
            .verify_boot_archive(archive, evidence, now_unix_ms)?
            .summary())
    })
}

/// Verify a content receipt using historical boot evidence and locally computed content digests.
///
/// Each digest is 64 bytes, or empty to leave that side unchecked. This establishes neither
/// current authorization nor when inference occurred.
///
/// # Safety
/// Handle must be live. Every input must address its declared readable length.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn stogas_evidence_verify_receipt_archive(
    handle: *const StogasEvidence,
    archive: *const u8,
    archive_len: usize,
    evidence: *const u8,
    evidence_len: usize,
    receipt: *const u8,
    receipt_len: usize,
    request_digest: *const u8,
    request_digest_len: usize,
    response_digest: *const u8,
    response_digest_len: usize,
    now_unix_ms: i64,
) -> *mut c_char {
    response_coded(|| {
        // SAFETY: the caller retains the handle and every readable slice through this call.
        let (verifier, archive, evidence, receipt, request, response) = unsafe {
            (
                verifier(handle)?,
                input_slice(
                    archive,
                    archive_len,
                    evidence::MAX_ARCHIVE_BYTES,
                    "boot archive",
                )?,
                input_slice(
                    evidence,
                    evidence_len,
                    stogas_core::MAX_INPUT_BYTES,
                    "evidence",
                )?,
                input_slice(
                    receipt,
                    receipt_len,
                    stogas_core::receipt::MAX_METADATA_BYTES,
                    "receipt",
                )?,
                input_slice(
                    request_digest,
                    request_digest_len,
                    DIGEST_BYTES,
                    "request digest",
                )?,
                input_slice(
                    response_digest,
                    response_digest_len,
                    DIGEST_BYTES,
                    "response digest",
                )?,
            )
        };
        let (request, response) = (
            content_digest(request, "request")?,
            content_digest(response, "response")?,
        );
        let boot = verifier.verify_boot_archive(archive, evidence, now_unix_ms)?;
        Ok(stogas_core::receipt::verify_metadata(
            receipt,
            &boot,
            request.as_ref(),
            response.as_ref(),
        )?
        .receipt)
    })
}

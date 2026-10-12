//! Gateway builds only: server channel, boot keys, native TLS signers, quote batches
//! and session evidence. Status for boot, TLS and quote calls: 0 success, 1 invalid
//! input, 2 authentication, 7 cryptographic failure, 255 panic (discard the owner).

use std::{
    panic::{AssertUnwindSafe, catch_unwind},
    ptr, slice,
};
use stogas_verifier::{
    approvals::Environment,
    evidence::boot::BootRequestPurpose,
    gateway::{self, Error, NodeKeys, TlsKey},
    signing::{SIGNATURE_BYTES, mldsa},
};
use zeroize::Zeroize as _;

mod channel;
pub use channel::*;

pub struct StogasNodeKeys(NodeKeys);
pub struct StogasTlsKey(TlsKey);

/// Owned bytes. Release with `stogas_buffer_free`, or `stogas_secret_buffer_free`
/// for opened provisioning.
#[repr(C)]
pub struct StogasBuffer {
    pub data: *mut u8,
    pub len: usize,
}

impl StogasBuffer {
    pub(crate) const EMPTY: Self = Self {
        data: ptr::null_mut(),
        len: 0,
    };

    pub(crate) fn owned(bytes: Vec<u8>) -> Self {
        let bytes = bytes.into_boxed_slice();
        Self {
            len: bytes.len(),
            data: Box::into_raw(bytes).cast::<u8>(),
        }
    }

    /// # Safety
    /// The buffer came from this library and is released exactly once.
    unsafe fn take(self) -> Option<Box<[u8]>> {
        // SAFETY: the caller returns an allocation created by `owned`.
        (!self.data.is_null())
            .then(|| unsafe { Box::from_raw(ptr::slice_from_raw_parts_mut(self.data, self.len)) })
    }
}

/// # Safety
/// Release each returned buffer exactly once, after its last use.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn stogas_buffer_free(buffer: StogasBuffer) {
    // SAFETY: ownership returns to the allocator exactly once.
    drop(unsafe { buffer.take() });
}

/// Erase, then release, a buffer holding opened provisioning.
///
/// # Safety
/// Release each returned buffer exactly once, after its last use.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn stogas_secret_buffer_free(buffer: StogasBuffer) {
    // SAFETY: ownership returns to the allocator exactly once.
    if let Some(mut bytes) = unsafe { buffer.take() } {
        bytes.zeroize();
    }
}

#[derive(Debug)]
enum Status {
    Input,
    Authentication,
    Crypto,
}

impl From<Error> for Status {
    fn from(error: Error) -> Self {
        match error {
            Error::Input(_) => Self::Input,
            Error::Authentication => Self::Authentication,
            Error::Signing(_) => Self::Crypto,
        }
    }
}

fn status(operation: impl FnOnce() -> Result<(), Status>) -> u32 {
    match catch_unwind(AssertUnwindSafe(operation)) {
        Ok(Ok(())) => 0,
        Ok(Err(Status::Input)) => 1,
        Ok(Err(Status::Authentication)) => 2,
        Ok(Err(Status::Crypto)) => 7,
        Err(_) => 255,
    }
}

const fn environment(value: u8) -> Result<Environment, Status> {
    match value {
        1 => Ok(Environment::Production),
        #[cfg(feature = "staging")]
        2 => Ok(Environment::Staging),
        _ => Err(Status::Input),
    }
}

/// # Safety
/// Non-null pointers address `len` readable bytes for the call.
const unsafe fn input<'a>(data: *const u8, len: usize) -> Result<&'a [u8], Status> {
    if data.is_null() {
        return if len == 0 {
            Ok(&[])
        } else {
            Err(Status::Input)
        };
    }
    // SAFETY: the caller supplies a readable allocation of this length.
    Ok(unsafe { slice::from_raw_parts(data, len) })
}

/// # Safety
/// Non-null pointers address N readable bytes for the call.
unsafe fn array<'a, const N: usize>(data: *const u8) -> Result<&'a [u8; N], Status> {
    // SAFETY: the caller supplies N readable bytes.
    unsafe { data.cast::<[u8; N]>().as_ref() }.ok_or(Status::Input)
}

/// Derive one boot's keys from independent random seeds, erasing them: 64 bytes
/// for the composite signing key (ML-DSA-65, then Ed25519) and 32 for provisioning.
///
/// # Safety
/// The signing seed addresses 64 writable bytes and the provisioning seed 32; the
/// output pointer is writable and receives one owner to free exactly once.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn stogas_node_keys_new(
    signing_seed: *mut u8,
    provisioning_seed: *mut u8,
    keys: *mut *mut StogasNodeKeys,
) -> u32 {
    status(|| {
        if keys.is_null() || signing_seed.is_null() || provisioning_seed.is_null() {
            return Err(Status::Input);
        }
        // SAFETY: the caller supplies writable, disjoint seeds and output.
        let (signing, provisioning) = unsafe {
            keys.write(ptr::null_mut());
            (
                &mut *signing_seed.cast::<[[u8; 32]; 2]>(),
                &mut *provisioning_seed.cast::<[u8; 32]>(),
            )
        };
        let owner = Box::new(StogasNodeKeys(NodeKeys::from_seeds(signing, provisioning)));
        signing.zeroize();
        provisioning.zeroize();
        // SAFETY: the output pointer is writable.
        unsafe { keys.write(Box::into_raw(owner)) };
        Ok(())
    })
}

/// # Safety
/// Keys are live; digest and challenge address 32 bytes; report data is 64 writable bytes.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn stogas_node_report_data(
    keys: *const StogasNodeKeys,
    environment_id: u8,
    tls_spki_sha256: *const u8,
    challenge: *const u8,
    report_data: *mut u8,
) -> u32 {
    status(|| {
        // SAFETY: the caller supplies live keys and fixed-size readable inputs.
        let (keys, spki, challenge) = unsafe {
            (
                keys.as_ref().ok_or(Status::Input)?,
                array(tls_spki_sha256)?,
                array(challenge)?,
            )
        };
        if report_data.is_null() {
            return Err(Status::Input);
        }
        let data = keys
            .0
            .report_data(environment(environment_id)?, spki, challenge)?;
        // SAFETY: the output addresses 64 writable bytes disjoint from the inputs.
        unsafe { report_data.copy_from_nonoverlapping(data.as_ptr(), data.len()) };
        Ok(())
    })
}

/// # Safety
/// Keys are live; each pointer addresses its fixed or declared readable length;
/// the document output is writable.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn stogas_node_boot_document(
    keys: *const StogasNodeKeys,
    environment_id: u8,
    tls_spki_sha256: *const u8,
    challenge: *const u8,
    report: *const u8,
    report_len: usize,
    gateway_release_id: *const u8,
    document: *mut StogasBuffer,
) -> u32 {
    status(|| {
        if document.is_null() {
            return Err(Status::Input);
        }
        // SAFETY: the output is writable.
        unsafe { document.write(StogasBuffer::EMPTY) };
        // SAFETY: the caller supplies live keys and readable inputs.
        let bytes = unsafe {
            keys.as_ref().ok_or(Status::Input)?.0.boot_document(
                environment(environment_id)?,
                array(tls_spki_sha256)?,
                array(challenge)?,
                input(report, report_len)?,
                array(gateway_release_id)?,
            )?
        };
        // SAFETY: the output is writable.
        unsafe { document.write(StogasBuffer::owned(bytes)) };
        Ok(())
    })
}

/// Purpose 1 renews the TLS certificate; 2 acknowledges registration.
///
/// # Safety
/// Keys are live; the node ID addresses its readable length; the signature
/// output addresses 3,373 writable bytes.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn stogas_node_sign_boot_request(
    keys: *const StogasNodeKeys,
    purpose: u8,
    node_id: *const u8,
    node_id_len: usize,
    issued_at_ms: i64,
    signature: *mut u8,
) -> u32 {
    status(|| {
        let purpose = match purpose {
            1 => BootRequestPurpose::Certificate,
            2 => BootRequestPurpose::Complete,
            _ => return Err(Status::Input),
        };
        if signature.is_null() || node_id_len > 128 {
            return Err(Status::Input);
        }
        // SAFETY: the caller supplies live keys and a readable node ID.
        let (keys, node_id) = unsafe {
            (
                keys.as_ref().ok_or(Status::Input)?,
                input(node_id, node_id_len)?,
            )
        };
        let node_id = std::str::from_utf8(node_id).map_err(|_| Status::Input)?;
        let bytes = keys.0.sign_boot_request(purpose, node_id, issued_at_ms)?;
        // SAFETY: the output addresses 3,373 writable bytes.
        unsafe { signature.copy_from_nonoverlapping(bytes.as_ptr(), SIGNATURE_BYTES) };
        Ok(())
    })
}

/// Returns the receipt object as JSON.
///
/// # Safety
/// Keys are live; digests address 32 bytes; metadata addresses its readable
/// length; the receipt output is writable.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn stogas_node_sign_receipt(
    keys: *const StogasNodeKeys,
    boot_sha256: *const u8,
    request_sha256: *const u8,
    response_sha256: *const u8,
    metadata: *const u8,
    metadata_len: usize,
    receipt: *mut StogasBuffer,
) -> u32 {
    status(|| {
        if receipt.is_null() {
            return Err(Status::Input);
        }
        // SAFETY: the output is writable.
        unsafe { receipt.write(StogasBuffer::EMPTY) };
        if metadata_len > stogas_verifier::receipt::MAX_METADATA_BYTES {
            return Err(Status::Input);
        }
        // SAFETY: the caller supplies live keys and readable inputs.
        let signed = unsafe {
            keys.as_ref().ok_or(Status::Input)?.0.sign_receipt(
                array(boot_sha256)?,
                array(request_sha256)?,
                array(response_sha256)?,
                input(metadata, metadata_len)?,
            )?
        };
        let bytes = serde_json::to_vec(&signed).map_err(|_| Status::Input)?;
        // SAFETY: the output is writable.
        unsafe { receipt.write(StogasBuffer::owned(bytes)) };
        Ok(())
    })
}

/// Free the plaintext with `stogas_secret_buffer_free`.
///
/// # Safety
/// Keys are live; the digest addresses 32 bytes; the envelope addresses its
/// readable length; the plaintext output is writable.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn stogas_node_open_provisioning(
    keys: *const StogasNodeKeys,
    boot_sha256: *const u8,
    envelope: *const u8,
    envelope_len: usize,
    plaintext: *mut StogasBuffer,
) -> u32 {
    status(|| {
        if plaintext.is_null() {
            return Err(Status::Input);
        }
        // SAFETY: the output is writable.
        unsafe { plaintext.write(StogasBuffer::EMPTY) };
        if envelope_len > 160 * 1024 {
            return Err(Status::Input);
        }
        // SAFETY: the caller supplies live keys and readable inputs.
        let mut opened = unsafe {
            keys.as_ref()
                .ok_or(Status::Input)?
                .0
                .open_provisioning(array(boot_sha256)?, input(envelope, envelope_len)?)?
        };
        let owned = StogasBuffer::owned(std::mem::take(&mut *opened));
        // SAFETY: the output is writable.
        unsafe { plaintext.write(owned) };
        Ok(())
    })
}

/// # Safety
/// Release live keys exactly once, after concurrent calls finish.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn stogas_node_keys_free(keys: *mut StogasNodeKeys) {
    if !keys.is_null() {
        // SAFETY: the caller returns the owner exactly once.
        drop(unsafe { Box::from_raw(keys) });
    }
}

/// # Safety
/// The key output is writable; the public key output addresses 1,952 writable bytes.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn stogas_tls_key_generate(
    key: *mut *mut StogasTlsKey,
    public_key: *mut u8,
) -> u32 {
    status(|| {
        if key.is_null() || public_key.is_null() {
            return Err(Status::Input);
        }
        // SAFETY: the output pointer is writable.
        unsafe { key.write(ptr::null_mut()) };
        let owner = Box::new(StogasTlsKey(TlsKey::generate()?));
        // SAFETY: the outputs are writable and disjoint.
        unsafe {
            public_key
                .copy_from_nonoverlapping(owner.0.public_key().as_ptr(), mldsa::PUBLIC_KEY_BYTES);
            key.write(Box::into_raw(owner));
        }
        Ok(())
    })
}

/// # Safety
/// The key is live; the message addresses its readable length; the signature
/// output addresses 3,309 writable bytes.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn stogas_tls_key_sign(
    key: *const StogasTlsKey,
    message: *const u8,
    message_len: usize,
    signature: *mut u8,
) -> u32 {
    status(|| {
        if signature.is_null() || message_len > stogas_verifier::MAX_INPUT_BYTES {
            return Err(Status::Input);
        }
        // SAFETY: the caller supplies a live key and readable message.
        let bytes = unsafe {
            key.as_ref()
                .ok_or(Status::Input)?
                .0
                .sign(input(message, message_len)?)?
        };
        // SAFETY: the output addresses 3,309 writable bytes.
        unsafe { signature.copy_from_nonoverlapping(bytes.as_ptr(), mldsa::SIGNATURE_BYTES) };
        Ok(())
    })
}

/// # Safety
/// Release a live key exactly once, after concurrent calls finish.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn stogas_tls_key_free(key: *mut StogasTlsKey) {
    if !key.is_null() {
        // SAFETY: the caller returns the owner exactly once.
        drop(unsafe { Box::from_raw(key) });
    }
}

/// # Safety
/// Digests and challenge address 32 readable bytes; the leaf addresses 64 writable bytes.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn stogas_tls_leaf(
    environment_id: u8,
    boot_sha256: *const u8,
    challenge: *const u8,
    signer_spki_sha256: *const u8,
    leaf: *mut u8,
) -> u32 {
    status(|| {
        if leaf.is_null() {
            return Err(Status::Input);
        }
        // SAFETY: the caller supplies fixed-size readable inputs.
        let hash = unsafe {
            gateway::tls_leaf(
                environment(environment_id)?,
                array(boot_sha256)?,
                array(challenge)?,
                array(signer_spki_sha256)?,
            )
        };
        // SAFETY: the output addresses 64 writable bytes.
        unsafe { leaf.copy_from_nonoverlapping(hash.as_ptr(), hash.len()) };
        Ok(())
    })
}

/// # Safety
/// Digests address 32 readable bytes; the leaf addresses 64 writable bytes.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn stogas_e2ee_leaf(
    environment_id: u8,
    boot_sha256: *const u8,
    transcript_sha256: *const u8,
    leaf: *mut u8,
) -> u32 {
    status(|| {
        if leaf.is_null() {
            return Err(Status::Input);
        }
        // SAFETY: the caller supplies fixed-size readable inputs.
        let hash = unsafe {
            gateway::e2ee_leaf(
                environment(environment_id)?,
                array(boot_sha256)?,
                array(transcript_sha256)?,
            )
        };
        // SAFETY: the output addresses 64 writable bytes.
        unsafe { leaf.copy_from_nonoverlapping(hash.as_ptr(), hash.len()) };
        Ok(())
    })
}

/// Proofs are returned in leaf order, each prefixed by its big-endian u16 length.
///
/// # Safety
/// Leaves address `count` contiguous 64-byte hashes; report data addresses 64
/// writable bytes; the proofs output is writable.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn stogas_quote_batch(
    leaves: *const u8,
    count: usize,
    report_data: *mut u8,
    proofs: *mut StogasBuffer,
) -> u32 {
    status(|| {
        if report_data.is_null() || proofs.is_null() || leaves.is_null() || count > 1024 {
            return Err(Status::Input);
        }
        // SAFETY: the output is writable.
        unsafe { proofs.write(StogasBuffer::EMPTY) };
        // SAFETY: the caller supplies `count` contiguous 64-byte hashes.
        let leaves = unsafe { slice::from_raw_parts(leaves.cast::<[u8; 64]>(), count) };
        let (data, batch) = gateway::quote_batch(leaves)?;
        let mut encoded = Vec::new();
        for proof in batch {
            let bytes = proof.to_bytes();
            encoded.extend_from_slice(
                &u16::try_from(bytes.len())
                    .map_err(|_| Status::Input)?
                    .to_be_bytes(),
            );
            encoded.extend_from_slice(&bytes);
        }
        // SAFETY: the outputs are writable and disjoint from the leaves.
        unsafe {
            report_data.copy_from_nonoverlapping(data.as_ptr(), data.len());
            proofs.write(StogasBuffer::owned(encoded));
        }
        Ok(())
    })
}

/// Certificate 1 returns the native TLS CMW extension value; 0 returns the
/// bare payload used by encrypted setup.
///
/// # Safety
/// Each input addresses its declared readable length; the output is writable.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn stogas_session_evidence(
    report: *const u8,
    report_len: usize,
    proof: *const u8,
    proof_len: usize,
    boot_document: *const u8,
    boot_document_len: usize,
    boot_inclusion: *const u8,
    boot_inclusion_len: usize,
    certificate: u8,
    evidence: *mut StogasBuffer,
) -> u32 {
    status(|| {
        if evidence.is_null() || certificate > 1 {
            return Err(Status::Input);
        }
        // SAFETY: the output is writable.
        unsafe { evidence.write(StogasBuffer::EMPTY) };
        let limit = stogas_verifier::attestation::evidence::MAX_EVIDENCE_BYTES;
        if boot_document_len > limit || boot_inclusion_len > limit || report_len > limit {
            return Err(Status::Input);
        }
        // SAFETY: the caller supplies readable inputs of these lengths.
        let bytes = unsafe {
            gateway::session_evidence(
                input(report, report_len)?,
                input(proof, proof_len)?,
                input(boot_document, boot_document_len)?,
                input(boot_inclusion, boot_inclusion_len)?,
                certificate == 1,
            )?
        };
        // SAFETY: the output is writable.
        unsafe { evidence.write(StogasBuffer::owned(bytes)) };
        Ok(())
    })
}

#[cfg(test)]
mod tests;

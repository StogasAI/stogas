use super::*;
use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use sha2::{Digest as _, Sha256};
use stogas_core::{
    attestation::{
        BatchProof, Binding,
        evidence::{MAX_EVIDENCE_BYTES, SessionEvidence},
    },
    authority::Environment,
    secret_release, signing,
};

fn take(buffer: StogasBuffer) -> Vec<u8> {
    // SAFETY: the buffer was returned by this library and is released once.
    unsafe { buffer.take() }.unwrap().into_vec()
}

struct Boot {
    keys: *mut StogasNodeKeys,
    sha256: [u8; 32],
    report_data: serde_json::Value,
}

impl Drop for Boot {
    fn drop(&mut self) {
        // SAFETY: the test owns these keys and releases them once.
        unsafe { stogas_node_keys_free(self.keys) };
    }
}

impl Boot {
    fn public(&self, field: &str) -> Vec<u8> {
        URL_SAFE_NO_PAD
            .decode(self.report_data[field].as_str().unwrap())
            .unwrap()
    }
}

// The document commits the keys through report data copied into a synthetic report.
fn boot() -> Boot {
    let mut keys = ptr::null_mut();
    let (spki, challenge, digest) = ([1; 32], [2; 32], [3; 32]);
    let mut report = vec![0; 0x4a0];
    let mut document = StogasBuffer::EMPTY;
    // SAFETY: every pointer addresses live storage of the documented size.
    unsafe {
        let mut seeds = [[7; 32], [8; 32], [9; 32]];
        let (signing, provisioning) = seeds.split_at_mut(2);
        assert_eq!(
            stogas_node_keys_new(
                signing.as_flattened_mut().as_mut_ptr(),
                provisioning.as_flattened_mut().as_mut_ptr(),
                &raw mut keys
            ),
            0
        );
        assert_eq!(seeds, [[0; 32]; 3]);
        let data = report[0x50..].as_mut_ptr();
        assert_eq!(
            stogas_node_report_data(keys, 3, spki.as_ptr(), challenge.as_ptr(), data),
            1
        );
        assert_eq!(
            stogas_node_report_data(keys, 1, spki.as_ptr(), challenge.as_ptr(), data),
            0
        );
        let status = stogas_node_boot_document(
            keys,
            1,
            spki.as_ptr(),
            challenge.as_ptr(),
            report.as_ptr(),
            report.len(),
            digest.as_ptr(),
            &raw mut document,
        );
        assert_eq!(status, 0);
    }
    let document = take(document);
    let record: serde_json::Value = serde_json::from_slice(&document).unwrap();
    Boot {
        keys,
        sha256: Sha256::digest(&document).into(),
        report_data: record["report_data"].clone(),
    }
}

#[test]
fn boot_requests_and_receipts_sign_under_the_logged_boot_key() {
    let boot = boot();
    let node = b"amber-anchor-00";
    let metadata = br#"{"node_id":"amber-anchor-00"}"#;
    let mut signature = [0; SIGNATURE_BYTES];
    let mut receipt = StogasBuffer::EMPTY;
    // SAFETY: inputs address their declared lengths; outputs are writable.
    unsafe {
        let request = |purpose, output: &mut [u8; SIGNATURE_BYTES]| {
            stogas_node_sign_boot_request(
                boot.keys,
                purpose,
                node.as_ptr(),
                node.len(),
                1,
                output.as_mut_ptr(),
            )
        };
        assert_eq!(request(3, &mut signature), 1);
        assert_eq!(request(2, &mut signature), 0);
        let status = stogas_node_sign_receipt(
            boot.keys,
            boot.sha256.as_ptr(),
            [5; 32].as_ptr(),
            [6; 32].as_ptr(),
            metadata.as_ptr(),
            metadata.len(),
            &raw mut receipt,
        );
        assert_eq!(status, 0);
    }
    let message = [
        &b"stogas.registration-complete.v1\0"[..],
        node,
        b"\0",
        &1i64.to_be_bytes(),
    ]
    .concat();
    let public = boot.public("signing_public_key");
    assert!(signing::verify(&public, &message, &signature).is_ok());
    let receipt: serde_json::Value = serde_json::from_slice(&take(receipt)).unwrap();
    assert_eq!(receipt["boot_sha256"], hex::encode(boot.sha256));
}

#[test]
fn provisioning_opens_once_into_an_erasable_buffer_for_its_boot() {
    let boot = boot();
    let sealed =
        secret_release::seal_provisioning(&boot.public("hpke_public_key"), &boot.sha256, b"{}")
            .unwrap();
    let envelope = serde_json::to_vec(&sealed).unwrap();
    let mut tampered = envelope.clone();
    let at = tampered.len() - 4;
    tampered[at] = if tampered[at] == b'A' { b'B' } else { b'A' };
    let mut plaintext = StogasBuffer::EMPTY;
    // SAFETY: inputs address their declared lengths; the opened buffer is
    // erased and released once.
    unsafe {
        let open = |digest: &[u8; 32], envelope: &[u8], output: &mut StogasBuffer| {
            stogas_node_open_provisioning(
                boot.keys,
                digest.as_ptr(),
                envelope.as_ptr(),
                envelope.len(),
                output,
            )
        };
        assert_eq!(open(&[9; 32], &envelope, &mut plaintext), 1);
        assert!(plaintext.data.is_null());
        assert_eq!(open(&boot.sha256, &tampered, &mut plaintext), 2);
        assert_eq!(open(&boot.sha256, &envelope, &mut plaintext), 0);
        assert_eq!(slice::from_raw_parts(plaintext.data, plaintext.len), b"{}");
        stogas_secret_buffer_free(plaintext);
    }
}

#[test]
fn quote_batches_frame_each_proof_for_session_evidence() {
    let leaves: Vec<[u8; 64]> = (0..3u8)
        .map(|index| {
            let mut leaf = [0; 64];
            // SAFETY: inputs address 32 bytes; the leaf output addresses 64.
            let status = unsafe {
                stogas_e2ee_leaf(1, [index; 32].as_ptr(), [7; 32].as_ptr(), leaf.as_mut_ptr())
            };
            assert_eq!(status, 0);
            leaf
        })
        .collect();
    let mut report = vec![0; 0x4a0];
    let mut proofs = StogasBuffer::EMPTY;
    // SAFETY: leaves are contiguous 64-byte hashes; outputs are writable.
    unsafe {
        let data = report[0x50..].as_mut_ptr();
        assert_eq!(
            stogas_quote_batch(leaves.as_ptr().cast(), 0, data, &raw mut proofs),
            1
        );
        assert_eq!(
            stogas_quote_batch(leaves.as_ptr().cast(), 3, data, &raw mut proofs),
            0
        );
    }
    let framed = take(proofs);
    let report_data: [u8; 64] = report[0x50..0x90].try_into().unwrap();
    let evidence = |proof: &[u8], document_len| {
        let mut output = StogasBuffer::EMPTY;
        // SAFETY: inputs address their declared lengths or fail before any read.
        let status = unsafe {
            stogas_session_evidence(
                report.as_ptr(),
                report.len(),
                proof.as_ptr(),
                proof.len(),
                b"{}".as_ptr(),
                document_len,
                b"{}".as_ptr(),
                2,
                0,
                &raw mut output,
            )
        };
        (status, output)
    };
    let mut rest = framed.as_slice();
    for index in 0..3u8 {
        let length = usize::from(u16::from_be_bytes([rest[0], rest[1]]));
        let (proof, next) = rest[2..].split_at(length);
        rest = next;
        let (status, output) = evidence(proof, 2);
        assert_eq!(status, 0);
        let payload = take(output);
        let parsed = SessionEvidence::from_bytes(&payload).unwrap();
        assert_eq!(parsed.proof.to_bytes(), proof);
        let binding = Binding::E2eeSession {
            environment: Environment::Production,
            boot_evidence_sha256: [index; 32],
            transcript_sha256: [7; 32],
        };
        assert!(
            BatchProof::from_bytes(proof)
                .unwrap()
                .verify(&binding, &report_data)
                .is_ok()
        );
    }
    assert!(rest.is_empty());
    let (status, output) = evidence(&framed[2..], MAX_EVIDENCE_BYTES + 1);
    assert_eq!(status, 1);
    assert!(output.data.is_null());
}

#[test]
fn native_tls_keys_sign_only_through_a_live_owner() {
    let (mut key, mut public) = (ptr::null_mut(), [0; mldsa::PUBLIC_KEY_BYTES]);
    let mut signature = [0; mldsa::SIGNATURE_BYTES];
    // SAFETY: outputs address their documented sizes; the key is freed once.
    unsafe {
        assert_eq!(
            stogas_tls_key_generate(&raw mut key, public.as_mut_ptr()),
            0
        );
        assert_eq!(
            stogas_tls_key_sign(key, b"hello".as_ptr(), 5, signature.as_mut_ptr()),
            0
        );
        assert_eq!(
            stogas_tls_key_sign(ptr::null(), b"hello".as_ptr(), 5, signature.as_mut_ptr()),
            1
        );
        stogas_tls_key_free(key);
    }
    assert!(mldsa::verify(&public, b"hello", &[], &signature).is_ok());
}

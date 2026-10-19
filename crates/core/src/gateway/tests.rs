use super::*;
use crate::attestation::certificate::ParsedNativeCertificate;
use serde::Deserialize;
use serde_json::json;
use sha2::{Digest as _, Sha256};

fn node_keys() -> NodeKeys {
    let mut seeds = [[0; 32]; 3];
    getrandom::fill(seeds.as_flattened_mut()).unwrap();
    let [mldsa, ed25519, provisioning] = seeds;
    NodeKeys::from_seeds(&[mldsa, ed25519], &provisioning)
}

#[derive(Deserialize)]
struct BatchVector {
    count: u16,
    index: u16,
    proof: String,
    report_data: String,
}

// The committed vectors were produced by the former independent Go encoder.
fn leaf(index: u16) -> [u8; 64] {
    let challenge = Sha256::digest(index.to_be_bytes()).into();
    if index.is_multiple_of(2) {
        tls_leaf(Environment::Production, &[17; 32], &challenge, &[34; 32])
    } else {
        e2ee_leaf(Environment::Production, &[17; 32], &challenge)
    }
}

#[test]
fn quote_batches_reproduce_independent_vectors_and_verify_every_leaf() {
    let vectors: Vec<BatchVector> = serde_json::from_str(include_str!(
        "../../../../tests/fixtures/attestation-batch-v1.json"
    ))
    .unwrap();
    for vector in vectors {
        let leaves: Vec<_> = (0..vector.count).map(leaf).collect();
        let (report_data, proofs) = quote_batch(&leaves).unwrap();
        assert_eq!(hex::encode(report_data), vector.report_data);
        assert_eq!(
            hex::encode(proofs[usize::from(vector.index)].to_bytes()),
            vector.proof
        );
    }
    let leaves: Vec<_> = (0..MAX_BATCH_LEAVES).map(leaf).collect();
    let (report_data, proofs) = quote_batch(&leaves).unwrap();
    for (index, proof) in (0..).zip(&proofs) {
        let parsed = BatchProof::from_bytes(&proof.to_bytes()).unwrap();
        assert!(parsed.verify_leaf(&leaf(index), &report_data).is_ok());
        assert!(parsed.verify_leaf(&leaf(index ^ 1), &report_data).is_err());
    }
    assert!(quote_batch(&[]).is_err());
    assert!(quote_batch(&vec![[0; 64]; usize::from(MAX_BATCH_LEAVES) + 1]).is_err());
}

#[test]
fn session_evidence_reproduces_the_independent_certificate_extension() {
    let vector: serde_json::Value = serde_json::from_str(include_str!(
        "../../../../tests/fixtures/native-certificate-v1.json"
    ))
    .unwrap();
    let bytes = |field: &str| {
        URL_SAFE_NO_PAD
            .decode(vector[field].as_str().unwrap())
            .unwrap()
    };
    let extension = bytes("extension");
    let parsed = SessionEvidence::from_extension(&extension).unwrap();
    let proof = parsed.proof.to_bytes();
    let encode = |certificate| {
        session_evidence(
            parsed.report,
            &proof,
            parsed.boot_document,
            parsed.boot_inclusion,
            certificate,
        )
    };
    assert_eq!(encode(true).unwrap(), extension);
    let payload = encode(false).unwrap();
    let decoded = SessionEvidence::from_bytes(&payload).unwrap();
    assert_eq!(decoded.boot_inclusion, parsed.boot_inclusion);
    let der = bytes("certificate");
    let certificate = ParsedNativeCertificate::parse(&der).unwrap();
    assert_eq!(certificate.evidence.boot_document, parsed.boot_document);
    // Evidence beyond the transport bound is never produced.
    let large = vec![b'x'; crate::attestation::evidence::MAX_EVIDENCE_BYTES];
    assert!(session_evidence(parsed.report, &proof, &large, b"{}", false).is_err());
    assert!(session_evidence(&parsed.report[1..], &proof, b"{}", b"{}", false).is_err());
}

#[test]
fn boot_documents_commit_the_quote_and_requests_and_receipts_verify_under_the_boot_key() {
    let keys = node_keys();
    let (spki, challenge) = ([3; 32], [4; 32]);
    let report_data = keys
        .report_data(Environment::Production, &spki, &challenge)
        .unwrap();
    let mut report = vec![0; REPORT_BYTES];
    report[0x50..0x90].copy_from_slice(&report_data);
    let document = keys
        .boot_document(
            Environment::Production,
            &spki,
            &challenge,
            &report,
            &[5; 32],
        )
        .unwrap();
    let record: BootRecord = serde_json::from_slice(&document).unwrap();
    let value = serde_json::to_value(&record).unwrap();
    assert_eq!(crate::canonical_json(&value).unwrap().as_bytes(), document);
    assert_eq!(record.report_data.commitment().unwrap(), report_data);
    report[0x50] ^= 1;
    assert!(
        keys.boot_document(
            Environment::Production,
            &spki,
            &challenge,
            &report,
            &[5; 32]
        )
        .is_err()
    );
    let public = URL_SAFE_NO_PAD
        .decode(&record.report_data.signing_public_key)
        .unwrap();

    let node = "amber-anchor-00";
    let signature = keys
        .sign_boot_request(BootRequestPurpose::Complete, node, 1_000)
        .unwrap();
    let request = |signature: &[u8]| {
        serde_json::to_vec(&json!({
            "node_id": node, "issued_at_ms": 1_000,
            "signature": URL_SAFE_NO_PAD.encode(signature)
        }))
        .unwrap()
    };
    let verify =
        |purpose| boot::verify_boot_request(&request(&signature), node, &public, 1_000, purpose);
    assert!(verify(BootRequestPurpose::Complete).is_ok());
    assert!(verify(BootRequestPurpose::Certificate).is_err());

    let boot: [u8; 32] = Sha256::digest(&document).into();
    let metadata =
        br#"{"node_id":"amber-anchor-00","receipt":{"ignored":true},"usage":{"b":1,"a":2}}"#;
    let receipt = keys
        .sign_receipt(&boot, &[7; 32], &[8; 32], metadata)
        .unwrap();
    assert_eq!(receipt.boot_sha256, hex::encode(boot));
    let digest = receipt::metadata_digest(&serde_json::from_slice(metadata).unwrap()).unwrap();
    let signature = URL_SAFE_NO_PAD.decode(&receipt.signature).unwrap();
    let message = |response| receipt::message(&[7; 32], response, &digest);
    assert!(signing::verify(&public, &message(&[8; 32]), &signature).is_ok());
    assert!(signing::verify(&public, &message(&[9; 32]), &signature).is_err());
    assert!(keys.sign_receipt(&boot, &[7; 32], &[8; 32], b"[]").is_err());
    assert!(
        keys.sign_receipt(&boot, &[7; 32], &[8; 32], br#"{"a":1,"a":2}"#)
            .is_err()
    );
}

#[test]
fn provisioning_key_opens_exactly_one_envelope() {
    let keys = node_keys();
    let recipient = URL_SAFE_NO_PAD.decode(&keys.recipient_public).unwrap();
    let envelope = serde_json::to_vec(
        &secret_release::seal_provisioning(&recipient, &[1; 32], b"{\"secret\":1}").unwrap(),
    )
    .unwrap();
    assert_eq!(
        keys.open_provisioning(&[1; 32], &envelope)
            .unwrap()
            .as_slice(),
        b"{\"secret\":1}"
    );
    assert!(keys.open_provisioning(&[1; 32], &envelope).is_err());
}

#[test]
fn provisioning_rejects_other_boots_and_recipients_without_spending_the_key() {
    let keys = node_keys();
    let recipient = URL_SAFE_NO_PAD.decode(&keys.recipient_public).unwrap();
    let envelope = serde_json::to_vec(
        &secret_release::seal_provisioning(&recipient, &[1; 32], b"{}").unwrap(),
    )
    .unwrap();
    assert!(keys.open_provisioning(&[2; 32], &envelope).is_err());
    let mut changed: serde_json::Value = serde_json::from_slice(&envelope).unwrap();
    changed["boot_sha256"] = json!(hex::encode([2; 32]));
    let changed = serde_json::to_vec(&changed).unwrap();
    assert!(keys.open_provisioning(&[2; 32], &changed).is_err());
    let other = node_keys();
    assert!(other.open_provisioning(&[1; 32], &envelope).is_err());
    assert!(keys.open_provisioning(&[1; 32], &envelope).is_ok());
}

#[test]
fn native_tls_keys_are_fresh_context_free_signers() {
    let (first, second) = (TlsKey::generate().unwrap(), TlsKey::generate().unwrap());
    assert_ne!(first.public_key(), second.public_key());
    let signature = first.sign(b"transcript").unwrap();
    assert!(mldsa::verify(first.public_key(), b"transcript", &[], &signature).is_ok());
    assert!(mldsa::verify(second.public_key(), b"transcript", &[], &signature).is_err());
}

#[test]
fn provisioning_opens_the_committed_control_vector_and_rejects_malformed_envelopes() {
    let vector: serde_json::Value = serde_json::from_str(include_str!(
        "../../../../tests/fixtures/boot-provisioning-v1.json"
    ))
    .unwrap();
    let digest = |field: &serde_json::Value| -> [u8; 32] {
        hex::decode(field.as_str().unwrap())
            .unwrap()
            .try_into()
            .unwrap()
    };
    let sealed = &vector["sealed"];
    let (seed, boot) = (digest(&vector["seed_hex"]), digest(&sealed["boot_sha256"]));
    let keys = NodeKeys::from_seeds(&[[42; 32]; 2], &seed);
    let ciphertext = sealed["ciphertext"].as_str().unwrap();
    let encapsulated = sealed["encapsulated_key"].as_str().unwrap();
    let mut flipped = URL_SAFE_NO_PAD.decode(ciphertext).unwrap();
    flipped[0] ^= 1;
    for (name, value) in [
        ("schema", "stogas.session.v1".to_owned()),
        ("encapsulated_key", "AA".into()),
        ("encapsulated_key", format!("{encapsulated}A")),
        ("ciphertext", "A".repeat(87_404)),
        ("ciphertext", "AA".into()),
        ("ciphertext", format!("{ciphertext}=")),
        ("ciphertext", format!("\n{ciphertext}")),
        ("ciphertext", URL_SAFE_NO_PAD.encode(flipped)),
    ] {
        let mut changed = sealed.clone();
        changed[name] = json!(value);
        let changed = serde_json::to_vec(&changed).unwrap();
        assert!(keys.open_provisioning(&boot, &changed).is_err(), "{name}");
    }
    let opened = keys
        .open_provisioning(&boot, &serde_json::to_vec(sealed).unwrap())
        .unwrap();
    let opened: serde_json::Value = serde_json::from_slice(&opened).unwrap();
    assert_eq!(opened, vector["plaintext"]);
}

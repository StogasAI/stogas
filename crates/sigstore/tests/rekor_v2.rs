//! Rekor v2 build attestations: Sigstore's official conformance bundles, which its staging
//! Rekor v2 logged and its staging timestamp authority dated, verified as GitHub's will be once
//! GitHub logs to Rekor v2.
//!
//! The cases are copied unchanged from sigstore/sigstore-conformance at
//! acb38c9ee4274fa058127e6a5a4cdb9e94e449e1 (test/assets/bundle-verify), which is licensed under
//! the Apache License 2.0.

use base64::{Engine as _, engine::general_purpose::STANDARD};
use serde_json::{Value, json};
use stogas_sigstore::{
    IdentityPolicy, Subject, TrustedRoot, VerifiedAttestation, verify_dsse_attestation,
};

const IDENTITY: &str = "https://github.com/sigstore-conformance/extremely-dangerous-public-oidc-beacon/.github/workflows/extremely-dangerous-oidc-beacon.yml@refs/heads/main";
const ISSUER: &str = "https://token.actions.githubusercontent.com";
// SHA-256 of the conformance suite's a.txt.
const SUBJECT: &str = "a0cfc71271d6e278e57cd332ff957c3f7043fdda354c4cbb190a30d56efa01bf";
const ENTRY: &str = "/verificationMaterial/tlogEntries/0";
const PROOF: &str = "/verificationMaterial/tlogEntries/0/inclusionProof";

fn case(name: &str) -> (Value, Value) {
    let read = |file: &str| -> Value {
        serde_json::from_slice(
            &std::fs::read(format!(
                "{}/../../tests/fixtures/sigstore-conformance/{name}/{file}",
                env!("CARGO_MANIFEST_DIR")
            ))
            .unwrap(),
        )
        .unwrap()
    };
    (read("bundle.sigstore.json"), read("trusted_root.json"))
}

fn verify(bundle: &Value, root: &Value) -> Result<VerifiedAttestation, stogas_sigstore::Error> {
    verify_dsse_attestation(
        &TrustedRoot::from_json(&root.to_string())?,
        &serde_json::to_vec(bundle).unwrap(),
        &[Subject {
            name: "a.txt",
            sha256: SUBJECT,
        }],
        &IdentityPolicy {
            certificate_identity: IDENTITY.into(),
            certificate_oidc_issuer: ISSUER.into(),
            predicate_type: "https://slsa.dev/provenance/v1".into(),
        },
    )
}

fn set(value: &mut Value, pointer: &str, replacement: Value) {
    let (parent, key) = pointer.rsplit_once('/').unwrap();
    value.pointer_mut(parent).unwrap()[key] = replacement;
}

fn decode(value: &Value) -> Vec<u8> {
    STANDARD.decode(value.as_str().unwrap()).unwrap()
}

#[test]
fn official_rekor_v2_attestation_cases() {
    let (bundle, root) = case("rekor2-dsse-happy-path");
    let verified = verify(&bundle, &root).unwrap();
    // Rekor v2 signs no time, so the timestamp authority's dates the attestation.
    assert_eq!(verified.integrated_time, 1_778_700_213);
    assert_eq!(
        verified.subjects,
        [("a.txt".to_owned(), SUBJECT.to_owned())]
    );
    for name in [
        "rekor2-dsse-invalid-sig_fail",
        "rekor2-dsse-mismatch-envelope_fail",
        "rekor2-dsse-mismatch-sig_fail",
    ] {
        let (bundle, root) = case(name);
        assert!(verify(&bundle, &root).is_err(), "{name}");
    }
}

#[test]
fn rekor_v2_entries_must_be_exactly_what_the_log_proved() {
    let (original, root) = case("rekor2-dsse-happy-path");
    let entry = original.pointer(ENTRY).unwrap();
    let mut hashes = entry["inclusionProof"]["hashes"]
        .as_array()
        .unwrap()
        .clone();
    let first = hashes.remove(0);
    let body: Value = serde_json::from_slice(&decode(&entry["canonicalizedBody"])).unwrap();
    // protojson omits a zero integratedTime, so an explicit zero is the same entry.
    let mut zero = original.clone();
    set(&mut zero, &format!("{ENTRY}/integratedTime"), json!("0"));
    assert!(verify(&zero, &root).is_ok());
    for (pointer, replacement) in [
        (format!("{ENTRY}/integratedTime"), json!("1778700213")),
        (
            format!("{ENTRY}/inclusionPromise"),
            json!({"signedEntryTimestamp": STANDARD.encode([0; 64])}),
        ),
        (
            format!("{ENTRY}/kindVersion"),
            json!({"kind": "dsse", "version": "0.0.1"}),
        ),
        (
            format!("{ENTRY}/kindVersion"),
            json!({"kind": "dsse", "version": "0.0.2"}),
        ),
        (
            format!("{ENTRY}/kindVersion"),
            json!({"kind": "hashedrekord", "version": "0.0.1"}),
        ),
        (format!("{ENTRY}/logIndex"), json!("4026477")),
        (
            format!("{ENTRY}/logId/keyId"),
            json!(STANDARD.encode([0; 32])),
        ),
        (
            format!("{ENTRY}/canonicalizedBody"),
            json!(STANDARD.encode(serde_json::to_vec_pretty(&body).unwrap())),
        ),
        (format!("{PROOF}/logIndex"), json!("4026477")),
        (format!("{PROOF}/treeSize"), json!("4026480")),
        (format!("{PROOF}/rootHash"), json!(STANDARD.encode([0; 32]))),
        (format!("{PROOF}/hashes"), json!(hashes)),
        (format!("{PROOF}/hashes"), json!([first.clone(), first])),
        (format!("{PROOF}/checkpoint/envelope"), json!("")),
        (format!("{ENTRY}/inclusionProof"), Value::Null),
        (
            "/verificationMaterial/timestampVerificationData".to_owned(),
            json!({}),
        ),
    ] {
        let mut bundle = original.clone();
        set(&mut bundle, &pointer, replacement.clone());
        assert!(verify(&bundle, &root).is_err(), "{pointer}: {replacement}");
    }

    // The checkpoint keeps its log signature and needs no witness cosignatures, but any change
    // to its text breaks the log's signature.
    let envelope = entry["inclusionProof"]["checkpoint"]["envelope"]
        .as_str()
        .unwrap();
    let (text, signatures) = envelope.split_once("\n\n").unwrap();
    let own = signatures.lines().next().unwrap();
    let mut alone = original.clone();
    set(
        &mut alone,
        &format!("{PROOF}/checkpoint/envelope"),
        json!(format!("{text}\n\n{own}\n")),
    );
    assert!(verify(&alone, &root).is_ok());
    for changed in [
        envelope.replacen("4026479", "4026478", 1),
        envelope.replacen("log2025-alpha3", "log2025-alpha2", 1),
        envelope.replacen(own, "", 1),
        format!("{text}\nextension\n\n{signatures}"),
    ] {
        let mut bundle = original.clone();
        set(
            &mut bundle,
            &format!("{PROOF}/checkpoint/envelope"),
            json!(changed),
        );
        assert!(verify(&bundle, &root).is_err(), "{changed}");
    }
}

#[test]
fn rekor_v2_logs_are_named_keyed_and_dated_by_the_trusted_root() {
    let (bundle, original) = case("rekor2-dsse-happy-path");
    let log_id = bundle.pointer(&format!("{ENTRY}/logId")).unwrap();
    let index = original["tlogs"]
        .as_array()
        .unwrap()
        .iter()
        .position(|log| &log["logId"] == log_id)
        .unwrap();
    let log = format!("/tlogs/{index}");
    // The timestamp authority dated the signature at 2026-05-13T19:23:33Z, and both ends of a
    // log key's validity are inclusive.
    for (validity, valid) in [
        (json!({}), true),
        (json!({"start": "2026-05-13T19:23:33Z"}), true),
        (
            json!({"start": "2025-09-22T00:00:00Z", "end": "2026-05-13T19:23:33Z"}),
            true,
        ),
        (json!({"start": "2026-05-13T19:23:34Z"}), false),
        (
            json!({"start": "2025-09-22T00:00:00Z", "end": "2026-05-13T19:23:32Z"}),
            false,
        ),
    ] {
        let mut root = original.clone();
        set(
            &mut root,
            &format!("{log}/publicKey/validFor"),
            validity.clone(),
        );
        assert_eq!(verify(&bundle, &root).is_ok(), valid, "{validity}");
    }
    let other_log = &original["tlogs"][(index + 1) % original["tlogs"].as_array().unwrap().len()];
    for (pointer, replacement) in [
        (
            format!("{log}/baseUrl"),
            json!("https://log2025-alpha2.rekor.sigstage.dev"),
        ),
        (
            format!("{log}/baseUrl"),
            json!("log2025-alpha3.rekor.sigstage.dev"),
        ),
        (format!("{log}/publicKey"), other_log["publicKey"].clone()),
        (format!("{log}/hashAlgorithm"), json!("SHA2_384")),
        ("/timestampAuthorities".to_owned(), json!([])),
        ("/certificateAuthorities".to_owned(), json!([])),
        ("/ctlogs".to_owned(), json!([])),
    ] {
        let mut root = original.clone();
        set(&mut root, &pointer, replacement.clone());
        assert!(verify(&bundle, &root).is_err(), "{pointer}: {replacement}");
    }
    let mut root = original;
    root.pointer_mut(&log)
        .unwrap()
        .as_object_mut()
        .unwrap()
        .remove("baseUrl");
    assert!(verify(&bundle, &root).is_err());
}

#[test]
fn rekor_v2_body_binds_the_envelope_and_signature() {
    let (original, root) = case("rekor2-dsse-happy-path");
    let envelope = &original["dsseEnvelope"];
    let mut payload: Value = serde_json::from_slice(&decode(&envelope["payload"])).unwrap();
    payload["predicate"]["buildDefinition"]["externalParameters"] = json!({"changed": true});
    let mut signature = decode(&envelope["signatures"][0]["sig"]);
    let last = signature.len() - 1;
    signature[last] ^= 1;
    let (other, _) = case("rekor2-dsse-mismatch-sig_fail");
    for (pointer, replacement) in [
        (
            "/dsseEnvelope/payload",
            json!(STANDARD.encode(serde_json::to_vec(&payload).unwrap())),
        ),
        ("/dsseEnvelope/payloadType", json!("application/json")),
        (
            "/dsseEnvelope/signatures/0/sig",
            json!(STANDARD.encode(signature)),
        ),
        (
            "/verificationMaterial/timestampVerificationData",
            other["verificationMaterial"]["timestampVerificationData"].clone(),
        ),
    ] {
        let mut bundle = original.clone();
        set(&mut bundle, pointer, replacement);
        assert!(verify(&bundle, &root).is_err(), "{pointer}");
    }
}

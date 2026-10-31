use super::*;
use ed25519_dalek::{Signer as _, SigningKey, pkcs8::EncodePublicKey as _};
use serde_json::{Value, json};

const ARTIFACT: &[u8] = b"exact document bytes, including its independent author signature\n";
const NOW: i64 = 1_790_000_000_000;

fn log_key() -> SigningKey {
    SigningKey::from_bytes(&[33; 32])
}

fn root() -> TrustedRoot {
    let spki = log_key().verifying_key().to_public_key_der().unwrap();
    TrustedRoot::from_json(
        &json!({
            "mediaType": "application/vnd.dev.sigstore.trustedroot+json;version=0.1",
            "certificateAuthorities": [], "ctlogs": [], "timestampAuthorities": [],
            "tlogs": [{
                "baseUrl": "https://rekor.sigstore.dev", "hashAlgorithm": "SHA2_256",
                "publicKey": {"rawBytes":STANDARD.encode(&spki), "keyDetails":"PKIX_ED25519"},
                "logId": {"keyId":STANDARD.encode(Sha256::digest(&spki))}
            }]
        })
        .to_string(),
    )
    .unwrap()
}

/// Sign the one-leaf test log independently of the document submission signature.
fn seal_body(bundle: &mut Value, body: &Value) {
    let body = serde_json_canonicalizer::to_vec(body).unwrap();
    let log = log_key();
    let spki = log.verifying_key().to_public_key_der().unwrap();
    let id = Sha256::digest(&spki);
    let root = Sha256::digest([&[0][..], body.as_slice()].concat());
    let checkpoint = format!("rekor.sigstore.dev - 1\n1\n{}\n", STANDARD.encode(root));
    let checkpoint_signature = log.sign(checkpoint.as_bytes());
    let checkpoint = format!(
        "{checkpoint}\n— rekor.sigstore.dev {}\n",
        STANDARD.encode([&id[..4], checkpoint_signature.to_bytes().as_slice()].concat())
    );
    let set = serde_json_canonicalizer::to_vec(&json!({
        "body": STANDARD.encode(&body), "integratedTime": NOW / 1000,
        "logID": hex::encode(id), "logIndex":0
    }))
    .unwrap();
    bundle["verificationMaterial"]["tlogEntries"] = json!([{
        "logIndex":"0", "logId":{"keyId":STANDARD.encode(id)},
        "kindVersion":{"kind":"hashedrekord","version":"0.0.1"},
        "integratedTime": (NOW / 1000).to_string(),
        "canonicalizedBody":STANDARD.encode(&body),
        "inclusionPromise":{"signedEntryTimestamp":STANDARD.encode(log.sign(&set).to_bytes())},
        "inclusionProof":{"logIndex":"0","rootHash":STANDARD.encode(root),"treeSize":"1",
            "hashes":[], "checkpoint":{"envelope":checkpoint}}
    }]);
}

fn submitter(seed: u8) -> Vec<u8> {
    let key = SigningKey::from_bytes(&[seed; 32]);
    key.verifying_key().to_public_key_der().unwrap().into_vec()
}

fn fixture(seed: u8) -> (Value, Value) {
    let key = SigningKey::from_bytes(&[seed; 32]);
    let spki = key.verifying_key().to_public_key_der().unwrap();
    let signature = key
        .sign_prehashed(Sha512::new_with_prefix(ARTIFACT), None)
        .unwrap();
    let public_key = pem::encode(&pem::Pem::new("PUBLIC KEY", spki.as_bytes()));
    let body = json!({"apiVersion":"0.0.1","kind":"hashedrekord","spec":{
        "data":{"hash":{"algorithm":"sha512","value":hex::encode(Sha512::digest(ARTIFACT))}},
        "signature":{"content":STANDARD.encode(signature.to_bytes()),
            "publicKey":{"content":STANDARD.encode(public_key)}}
    }});
    let mut bundle = json!({
        "mediaType":crate::SIGSTORE_BUNDLE_MEDIA_TYPE,
        "messageSignature":{
            "messageDigest":{"algorithm":"SHA2_512","digest":STANDARD.encode(Sha512::digest(ARTIFACT))},
            "signature":STANDARD.encode(signature.to_bytes())
        },
        "verificationMaterial":{
            "publicKey":{"hint":hex::encode(Sha256::digest(&spki))},
            "timestampVerificationData":{}, "tlogEntries":[]
        }
    });
    seal_body(&mut bundle, &body);
    (bundle, body)
}

#[test]
fn proves_exact_publication_by_the_designated_submitter_but_never_trusts_a_supplied_log() {
    // Qualify the fuzz seed's independently generated Go submission signature.
    // A valid artifact binding still cannot authenticate its synthetic log proof.
    let seed: Value = serde_json::from_str(include_str!(
        "../../../../tests/fixtures/rekor-document-v1.json"
    ))
    .unwrap();
    let artifact = seed["artifact"].as_str().unwrap().as_bytes();
    let parsed: Bundle = serde_json::from_value(seed["bundle"].clone()).unwrap();
    let go_submitter = hex::decode(seed["submission_key_spki"].as_str().unwrap()).unwrap();
    verify_binding(&parsed, artifact, &go_submitter).unwrap();
    assert!(verify_binding(&parsed, artifact, &submitter(9)).is_err());
    assert!(
        crate::verify_rekor_document_inclusion(
            crate::TrustedRoot::embedded().unwrap(),
            &serde_json::to_vec(&seed["bundle"]).unwrap(),
            artifact,
            &go_submitter
        )
        .is_err()
    );
    for seed in [8, 9] {
        let (bundle, _) = fixture(seed);
        let designated = submitter(seed);
        assert_eq!(
            verify(&bundle, ARTIFACT, &designated, &root()).unwrap(),
            NOW / 1000
        );
        assert!(verify(&bundle, b"substituted document", &designated, &root()).is_err());
        // Anyone can log the same bytes, but only the designated key's entries are findable.
        assert!(verify(&bundle, ARTIFACT, &submitter(seed + 1), &root()).is_err());
        assert!(
            crate::verify_rekor_document_inclusion(
                crate::TrustedRoot::embedded().unwrap(),
                &serde_json::to_vec(&bundle).unwrap(),
                ARTIFACT,
                &designated
            )
            .is_err()
        );
    }
}

#[test]
fn rejects_mutated_log_proofs_bundle_hints_and_ambiguous_formats() {
    let (original, _) = fixture(9);
    for (pointer, replacement) in [
        (
            "/mediaType",
            json!("application/vnd.dev.sigstore.bundle.v0.2+json"),
        ),
        (
            "/messageSignature/messageDigest/algorithm",
            json!("SHA2_256"),
        ),
        (
            "/messageSignature/messageDigest/digest",
            json!(STANDARD.encode([0; 64])),
        ),
        (
            "/messageSignature/signature",
            json!(STANDARD.encode([0; 64])),
        ),
        (
            "/verificationMaterial/publicKey/hint",
            json!("a".repeat(64)),
        ),
        (
            "/verificationMaterial/tlogEntries/0/kindVersion/kind",
            json!("dsse"),
        ),
        (
            "/verificationMaterial/tlogEntries/0/integratedTime",
            json!("1"),
        ),
        (
            "/verificationMaterial/tlogEntries/0/inclusionPromise/signedEntryTimestamp",
            json!(STANDARD.encode([0; 64])),
        ),
        (
            "/verificationMaterial/tlogEntries/0/inclusionProof/rootHash",
            json!(STANDARD.encode([0; 32])),
        ),
        (
            "/verificationMaterial/tlogEntries/0/inclusionProof/hashes",
            json!([STANDARD.encode([0; 32])]),
        ),
        (
            "/verificationMaterial/tlogEntries/0/inclusionProof/checkpoint/envelope",
            json!("bad checkpoint"),
        ),
        ("/verificationMaterial/tlogEntries", json!([])),
    ] {
        let mut bundle = original.clone();
        *bundle.pointer_mut(pointer).unwrap() = replacement;
        assert!(
            verify(&bundle, ARTIFACT, &submitter(9), &root()).is_err(),
            "{pointer}"
        );
    }
    let mut bundle = original.clone();
    bundle["verificationMaterial"]["tlogEntries"]
        .as_array_mut()
        .unwrap()
        .push(original["verificationMaterial"]["tlogEntries"][0].clone());
    assert!(verify(&bundle, ARTIFACT, &submitter(9), &root()).is_err());
    bundle = original;
    bundle["dsseEnvelope"] = json!({});
    assert!(verify(&bundle, ARTIFACT, &submitter(9), &root()).is_err());
}

#[test]
fn even_a_valid_log_cannot_substitute_the_artifact_hash_key_or_signature() {
    let (original, body) = fixture(9);
    for (pointer, replacement) in [
        ("/apiVersion", json!("0.0.2")),
        ("/kind", json!("rekord")),
        ("/spec/data/hash/algorithm", json!("sha256")),
        ("/spec/data/hash/value", json!("a".repeat(128))),
        ("/spec/signature/content", json!(STANDARD.encode([0; 64]))),
        (
            "/spec/signature/publicKey/content",
            json!(STANDARD.encode("bad public key")),
        ),
    ] {
        let mut changed = body.clone();
        *changed.pointer_mut(pointer).unwrap() = replacement;
        let mut bundle = original.clone();
        seal_body(&mut bundle, &changed);
        assert!(
            verify(&bundle, ARTIFACT, &submitter(9), &root()).is_err(),
            "{pointer}"
        );
    }
    let key = SigningKey::from_bytes(&[9; 32]);
    let mut changed = body;
    // Plain Ed25519 over a SHA-512 digest is not Ed25519ph.
    let wrong = STANDARD.encode(key.sign(&Sha512::digest(ARTIFACT)).to_bytes());
    changed["spec"]["signature"]["content"] = json!(wrong);
    let mut bundle = original;
    bundle["messageSignature"]["signature"] = json!(wrong);
    seal_body(&mut bundle, &changed);
    assert!(verify(&bundle, ARTIFACT, &submitter(9), &root()).is_err());
}

#[test]
fn bounds_outer_input_and_rejects_duplicate_fields() {
    assert!(matches!(
        crate::verify_rekor_document_inclusion(
            crate::TrustedRoot::embedded().unwrap(),
            b"{}",
            &vec![0; crate::MAX_DOCUMENT_BYTES + 1],
            &submitter(9)
        ),
        Err(crate::Error::TooLarge)
    ));
    for input in [
        br#"{"mediaType":"x","mediaType":"y"}"#.as_slice(),
        &vec![b' '; crate::MAX_BUNDLE_BYTES + 1],
    ] {
        assert!(
            crate::verify_rekor_document_inclusion(
                crate::TrustedRoot::embedded().unwrap(),
                input,
                ARTIFACT,
                &submitter(9)
            )
            .is_err()
        );
    }
}

// timestamp.sigstore.dev dated seed 9's signature over ARTIFACT at this second.
const TIMESTAMPED: &str = "2026-10-31T05:16:49Z";
const V2_LOG: &str = "log.example";

fn vectors() -> Value {
    serde_json::from_str(include_str!(
        "../../../../tests/fixtures/rekor-v2-vectors.json"
    ))
    .unwrap()
}

fn leaf_hash(body: &[u8]) -> [u8; 32] {
    Sha256::digest([&[0][..], body].concat()).into()
}

/// RFC 6962's tree hash and audit path.
fn tree_hash(leaves: &[[u8; 32]]) -> [u8; 32] {
    if let [leaf] = leaves {
        return *leaf;
    }
    let split = leaves.len().next_power_of_two() / 2;
    Sha256::digest(
        [
            &[1][..],
            &tree_hash(&leaves[..split]),
            &tree_hash(&leaves[split..]),
        ]
        .concat(),
    )
    .into()
}

fn audit_path(index: usize, leaves: &[[u8; 32]]) -> Vec<[u8; 32]> {
    if leaves.len() == 1 {
        return Vec::new();
    }
    let split = leaves.len().next_power_of_two() / 2;
    let (mut path, sibling) = if index < split {
        (
            audit_path(index, &leaves[..split]),
            tree_hash(&leaves[split..]),
        )
    } else {
        (
            audit_path(index - split, &leaves[split..]),
            tree_hash(&leaves[..split]),
        )
    };
    path.push(sibling);
    path
}

fn v2_log_id() -> [u8; 32] {
    Sha256::new()
        .chain_update(V2_LOG)
        .chain_update([b'\n', 1])
        .chain_update(log_key().verifying_key().as_bytes())
        .finalize()
        .into()
}

fn signed_note(text: &str, name: &str, hash: [u8; 4], key: &SigningKey) -> String {
    let signature = key.sign(text.as_bytes()).to_bytes();
    format!(
        "{text}\n\u{2014} {name} {}\n",
        STANDARD.encode([&hash[..], &signature[..]].concat())
    )
}

fn v2_checkpoint(text: &str) -> String {
    let spki = log_key().verifying_key().to_public_key_der().unwrap();
    let hash = crate::note::key_hash(V2_LOG, spki.as_bytes()).unwrap();
    signed_note(text, V2_LOG, hash, &log_key())
}

fn v2_root(validity: &Value) -> Value {
    let spki = log_key().verifying_key().to_public_key_der().unwrap();
    json!({
        "mediaType": "application/vnd.dev.sigstore.trustedroot.v0.2+json",
        "certificateAuthorities": [], "ctlogs": [],
        "timestampAuthorities": vectors()["timestamp_authorities"],
        "tlogs": [{
            "baseUrl": format!("https://{V2_LOG}"), "hashAlgorithm": "SHA2_256",
            "publicKey": {"rawBytes": STANDARD.encode(&spki), "keyDetails": "PKIX_ED25519",
                "validFor": validity},
            "logId": {"keyId": STANDARD.encode(v2_log_id())}
        }]
    })
}

fn v2_trust() -> TrustedRoot {
    TrustedRoot::from_json(&v2_root(&json!({"start": "2026-01-01T00:00:00Z"})).to_string()).unwrap()
}

/// Seed's signature over ARTIFACT, entry `index` of a `size`-entry Rekor v2 log, with the
/// timestamp over seed 9's signature.
fn v2_fixture(seed: u8, index: usize, size: usize) -> Value {
    let key = SigningKey::from_bytes(&[seed; 32]);
    let spki = key.verifying_key().to_public_key_der().unwrap();
    let signature = key
        .sign_prehashed(Sha512::new_with_prefix(ARTIFACT), None)
        .unwrap()
        .to_bytes();
    let body = v2_body(
        "SHA2_512",
        &Sha512::digest(ARTIFACT),
        &signature,
        "PKIX_ED25519_PH",
        &json!({"publicKey": {"rawBytes": STANDARD.encode(&spki)}}),
    )
    .unwrap();
    let leaves: Vec<_> = (0..size)
        .map(|position| {
            if position == index {
                leaf_hash(&body)
            } else {
                leaf_hash(format!("entry {position}").as_bytes())
            }
        })
        .collect();
    let root = tree_hash(&leaves);
    let checkpoint = v2_checkpoint(&format!("{V2_LOG}\n{size}\n{}\n", STANDARD.encode(root)));
    json!({
        "mediaType": crate::SIGSTORE_BUNDLE_MEDIA_TYPE,
        "messageSignature": {
            "messageDigest": {"algorithm": "SHA2_512", "digest": STANDARD.encode(Sha512::digest(ARTIFACT))},
            "signature": STANDARD.encode(signature)
        },
        "verificationMaterial": {
            "publicKey": {"hint": hex::encode(Sha256::digest(&spki))},
            "timestampVerificationData": {"rfc3161Timestamps": [
                {"signedTimestamp": vectors()["document_signature_timestamp"]}
            ]},
            "tlogEntries": [{
                "logIndex": index.to_string(), "logId": {"keyId": STANDARD.encode(v2_log_id())},
                "kindVersion": {"kind": "hashedrekord", "version": "0.0.2"},
                "canonicalizedBody": STANDARD.encode(&body),
                "inclusionProof": {
                    "logIndex": index.to_string(), "rootHash": STANDARD.encode(root),
                    "treeSize": size.to_string(),
                    "hashes": audit_path(index, &leaves).iter().map(|hash| STANDARD.encode(hash)).collect::<Vec<_>>(),
                    "checkpoint": {"envelope": checkpoint}
                }
            }]
        }
    })
}

fn set(value: &mut Value, pointer: &str, replacement: Value) {
    let (parent, key) = pointer.rsplit_once('/').unwrap();
    value.pointer_mut(parent).unwrap()[key] = replacement;
}

#[test]
fn rekor_v2_bodies_hash_to_the_leaves_rekor_tiles_logs() {
    let decode = |value: &Value| STANDARD.decode(value.as_str().unwrap()).unwrap();
    for vector in vectors()["hashedrekord"].as_array().unwrap() {
        // GitHub's DSSE entries: a SHA-256 digest and a Fulcio certificate. Stogas documents: a
        // SHA-512 digest and an Ed25519 key.
        let (algorithm, verifier) = vector.get("certificate").map_or_else(
            || {
                (
                    "SHA2_512",
                    json!({"publicKey": {"rawBytes": vector["public_key"]}}),
                )
            },
            |certificate| {
                (
                    "SHA2_256",
                    json!({"x509Certificate": {"rawBytes": certificate}}),
                )
            },
        );
        let body = v2_body(
            algorithm,
            &decode(&vector["digest"]),
            &decode(&vector["signature"]),
            vector["key_details"].as_str().unwrap(),
            &verifier,
        )
        .unwrap();
        assert_eq!(
            leaf_hash(&body)[..],
            decode(&vector["leaf_hash"]),
            "{}",
            vector["name"]
        );
    }
}

#[test]
fn proves_rekor_v2_publication_at_the_timestamp_authority_time() {
    let time = chrono::DateTime::parse_from_rfc3339(TIMESTAMPED)
        .unwrap()
        .timestamp();
    // Every position in trees of every shape, including each tree's right edge.
    for size in 1..=9 {
        for index in 0..size {
            let bundle = v2_fixture(9, index, size);
            assert_eq!(
                verify(&bundle, ARTIFACT, &submitter(9), &v2_trust()),
                Ok(time),
                "{index} of {size}"
            );
            assert!(verify(&bundle, b"substituted document", &submitter(9), &v2_trust()).is_err());
            assert!(verify(&bundle, ARTIFACT, &submitter(8), &v2_trust()).is_err());
        }
    }
    let bundle = v2_fixture(9, 2, 5);
    assert_eq!(
        crate::verify_rekor_document_inclusion(
            &v2_trust(),
            &serde_json::to_vec(&bundle).unwrap(),
            ARTIFACT,
            &submitter(9)
        )
        .unwrap(),
        time
    );
    // The timestamp selects the log key, and both ends of a key's validity are inclusive.
    for (validity, valid) in [
        (json!({"start": TIMESTAMPED}), true),
        (
            json!({"start": "2025-09-23T00:00:00Z", "end": TIMESTAMPED}),
            true,
        ),
        (json!({}), true),
        (json!({"start": "2026-10-31T05:16:50Z"}), false),
        (
            json!({"start": "2025-09-23T00:00:00Z", "end": "2026-10-31T05:16:48Z"}),
            false,
        ),
    ] {
        let trust = TrustedRoot::from_json(&v2_root(&validity).to_string()).unwrap();
        assert_eq!(
            verify(&bundle, ARTIFACT, &submitter(9), &trust).is_ok(),
            valid,
            "{validity}"
        );
    }
    // The log's name is its base URL's host.
    for base_url in [
        json!("https://other.example"),
        json!("log.example"),
        Value::Null,
    ] {
        let mut root = v2_root(&json!({}));
        match base_url {
            Value::Null => drop(root["tlogs"][0].as_object_mut().unwrap().remove("baseUrl")),
            url => root["tlogs"][0]["baseUrl"] = url,
        }
        let trust = TrustedRoot::from_json(&root.to_string()).unwrap();
        assert!(verify(&bundle, ARTIFACT, &submitter(9), &trust).is_err());
    }
    // A real timestamp over another signature dates nothing else, and every entry needs one.
    assert!(verify(&v2_fixture(8, 2, 5), ARTIFACT, &submitter(8), &v2_trust()).is_err());
    let mut undated = bundle.clone();
    set(
        &mut undated,
        "/verificationMaterial/timestampVerificationData",
        json!({}),
    );
    assert!(verify(&undated, ARTIFACT, &submitter(9), &v2_trust()).is_err());
    let mut altered = bundle;
    let token = vectors()["document_signature_timestamp"]
        .as_str()
        .unwrap()
        .to_owned();
    let mut bytes = STANDARD.decode(token).unwrap();
    let last = bytes.len() - 1;
    bytes[last] ^= 1;
    set(
        &mut altered,
        "/verificationMaterial/timestampVerificationData/rfc3161Timestamps",
        json!([{"signedTimestamp": STANDARD.encode(bytes)}]),
    );
    assert!(verify(&altered, ARTIFACT, &submitter(9), &v2_trust()).is_err());
}

#[test]
fn rejects_rekor_v2_entries_other_than_what_the_log_proved() {
    let original = v2_fixture(9, 2, 5);
    let accepts = |bundle: &Value| verify(bundle, ARTIFACT, &submitter(9), &v2_trust()).is_ok();
    assert!(accepts(&original));
    let entry = "/verificationMaterial/tlogEntries/0";
    // protojson omits a zero integratedTime, so an explicit zero is the same entry.
    let mut zero = original.clone();
    set(&mut zero, &format!("{entry}/integratedTime"), json!("0"));
    assert!(accepts(&zero));
    let proof = &original["verificationMaterial"]["tlogEntries"][0]["inclusionProof"];
    let mut hashes = proof["hashes"].as_array().unwrap().clone();
    hashes.reverse();
    let body = STANDARD
        .decode(
            original["verificationMaterial"]["tlogEntries"][0]["canonicalizedBody"]
                .as_str()
                .unwrap(),
        )
        .unwrap();
    let pretty: Value = serde_json::from_slice(&body).unwrap();
    for (pointer, replacement) in [
        ("/integratedTime", json!("1")),
        ("/integratedTime", json!("-1")),
        (
            "/inclusionPromise",
            json!({"signedEntryTimestamp": STANDARD.encode([0; 64])}),
        ),
        ("/kindVersion/version", json!("0.0.1")),
        ("/kindVersion/version", json!("0.0.3")),
        ("/kindVersion/kind", json!("dsse")),
        ("/logIndex", json!("3")),
        ("/logId/keyId", json!(STANDARD.encode([0; 32]))),
        (
            "/logId/keyId",
            json!(
                STANDARD.encode(Sha256::digest(
                    log_key()
                        .verifying_key()
                        .to_public_key_der()
                        .unwrap()
                        .as_bytes()
                ))
            ),
        ),
        (
            "/canonicalizedBody",
            json!(STANDARD.encode(serde_json::to_vec_pretty(&pretty).unwrap())),
        ),
        ("/canonicalizedBody", json!(STANDARD.encode(b"{}"))),
        ("/inclusionProof/logIndex", json!("3")),
        ("/inclusionProof/treeSize", json!("6")),
        ("/inclusionProof/rootHash", json!(STANDARD.encode([0; 32]))),
        ("/inclusionProof/hashes", json!([])),
        ("/inclusionProof/hashes", json!(hashes)),
        ("/inclusionProof/checkpoint/envelope", json!("")),
        ("/inclusionProof", Value::Null),
    ] {
        let mut bundle = original.clone();
        set(&mut bundle, &format!("{entry}{pointer}"), replacement);
        assert!(!accepts(&bundle), "{pointer}");
    }
    // Moving the entry to another index fails too, even when both indexes agree.
    let mut moved = original.clone();
    set(&mut moved, &format!("{entry}/logIndex"), json!("3"));
    set(
        &mut moved,
        &format!("{entry}/inclusionProof/logIndex"),
        json!("3"),
    );
    assert!(!accepts(&moved));
    // Two entries are ambiguous even when both are valid.
    let mut twice = original.clone();
    let copy = twice["verificationMaterial"]["tlogEntries"][0].clone();
    twice["verificationMaterial"]["tlogEntries"]
        .as_array_mut()
        .unwrap()
        .push(copy);
    assert!(!accepts(&twice));
}

// The checkpoint carries the log's own name, key hash and signature over this tree. Witness
// cosignatures are ignored.
#[test]
fn rekor_v2_checkpoints_are_the_logs_own() {
    let original = v2_fixture(9, 2, 5);
    let accepts = |bundle: &Value| verify(bundle, ARTIFACT, &submitter(9), &v2_trust()).is_ok();
    let proof = &original["verificationMaterial"]["tlogEntries"][0]["inclusionProof"];
    let text = |origin: &str| format!("{origin}\n5\n{}\n", proof["rootHash"].as_str().unwrap());
    let spki = log_key().verifying_key().to_public_key_der().unwrap();
    let c2sp = crate::note::key_hash(V2_LOG, spki.as_bytes()).unwrap();
    let v1_hash = Sha256::digest(spki.as_bytes());
    let other = SigningKey::from_bytes(&[34; 32]);
    let witness = format!("\u{2014} witness.example {}\n", STANDARD.encode([1; 72]));
    for (checkpoint, valid) in [
        (v2_checkpoint(&text(V2_LOG)), true),
        (format!("{}{witness}", v2_checkpoint(&text(V2_LOG))), true),
        (v2_checkpoint(&format!("{}extension\n", text(V2_LOG))), true),
        (v2_checkpoint(&text("log.example - 5")), false),
        (v2_checkpoint(&text("other.example")), false),
        (
            v2_checkpoint(&format!(
                "{V2_LOG}\n6\n{}\n",
                proof["rootHash"].as_str().unwrap()
            )),
            false,
        ),
        (
            signed_note(
                &text(V2_LOG),
                V2_LOG,
                v1_hash[..4].try_into().unwrap(),
                &log_key(),
            ),
            false,
        ),
        (signed_note(&text(V2_LOG), V2_LOG, c2sp, &other), false),
        (
            signed_note(&text(V2_LOG), "other.example", c2sp, &log_key()),
            false,
        ),
        (witness, false),
    ] {
        let mut bundle = original.clone();
        set(
            &mut bundle,
            "/verificationMaterial/tlogEntries/0/inclusionProof/checkpoint/envelope",
            json!(checkpoint),
        );
        assert_eq!(accepts(&bundle), valid, "{checkpoint}");
    }
}

#[test]
fn rekor_v1_document_proofs_carry_no_timestamps() {
    let (mut bundle, _) = fixture(9);
    set(
        &mut bundle,
        "/verificationMaterial/timestampVerificationData",
        json!({"rfc3161Timestamps": [{"signedTimestamp": vectors()["document_signature_timestamp"]}]}),
    );
    assert!(verify(&bundle, ARTIFACT, &submitter(9), &root()).is_err());
}

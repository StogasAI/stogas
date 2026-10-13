use super::*;
use p256::ecdsa::{Signature, SigningKey, signature::Signer as _};
use serde_json::json;

macro_rules! fixture {
    ($name:literal) => {
        include_bytes!(concat!("../../../../tests/fixtures/sigstore-tuf/", $name)).as_slice()
    };
}

const COMPILED: &[u8] = include_bytes!("../root.json");
const TARGETS: &[u8] = fixture!("14.targets.json");
const TRUSTED_ROOT: &[u8] = fixture!("trusted_root.json");
const SNAPSHOT: &[u8] = fixture!("166.snapshot.json");
const TIMESTAMP: &[u8] = fixture!("timestamp.json");
/// 2026-10-13, when the timestamp fixture was current.
const FETCHED_MS: i64 = 1_791_849_600_000;

fn trusted(bytes: &[u8]) -> Root {
    let metadata = Metadata::parse(bytes, "root").unwrap();
    let root = Root::parse(&metadata).unwrap();
    root.verify(&metadata).unwrap();
    root
}

fn edited(bytes: &[u8], change: impl FnOnce(&mut Value)) -> Vec<u8> {
    let mut value: Value = serde_json::from_slice(bytes).unwrap();
    change(&mut value);
    serde_json::to_vec(&value).unwrap()
}

// npm's Sigstore client (@sigstore/tuf 4.0.2) ships root 14 byte for byte, which gives an
// independent start for the compiled root and for TUF's canonical JSON.
#[test]
fn compiled_root_follows_the_root_that_npm_ships() {
    let fourteen = trusted(fixture!("14.root.json"));
    assert_eq!(newest_root(&fourteen, &[COMPILED]).unwrap().version, 15);
    assert_eq!(compiled_root().unwrap().version, 15);
}

// Root 13 replaced one root key, so it needed signatures under both key sets.
#[test]
fn follows_a_real_key_rotation_to_the_listed_trusted_root() {
    let roots = [fixture!("13.root.json"), fixture!("14.root.json"), COMPILED];
    let newest = newest_root(&trusted(fixture!("12.root.json")), &roots).unwrap();
    let (targets, _) = verify_targets(&newest, TARGETS, TRUSTED_ROOT).unwrap();
    assert_eq!((newest.version, targets.version), (15, 14));
    let update = verify_trust_update(&[], TARGETS, TRUSTED_ROOT).unwrap();
    assert_eq!((update.root_version, update.targets_version), (15, 14));
}

// Evidence carries exactly the roots after the compiled one, so each set of files has one form.
#[test]
fn rejects_missing_reordered_or_earlier_roots() {
    let twelve = trusted(fixture!("12.root.json"));
    assert!(newest_root(&twelve, &[fixture!("13.root.json"), COMPILED]).is_err());
    assert!(verify_trust_update(&[fixture!("14.root.json")], TARGETS, TRUSTED_ROOT).is_err());
    assert!(verify_trust_update(&[COMPILED], TARGETS, TRUSTED_ROOT).is_err());
    assert!(
        newest_root(
            &twelve,
            &[fixture!("14.root.json"), fixture!("13.root.json")]
        )
        .is_err()
    );
    assert!(newest_root(&twelve, &[fixture!("14.root.json")]).is_err());
}

#[test]
fn rejects_changed_undersigned_or_mistyped_metadata() {
    let twelve = trusted(fixture!("12.root.json"));
    let extended = edited(fixture!("13.root.json"), |root| {
        root["signed"]["expires"] = json!("2099-01-01T00:00:00Z");
    });
    assert!(newest_root(&twelve, &[&extended]).is_err());

    let fifteen = trusted(COMPILED);
    let two_signatures = edited(TARGETS, |targets| {
        targets["signatures"].as_array_mut().unwrap().truncate(2);
    });
    assert!(verify_targets(&fifteen, &two_signatures, TRUSTED_ROOT).is_err());
    let repeated = edited(TARGETS, |targets| {
        let first = targets["signatures"][0].clone();
        targets["signatures"].as_array_mut().unwrap().push(first);
    });
    assert!(verify_targets(&fifteen, &repeated, TRUSTED_ROOT).is_err());
    assert!(verify_targets(&fifteen, TIMESTAMP, TRUSTED_ROOT).is_err());
    assert!(newest_root(&twelve, &[TARGETS]).is_err());
}

#[test]
fn trusted_root_must_match_its_signed_length_and_digest() {
    let fifteen = trusted(COMPILED);
    let mut appended = TRUSTED_ROOT.to_vec();
    appended.push(b'\n');
    assert!(verify_targets(&fifteen, TARGETS, &appended).is_err());
    let compact = serde_json::from_slice::<Value>(TRUSTED_ROOT).unwrap();
    let compact = serde_json::to_vec(&compact).unwrap();
    assert!(verify_targets(&fifteen, TARGETS, &compact).is_err());
}

#[test]
fn publishers_also_require_current_timestamp_snapshot_and_root() {
    let current = |snapshot, timestamp, now| {
        verify_current_trust_update(&[], TARGETS, TRUSTED_ROOT, snapshot, timestamp, now)
    };
    let update = current(SNAPSHOT, TIMESTAMP, FETCHED_MS).unwrap();
    assert_eq!((update.root_version, update.targets_version), (15, 14));
    // The timestamp expires on 2026-10-20 and root 15 on 2026-11-20.
    for now in [1_792_540_800_000, 1_795_219_200_000] {
        assert!(current(SNAPSHOT, TIMESTAMP, now).is_err());
    }
    assert!(current(TIMESTAMP, SNAPSHOT, FETCHED_MS).is_err());
}

fn key(seed: u8) -> SigningKey {
    SigningKey::from_bytes(&[seed; 32].into()).unwrap()
}

fn signed_file(signed: &Value, signers: &[(&str, &SigningKey)]) -> Vec<u8> {
    let mut canonical = Vec::new();
    write_canonical(signed, &mut canonical).unwrap();
    let signatures: Vec<_> = signers
        .iter()
        .map(|(keyid, key)| {
            let signature: Signature = key.sign(&canonical);
            json!({"keyid": keyid, "sig": hex::encode(signature.to_der())})
        })
        .collect();
    serde_json::to_vec(&json!({"signed": signed, "signatures": signatures})).unwrap()
}

/// A root whose roles all use `listed` keys and `threshold`, signed by `signers`.
fn root_file(
    version: u64,
    listed: &[(&str, &SigningKey)],
    threshold: u64,
    signers: &[(&str, &SigningKey)],
) -> Vec<u8> {
    let keys: serde_json::Map<_, _> = listed
        .iter()
        .map(|(keyid, key)| {
            let mut spki =
                hex::decode("3059301306072a8648ce3d020106082a8648ce3d030107034200").unwrap();
            spki.extend_from_slice(key.verifying_key().to_encoded_point(false).as_bytes());
            let public = pem::encode(&pem::Pem::new("PUBLIC KEY", spki));
            let key = json!({
                "keytype": "ecdsa", "scheme": "ecdsa-sha2-nistp256", "keyval": {"public": public}
            });
            ((*keyid).to_owned(), key)
        })
        .collect();
    let keyids: Vec<_> = listed.iter().map(|(keyid, _)| *keyid).collect();
    let role = json!({"keyids": keyids, "threshold": threshold});
    let signed = json!({
        "_type": "root", "spec_version": "1.0", "version": version,
        "expires": "2030-01-01T00:00:00Z", "consistent_snapshot": true, "keys": keys,
        "roles": {"root": role, "targets": role, "snapshot": role, "timestamp": role}
    });
    signed_file(&signed, signers)
}

#[test]
fn publishers_follow_the_timestamp_to_the_snapshot_and_targets_it_names() {
    let key = key(5);
    let signers = [("k", &key)];
    let root = trusted(&root_file(1, &signers, 1, &signers));
    let metadata = |kind: &str, version: u64, listing: (&str, Value)| {
        let mut signed = json!({
            "_type": kind, "spec_version": "1.0", "version": version,
            "expires": "2030-01-01T00:00:00Z"
        });
        signed[listing.0] = listing.1;
        signed_file(&signed, &signers)
    };
    let listed = |name: &str, bytes: &[u8]| json!({name: {"length": bytes.len(), "hashes": {"sha256": hex::encode(Sha256::digest(bytes))}}});
    let targets = metadata(
        "targets",
        3,
        ("targets", listed("trusted_root.json", TRUSTED_ROOT)),
    );
    let snapshot = |targets: u64| {
        metadata(
            "snapshot",
            2,
            ("meta", json!({"targets.json": {"version": targets}})),
        )
    };
    let timestamp = |snapshot: u64, bytes: &[u8]| {
        let mut meta = listed("snapshot.json", bytes);
        meta["snapshot.json"]["version"] = json!(snapshot);
        metadata("timestamp", 1, ("meta", meta))
    };
    let check = |snapshot: &[u8], timestamp: &[u8]| {
        verify_current(
            &root,
            &targets,
            TRUSTED_ROOT,
            snapshot,
            timestamp,
            FETCHED_MS,
        )
    };
    let (current, older) = (snapshot(3), snapshot(2));
    let update = check(&current, &timestamp(2, &current)).unwrap();
    assert_eq!((update.root_version, update.targets_version), (1, 3));
    assert!(check(&current, &timestamp(1, &current)).is_err());
    assert!(check(&older, &timestamp(2, &older)).is_err());
    assert!(check(&older, &timestamp(2, &current)).is_err());
}

#[test]
fn a_new_root_needs_both_thresholds_from_distinct_keys() {
    let (a, b, c, d) = (key(1), key(2), key(3), key(4));
    let first = trusted(&root_file(
        1,
        &[("a", &a), ("b", &b)],
        2,
        &[("a", &a), ("b", &b)],
    ));
    let next = |listed: &[(&str, &SigningKey)], signers: &[(&str, &SigningKey)]| {
        newest_root(&first, &[&root_file(2, listed, 2, signers)]).map(|root| root.version)
    };
    let rotated = [("c", &c), ("d", &d)];
    assert_eq!(
        next(&rotated, &[("a", &a), ("b", &b), ("c", &c), ("d", &d)]),
        Ok(2)
    );
    assert!(next(&rotated, &[("a", &a), ("c", &c), ("d", &d)]).is_err());
    assert!(next(&rotated, &[("a", &a), ("b", &b), ("c", &c)]).is_err());
    let one_key_twice = [("c", &c), ("c2", &c)];
    assert!(
        next(
            &one_key_twice,
            &[("a", &a), ("b", &b), ("c", &c), ("c2", &c)]
        )
        .is_err()
    );
}

#[test]
fn canonical_form_escapes_only_quotes_and_backslashes() {
    let mut out = Vec::new();
    write_canonical(
        &json!({"b": [1, true, null], "a": "x\"y\\z\n\u{e9}"}),
        &mut out,
    )
    .unwrap();
    assert_eq!(
        out,
        "{\"a\":\"x\\\"y\\\\z\n\u{e9}\",\"b\":[1,true,null]}".as_bytes()
    );
    assert!(write_canonical(&json!(1.5), &mut Vec::new()).is_err());
}

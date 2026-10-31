use super::*;
use ed25519_dalek::{Signer as _, SigningKey, pkcs8::EncodePublicKey as _};
use serde_json::Value;

const NAME: &str = "log.example";

fn vectors() -> Value {
    serde_json::from_str(include_str!(
        "../../../../tests/fixtures/rekor-v2-vectors.json"
    ))
    .unwrap()
}

fn key(seed: u8) -> (SigningKey, Vec<u8>) {
    let key = SigningKey::from_bytes(&[seed; 32]);
    let spki = key.verifying_key().to_public_key_der().unwrap().into_vec();
    (key, spki)
}

fn body(size: u64) -> String {
    format!("{NAME}\n{size}\n{}\n", STANDARD.encode([7; 32]))
}

fn line(name: &str, hash: [u8; 4], signature: &[u8]) -> String {
    format!(
        "\u{2014} {name} {}\n",
        STANDARD.encode([&hash[..], signature].concat())
    )
}

fn signed(text: &str, seed: u8) -> String {
    let (key, spki) = key(seed);
    line(
        NAME,
        key_hash(NAME, &spki).unwrap(),
        &key.sign(text.as_bytes()).to_bytes(),
    )
}

fn open_with(note: &str, seed: u8) -> Result<Checkpoint, String> {
    let (_, spki) = key(seed);
    open_checkpoint(note, NAME, key_hash(NAME, &spki).unwrap(), &spki)
}

#[test]
fn key_hashes_match_rekor_tiles() {
    let vectors = vectors();
    let log = &vectors["log_key"];
    let spki = STANDARD.decode(log["spki"].as_str().unwrap()).unwrap();
    assert_eq!(
        hex::encode(key_hash(log["name"].as_str().unwrap(), &spki).unwrap()),
        log["key_hash"].as_str().unwrap()
    );
    // Sigstore's trusted root names each log by the full hash that the checkpoint truncates.
    let production = &vectors["production_log"];
    let spki = STANDARD
        .decode(production["publicKey"]["rawBytes"].as_str().unwrap())
        .unwrap();
    let id = STANDARD
        .decode(production["logId"]["keyId"].as_str().unwrap())
        .unwrap();
    assert_eq!(
        key_hash("log2025-1.rekor.sigstore.dev", &spki).unwrap(),
        id[..4]
    );
    // An ECDSA key's hash leaves out the name.
    let root: Value = serde_json::from_str(include_str!(
        "../../../../tests/fixtures/sigstore-tuf/trusted_root.json"
    ))
    .unwrap();
    let v1 = &root["tlogs"][0];
    let spki = STANDARD
        .decode(v1["publicKey"]["rawBytes"].as_str().unwrap())
        .unwrap();
    let id = STANDARD
        .decode(v1["logId"]["keyId"].as_str().unwrap())
        .unwrap();
    assert_eq!(key_hash("any name", &spki).unwrap(), id[..4]);
}

#[test]
fn production_checkpoint_opens_beside_witness_cosignatures() {
    let vectors = vectors();
    let production = &vectors["production_log"];
    let spki = STANDARD
        .decode(production["publicKey"]["rawBytes"].as_str().unwrap())
        .unwrap();
    let note = vectors["production_checkpoint"].as_str().unwrap();
    let name = "log2025-1.rekor.sigstore.dev";
    let hash = key_hash(name, &spki).unwrap();
    let checkpoint = open_checkpoint(note, name, hash, &spki).unwrap();
    assert_eq!(checkpoint.origin, name);
    assert!(checkpoint.size > 177_000_000);
    // Four witnesses cosigned it; removing them changes nothing.
    let (text, signatures) = note.split_once("\n\n").unwrap();
    let own = signatures.lines().next().unwrap();
    assert!(signatures.lines().count() > 1);
    assert_eq!(
        open_checkpoint(&format!("{text}\n\n{own}\n"), name, hash, &spki).unwrap(),
        checkpoint
    );
    // Another name, key or changed text is not this log's checkpoint.
    assert!(open_checkpoint(note, "rekor.sigstore.dev", hash, &spki).is_err());
    assert!(open_checkpoint(note, name, [0; 4], &spki).is_err());
    let changed = note.replacen(&checkpoint.size.to_string(), "1", 1);
    assert!(open_checkpoint(&changed, name, hash, &spki).is_err());
}

#[test]
fn official_checkpoint_cases() {
    // Copied unchanged from sigstore/sigstore-conformance at acb38c9ee4274fa058127e6a5a4cdb9e94e449e1
    // (test/assets/bundle-verify), which is licensed under the Apache License 2.0.
    let cases = [
        ("rekor2-checkpoint-cosigned", true),
        ("rekor2-checkpoint-multiple-cosigs", true),
        ("rekor2-checkpoint-origin-not-first", true),
        ("rekor2-checkpoint-two-sigs-cosigned", true),
        ("rekor2-checkpoint-two-sigs-from-origin", true),
        ("rekor2-checkpoint-missing-log-signature_fail", false),
        ("rekor2-checkpoint-missing-origin_fail", false),
        ("rekor2-checkpoint-missing-root-hash_fail", false),
        ("rekor2-checkpoint-missing-size_fail", false),
        ("rekor2-checkpoint-no-matching-signature_fail", false),
        ("rekor2-happy-path", true),
    ];
    let directory = concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../tests/fixtures/sigstore-conformance"
    );
    for (case, valid) in cases {
        let read = |file: &str| -> Value {
            serde_json::from_slice(&std::fs::read(format!("{directory}/{case}/{file}")).unwrap())
                .unwrap()
        };
        let (bundle, root) = (read("bundle.sigstore.json"), read("trusted_root.json"));
        let entry = &bundle["verificationMaterial"]["tlogEntries"][0];
        let log = root["tlogs"]
            .as_array()
            .unwrap()
            .iter()
            .find(|log| log["logId"] == entry["logId"])
            .unwrap();
        let name = log["baseUrl"]
            .as_str()
            .unwrap()
            .trim_start_matches("https://");
        let spki = STANDARD
            .decode(log["publicKey"]["rawBytes"].as_str().unwrap())
            .unwrap();
        let proof = &entry["inclusionProof"];
        let opened = open_checkpoint(
            proof["checkpoint"]["envelope"].as_str().unwrap(),
            name,
            key_hash(name, &spki).unwrap(),
            &spki,
        )
        .and_then(|checkpoint| {
            // The caller then requires the log's own origin and the proof's tree.
            (checkpoint.origin == name
                && checkpoint.size.to_string() == proof["treeSize"].as_str().unwrap()
                && STANDARD.encode(checkpoint.root) == proof["rootHash"].as_str().unwrap())
            .then_some(checkpoint)
            .ok_or_else(|| "checkpoint does not bind the proof".to_owned())
        });
        assert_eq!(opened.is_ok(), valid, "{case}: {opened:?}");
    }
}

#[test]
fn reads_signature_lines_as_go_does() {
    let text = body(5);
    let own = signed(&text, 1);
    let open = |signatures: &str| open_with(&format!("{text}\n{signatures}"), 1);
    assert_eq!(open(&own).unwrap().size, 5);

    // Other keys' lines are ignored wherever they appear: a witness, another key under the
    // log's name, and a key hash that matches under another name.
    let (_, other_spki) = key(2);
    let witness = line("witness.example", [1, 2, 3, 4], &[9; 72]);
    let same_name = line(NAME, key_hash(NAME, &other_spki).unwrap(), &[9; 64]);
    let (_, spki) = key(1);
    let same_hash = line("other.example", key_hash(NAME, &spki).unwrap(), &[9; 64]);
    for signatures in [
        format!("{witness}{own}"),
        format!("{own}{witness}"),
        format!("{same_name}{own}{same_hash}"),
    ] {
        assert!(open(&signatures).is_ok(), "{signatures}");
    }
    // Without the log's own valid signature the note is not the log's.
    for signatures in [witness.clone(), same_name, same_hash] {
        assert!(open(&signatures).is_err(), "{signatures}");
    }
    // Go checks the first line from the log's key and skips repeats, so only an invalid first
    // line rejects the note.
    let (key, spki) = self::key(1);
    let forged = line(
        NAME,
        key_hash(NAME, &spki).unwrap(),
        &key.sign(b"other text").to_bytes(),
    );
    assert!(open(&format!("{own}{forged}")).is_ok());
    assert!(open(&format!("{own}{own}")).is_ok());
    assert!(open(&format!("{forged}{own}")).is_err());

    // A malformed line rejects the note even from an unknown signer.
    let encoded = STANDARD.encode([1; 8]);
    for malformed in [
        format!("- witness.example {encoded}\n"),
        "\u{2014} witness.example\n".to_owned(),
        "\u{2014} witness.example \n".to_owned(),
        "\u{2014} witness.example not*base64\n".to_owned(),
        format!("\u{2014} witness.example {}\n", STANDARD.encode([1; 4])),
        format!("\u{2014} wit+ness.example {encoded}\n"),
        format!("\u{2014}  {encoded}\n"),
        format!("\u{2014} witness.example {encoded} extra\n"),
    ] {
        assert!(open(&format!("{own}{malformed}")).is_err(), "{malformed}");
    }

    // Go reads at most 100 signature lines.
    let many = |count| format!("{}{own}", witness.repeat(count));
    assert!(open(&many(99)).is_ok());
    assert!(open(&many(100)).is_err());
}

#[test]
fn rejects_malformed_notes_and_checkpoints() {
    let text = body(5);
    let note = format!("{text}\n{}", signed(&text, 1));
    assert!(open_with(&note, 1).is_ok());
    assert!(open_with(&note, 2).is_err());
    for broken in [
        note.trim_end().to_owned(),
        note.replace("\n\n", "\n"),
        format!("{text}\n"),
        note.replace('\n', "\r\n"),
        note.replacen(NAME, &format!("{NAME}\t"), 1),
    ] {
        assert!(open_with(&broken, 1).is_err(), "{broken:?}");
    }
    // Go sets no size limit; ours is far above any real checkpoint's.
    let sized = |length: usize| {
        let text = format!("{}{}\n", body(5), "x".repeat(length));
        format!("{text}\n{}", signed(&text, 1))
    };
    let largest = MAX_NOTE_BYTES - sized(0).len();
    assert_eq!(sized(largest).len(), MAX_NOTE_BYTES);
    assert!(open_with(&sized(largest), 1).is_ok());
    assert!(open_with(&sized(largest + 1), 1).is_err());

    // The text: origin, decimal size and a 32-byte root, then any extension lines.
    let root = STANDARD.encode([7; 32]);
    let with = |text: &str| open_with(&format!("{text}\n{}", signed(text, 1)), 1);
    assert_eq!(with(&format!("{NAME}\n007\n{root}\n")).unwrap().size, 7);
    assert!(with(&format!("{NAME}\n5\n{root}\nextension\nlines\n")).is_ok());
    for text in [
        format!("\n5\n{root}\n"),
        format!("{NAME}\n\n{root}\n"),
        format!("{NAME}\n+5\n{root}\n"),
        format!("{NAME}\n-5\n{root}\n"),
        format!("{NAME}\n18446744073709551616\n{root}\n"),
        format!("{NAME}\n5\n{}\n", STANDARD.encode([7; 31])),
        format!("{NAME}\n5\nnot base64\n"),
        format!("{NAME}\n5\n"),
    ] {
        assert!(with(&text).is_err(), "{text:?}");
    }
}

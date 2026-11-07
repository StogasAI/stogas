use super::*;
use serde_json::json;

fn hashes(count: usize) -> Vec<Hash> {
    (0..count)
        .map(|index| {
            leaf(&json!({"request_id": format!("row-{index}"), "log_batch": {"index": index}}))
                .unwrap()
        })
        .collect()
}

/// RFC 9162 section 2.1.1, written as the RFC states it.
fn reference_root(leaves: &[Hash]) -> Hash {
    if leaves.len() == 1 {
        return leaves[0];
    }
    let mut k = 1;
    while k * 2 < leaves.len() {
        k *= 2;
    }
    let mut hash = Sha512::new();
    hash.update([1]);
    hash.update(reference_root(&leaves[..k]));
    hash.update(reference_root(&leaves[k..]));
    hash.finalize().into()
}

#[test]
fn every_leaf_of_every_size_proves_its_inclusion() {
    for count in 1..=70 {
        let leaves = hashes(count);
        let root = root(&leaves);
        assert_eq!(root, reference_root(&leaves), "size {count}");
        let count = u32::try_from(count).unwrap();
        for index in 0..count {
            let path = path(&leaves, index as usize);
            assert!(path.len() <= MAX_PATH);
            assert_eq!(
                path_root(&leaves[index as usize], index, count, &path),
                Some(root),
                "leaf {index} of {count}"
            );
            // The same path proves nothing for another place, size, leaf or path.
            if count > 1 {
                let other = (index + 1) % count;
                assert_ne!(
                    path_root(&leaves[index as usize], other, count, &path),
                    Some(root)
                );
                assert_ne!(
                    path_root(&leaves[other as usize], index, count, &path),
                    Some(root)
                );
                let mut flipped = path.clone();
                flipped[0][0] ^= 1;
                assert_ne!(
                    path_root(&leaves[index as usize], index, count, &flipped),
                    Some(root)
                );
                assert!(
                    path_root(&leaves[index as usize], index, count, &path[1..])
                        .is_none_or(|implied| implied != root)
                );
            }
            // A path alone does not fix the tree's size: leaf 0 of 3 has the same path as leaf
            // 0 of 4 whose last leaf hashes as the third. The signature covers the size.
            let mut longer = path.clone();
            longer.push(root);
            assert!(
                path_root(&leaves[index as usize], index, count, &longer)
                    .is_none_or(|implied| implied != root)
            );
            assert_eq!(path_root(&leaves[0], count, count, &path), None);
        }
    }
}

#[test]
fn the_largest_batch_keeps_paths_short() {
    let leaves = hashes(MAX_LEAVES as usize);
    let root = root(&leaves);
    for index in [0, 1, 4_095, 4_096, 8_191] {
        let path = path(&leaves, index);
        assert_eq!(path.len(), MAX_PATH);
        assert_eq!(
            path_root(
                &leaves[index],
                u32::try_from(index).unwrap(),
                MAX_LEAVES,
                &path
            ),
            Some(root)
        );
    }
}

#[cfg(feature = "gateway")]
#[test]
fn log_trees_hash_as_quote_batch_trees_do() {
    // Both formats follow RFC 9162 with SHA-512, and differ only in their leaves and in what
    // commits to the root.
    for count in [1, 2, 3, 5, 8, 13, 64, 100] {
        let leaves = hashes(count);
        let mut paths = vec![Vec::new(); count];
        assert_eq!(
            root(&leaves),
            crate::attestation::subtree(&leaves, &mut paths)
        );
        for (index, expected) in paths.iter().enumerate() {
            assert_eq!(&path(&leaves, index), expected);
        }
    }
}

#[test]
fn a_leaf_hashes_the_row_by_meaning() {
    let row =
        br#"{"request_id":"a","usage":{"meters":{},"billed_cost_usd":"0"},"temperature":0.7}"#;
    let reformatted =
        b"{ \"temperature\" : 7e-1,\n \"usage\": {\"billed_cost_usd\": \"0\", \"meters\": {}},\n \"request_id\": \"a\" }";
    assert_eq!(row_leaf(row).unwrap(), row_leaf(reformatted).unwrap());
    assert_ne!(
        row_leaf(row).unwrap(),
        row_leaf(
            br#"{"request_id":"b","usage":{"meters":{},"billed_cost_usd":"0"},"temperature":0.7}"#
        )
        .unwrap()
    );
    // A row must be one object that RFC 8785 writes exactly.
    for invalid in [
        br#"{"a":1,"a":2}"#.as_slice(),
        br#"{"count":9007199254740993}"#,
        br#"["not","a","row"]"#,
        b"{\"text\":\"\\ud800\"}",
        b"{",
    ] {
        assert!(matches!(row_leaf(invalid), Err(Error::Row)));
    }
    assert!(matches!(
        row_leaf(&vec![b' '; MAX_ROW_BYTES + 1]),
        Err(Error::Row)
    ));
}

#[test]
fn the_signed_message_has_one_fixed_layout() {
    let message = message(&[0xb0; 32], 7, 1_000, 61_000, 3, &[0xa5; 64]);
    assert_eq!(
        hex::encode(&message),
        [
            hex::encode(b"stogas.log-batch.v1\0"),
            "b0".repeat(32),
            "00000007".into(),
            "00000000000003e8".into(),
            "000000000000ee48".into(),
            "00000003".into(),
            "a5".repeat(64),
        ]
        .concat()
    );
}

#[test]
fn batch_times_have_one_spelling() {
    assert_eq!(
        timestamp(1_793_694_900_123).as_deref(),
        Some("2026-11-03T08:35:00.123Z")
    );
    assert_eq!(
        unix_ms("2026-11-03T08:35:00.123Z").unwrap(),
        1_793_694_900_123
    );
    for other in [
        "2026-11-03T08:35:00.123+00:00",
        "2026-11-03T08:35:00.12Z",
        "2026-11-03T08:35:00Z",
        "2026-11-03 08:35:00.123Z",
        "2026-11-03T09:35:00.123+01:00",
    ] {
        assert!(unix_ms(other).is_err(), "{other}");
    }
}

/// Rows, leaves, root, paths, the signed message and a signature, shared with the TypeScript
/// that rebuilds paths and with any independent verifier.
#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct Vectors {
    description: String,
    rows: Vec<Value>,
    leaves: Vec<String>,
    root: String,
    paths: Vec<Vec<String>>,
    public_key: String,
    batch: Batch,
    message: String,
}

const VECTORS: &str = include_str!("../../../../tests/fixtures/log-batch-v1.json");

#[test]
fn shared_vectors_hold() {
    let vectors: Vectors = serde_json::from_str(VECTORS).unwrap();
    let leaves: Vec<Hash> = vectors.rows.iter().map(|row| leaf(row).unwrap()).collect();
    assert_eq!(
        vectors.leaves,
        leaves.iter().map(hex::encode).collect::<Vec<_>>()
    );
    assert_eq!(vectors.root, hex::encode(root(&leaves)));
    for (index, expected) in vectors.paths.iter().enumerate() {
        assert_eq!(
            expected,
            &path(&leaves, index)
                .iter()
                .map(hex::encode)
                .collect::<Vec<_>>()
        );
        let proof = Proof {
            schema: PROOF_SCHEMA.into(),
            row: vectors.rows[index].clone(),
            batch: vectors.batch.clone(),
            path: expected.clone(),
        };
        assert_eq!(
            proof.verify_inclusion().unwrap(),
            u32::try_from(index).unwrap()
        );
    }
    assert_eq!(
        vectors.message,
        hex::encode(vectors.batch.message().unwrap())
    );
    let key = URL_SAFE_NO_PAD.decode(&vectors.public_key).unwrap();
    vectors.batch.verify_key(&key).unwrap();
    let mut other = vectors.batch;
    other.sequence += 1;
    assert!(matches!(other.verify_key(&key), Err(Error::Signature)));
}

/// Writes the vectors' derived fields from their rows. Run it after changing the rows:
/// `cargo test --package stogas-core --features gateway log_batch::tests::write_vectors -- --ignored`.
#[cfg(feature = "gateway")]
#[test]
#[ignore = "rewrites tests/fixtures/log-batch-v1.json"]
fn write_vectors() {
    let mut vectors: Vectors = serde_json::from_str(VECTORS).unwrap();
    let leaves: Vec<Hash> = vectors.rows.iter().map(|row| leaf(row).unwrap()).collect();
    vectors.leaves = leaves.iter().map(hex::encode).collect();
    vectors.root = hex::encode(root(&leaves));
    vectors.paths = (0..leaves.len())
        .map(|index| path(&leaves, index).iter().map(hex::encode).collect())
        .collect();
    let keys = crate::gateway::NodeKeys::from_seeds(&[[7; 32], [8; 32]], &[9; 32]);
    let boot: [u8; 32] = hex::decode(&vectors.batch.boot_sha256)
        .unwrap()
        .try_into()
        .unwrap();
    let opened = unix_ms(&vectors.batch.opened_at).unwrap();
    let sealed = unix_ms(&vectors.batch.sealed_at).unwrap();
    vectors.batch = keys
        .sign_log_batch(
            &boot,
            &vectors.batch.node_id,
            vectors.batch.sequence,
            [opened, sealed],
            &leaves,
        )
        .unwrap();
    vectors.public_key = URL_SAFE_NO_PAD
        .encode(crate::signing::SigningKey::from_seeds(&[[7; 32], [8; 32]]).public_key());
    vectors.message = hex::encode(vectors.batch.message().unwrap());
    let path = concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../tests/fixtures/log-batch-v1.json"
    );
    let mut json = serde_json::to_string_pretty(&vectors).unwrap();
    json.push('\n');
    std::fs::write(path, json).unwrap();
}

#[test]
fn proofs_reject_rows_that_name_another_place() {
    let vectors: Vectors = serde_json::from_str(VECTORS).unwrap();
    let proof = |row: Value| Proof {
        schema: PROOF_SCHEMA.into(),
        row,
        batch: vectors.batch.clone(),
        path: vectors.paths[1].clone(),
    };
    let row = vectors.rows[1].clone();
    proof(row.clone()).verify_inclusion().unwrap();

    let mut changed = row.clone();
    changed["usage"]["billed_cost_usd"] = json!("1000");
    assert!(matches!(
        proof(changed).verify_inclusion(),
        Err(Error::Inclusion)
    ));

    for (pointer, value) in [
        ("/log_batch/index", json!(2)),
        ("/log_batch/sequence", json!(vectors.batch.sequence + 1)),
        ("/node_id", json!(format!("{}0", vectors.batch.node_id))),
        ("/log_batch", Value::Null),
        ("/log_batch/index", json!(vectors.batch.leaf_count)),
    ] {
        let mut moved = row.clone();
        *moved.pointer_mut(pointer).unwrap() = value;
        assert!(
            matches!(
                proof(moved).verify_inclusion(),
                Err(Error::Place | Error::Inclusion)
            ),
            "{pointer}"
        );
    }
    let mut extra = row.clone();
    extra["log_batch"]["leaf"] = json!(1);
    assert!(matches!(proof(extra).verify_inclusion(), Err(Error::Place)));

    let mut unnamed = proof(row.clone());
    unnamed.schema = SCHEMA.into();
    assert!(matches!(unnamed.verify_inclusion(), Err(Error::Invalid)));
    let mut resized = proof(row);
    resized.batch.leaf_count = MAX_LEAVES + 1;
    assert!(matches!(resized.verify_inclusion(), Err(Error::Invalid)));
}

#[test]
fn a_proof_reads_strictly_and_names_itself() {
    let vectors: Vectors = serde_json::from_str(VECTORS).unwrap();
    let proof = json!({
        "schema": PROOF_SCHEMA,
        "row": vectors.rows[0],
        "batch": vectors.batch,
        "path": vectors.paths[0],
    });
    assert!(Proof::is_proof(&proof));
    assert!(!Proof::is_proof(
        &json!({"receipt": {"schema": "stogas.receipt.v2"}})
    ));
    let bytes = serde_json::to_vec(&proof).unwrap();
    Proof::parse(&bytes).unwrap().verify_inclusion().unwrap();
    for (pointer, schema) in [
        ("/schema", "stogas.log-proof.v2"),
        ("/batch/schema", "stogas.log-batch.v2"),
    ] {
        let mut newer = proof.clone();
        *newer.pointer_mut(pointer).unwrap() = json!(schema);
        assert!(Proof::is_proof(&newer));
        assert!(matches!(
            Proof::parse(&serde_json::to_vec(&newer).unwrap()),
            Err(Error::Format(error)) if error.newer
        ));
    }
    let mut extra = proof;
    extra["note"] = json!("unsigned");
    assert!(Proof::parse(&serde_json::to_vec(&extra).unwrap()).is_err());
    let duplicated = [&bytes[..bytes.len() - 1], br#","schema":"x"}"#].concat();
    assert!(Proof::parse(&duplicated).is_err());
}

#[cfg(feature = "staging")]
#[test]
fn a_proof_verifies_under_the_boot_that_signed_its_batch() {
    use crate::signing::SigningKey;
    let fixture: Value = serde_json::from_str(include_str!(
        "../../../../tests/fixtures/hardware-session-v1.json"
    ))
    .unwrap();
    let mut verifier = crate::evidence::Verifier::new(
        crate::authority::Environment::Staging,
        serde_json::from_value(fixture["root"].clone()).unwrap(),
    )
    .unwrap();
    let now = fixture["verified_at_ms"].as_i64().unwrap();
    let snapshot = verifier
        .refresh(&serde_json::to_vec(&fixture["evidence"]).unwrap(), now)
        .unwrap();
    let session = snapshot
        .verify_native_certificate(
            &URL_SAFE_NO_PAD
                .decode(fixture["certificate"].as_str().unwrap())
                .unwrap(),
            hex::decode(fixture["challenge"].as_str().unwrap())
                .unwrap()
                .try_into()
                .unwrap(),
            now,
        )
        .unwrap();
    let boot = session.boot();
    let node = boot.hardware().node_id().to_owned();
    let rows: Vec<Value> = (0..3)
        .map(|index| {
            json!({
                "request_id": format!("01a1a1a1-0000-7000-8000-00000000000{index}"),
                "node_id": node,
                "log_batch": {"sequence": 4, "index": index},
                "usage": {"billed_cost_usd": "0.01"},
                "receipt_commitments": (index == 2).then(|| json!({
                    "request": "aa".repeat(32),
                    "response": "bb".repeat(32),
                })),
            })
        })
        .collect();
    let leaves: Vec<Hash> = rows.iter().map(|row| leaf(row).unwrap()).collect();
    let root = root(&leaves);
    // The public deterministic key of the diagnostic boot that produced the hardware sample.
    let key = SigningKey::from_seeds(&[[42; 32]; 2]);
    let sign = |batch: &Batch| URL_SAFE_NO_PAD.encode(key.sign(&batch.message().unwrap()).unwrap());
    let mut batch = Batch {
        schema: SCHEMA.into(),
        node_id: node.clone(),
        boot_sha256: hex::encode(boot.document_sha256()),
        sequence: 4,
        opened_at: "2026-11-03T08:35:00.000Z".into(),
        sealed_at: "2026-11-03T08:36:00.004Z".into(),
        leaf_count: 3,
        root: hex::encode(root),
        signature: String::new(),
    };
    batch.signature = sign(&batch);
    let proof = |batch: &Batch| Proof {
        schema: PROOF_SCHEMA.into(),
        row: rows[2].clone(),
        batch: batch.clone(),
        path: path(&leaves, 2).iter().map(hex::encode).collect(),
    };
    let row = proof(&batch).verify(boot).unwrap();
    assert_eq!((row.sequence, row.index, row.leaf_count), (4, 2, 3));
    assert_eq!(row.node_id, node);
    assert_eq!(
        row.request_id.as_deref(),
        Some("01a1a1a1-0000-7000-8000-000000000002")
    );
    assert_eq!(
        row.receipt_commitments,
        Some(ReceiptCommitments {
            request: "aa".repeat(32),
            response: "bb".repeat(32),
        })
    );

    // Another boot's batch names another document, even with this node's rows.
    let mut other = batch.clone();
    other.boot_sha256 = "00".repeat(32);
    other.signature = sign(&other);
    assert!(matches!(proof(&other).verify(boot), Err(Error::Identity)));
    // A batch whose fields changed after signing fails its signature.
    let mut later = batch.clone();
    later.sealed_at = "2026-11-03T08:36:00.005Z".into();
    assert!(matches!(proof(&later).verify(boot), Err(Error::Signature)));
    let mut unsigned = batch;
    unsigned.signature = URL_SAFE_NO_PAD.encode([0; crate::signing::SIGNATURE_BYTES]);
    assert!(matches!(
        proof(&unsigned).verify(boot),
        Err(Error::Signature)
    ));
}

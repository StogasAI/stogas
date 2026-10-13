use super::*;

// The index is the ledger's published split of the hardware session bundle.
const INDEX: &[u8] = include_bytes!("../../../../tests/fixtures/evidence-archive-v1.json");

fn bundle() -> Value {
    let session: Value = serde_json::from_str(include_str!(
        "../../../../tests/fixtures/hardware-session-v1.json"
    ))
    .unwrap();
    session["bundle"].clone()
}

fn objects(body: &Value) -> BTreeMap<String, Value> {
    [&body["sigstore"], &body["keys"], &body["approvals"]]
        .into_iter()
        .chain(
            body["vendor_collateral"]
                .as_array()
                .unwrap()
                .iter()
                .map(|entry| &entry["der_base64url"]),
        )
        .map(|value| (payload_sha256(value).unwrap(), value.clone()))
        .collect()
}

#[test]
fn rebuilds_the_published_bundle() {
    let bundle = bundle();
    let index = Index::parse(INDEX, bundle["body_sha256"].as_str().unwrap()).unwrap();
    let evidence = index.assemble(&objects(&bundle["body"])).unwrap();
    assert_eq!(serde_json::from_slice::<Value>(&evidence).unwrap(), bundle);
}

#[test]
fn rejects_substituted_indexes_and_objects() {
    let bundle = bundle();
    let expected = bundle["body_sha256"].as_str().unwrap();
    let index: Value = serde_json::from_slice(INDEX).unwrap();
    let mut changes = Vec::new();
    for (field, value) in [
        ("body_sha256", json!("f".repeat(64))),
        ("keys", json!("../outside")),
        ("sizes", json!({})),
        ("unknown", json!(true)),
    ] {
        let mut change = index.clone();
        change[field] = value;
        changes.push(change);
    }
    let mut oversized = index.clone();
    for size in oversized["sizes"].as_object_mut().unwrap().values_mut() {
        *size = json!(MAX_INPUT_BYTES);
    }
    changes.push(oversized);
    for change in changes {
        assert!(Index::parse(&serde_json::to_vec(&change).unwrap(), expected).is_err());
    }

    let mut objects = objects(&bundle["body"]);
    let approvals = objects
        .get_mut(index["approvals"].as_str().unwrap())
        .unwrap();
    approvals["document"]["revision"] =
        json!(approvals["document"]["revision"].as_u64().unwrap() + 1);
    let error = Index::parse(INDEX, expected)
        .unwrap()
        .assemble(&objects)
        .unwrap_err();
    assert!(error.to_string().contains("archived digest"));
}

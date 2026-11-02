use super::*;

// The index is the ledger's published split of the hardware session evidence.
const INDEX: &[u8] = include_bytes!("../../../../tests/fixtures/evidence-archive-v1.json");

fn evidence() -> Value {
    let session: Value = serde_json::from_str(include_str!(
        "../../../../tests/fixtures/hardware-session-v1.json"
    ))
    .unwrap();
    session["evidence"].clone()
}

fn objects(document: &Value) -> BTreeMap<String, Value> {
    let releases = ["gateways", "catalogs"]
        .into_iter()
        .flat_map(|field| document[field].as_array().unwrap());
    let collateral = document["vendor_collateral"]
        .as_array()
        .unwrap()
        .iter()
        .map(|row| &row["der_base64url"]);
    [
        &document["keys"],
        &document["sigstore"],
        &document["hardware_policies"],
    ]
    .into_iter()
    .chain(releases)
    .chain(collateral)
    .map(|value| (payload_sha256(value).unwrap(), value.clone()))
    .collect()
}

#[test]
fn rebuilds_the_published_evidence() {
    let evidence = evidence();
    let index = Index::parse(INDEX, &payload_sha256(&evidence["document"]).unwrap()).unwrap();
    let rebuilt = index.assemble(&objects(&evidence["document"])).unwrap();
    assert_eq!(serde_json::from_slice::<Value>(&rebuilt).unwrap(), evidence);
}

#[test]
fn rejects_substituted_indexes_and_objects() {
    let evidence = evidence();
    let expected = payload_sha256(&evidence["document"]).unwrap();
    let index: Value = serde_json::from_slice(INDEX).unwrap();
    let mut changes = Vec::new();
    for (field, value) in [
        ("evidence_sha256", json!("f".repeat(64))),
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
        assert!(Index::parse(&serde_json::to_vec(&change).unwrap(), &expected).is_err());
    }

    let mut objects = objects(&evidence["document"]);
    let gateway = objects
        .get_mut(index["gateways"][0].as_str().unwrap())
        .unwrap();
    gateway["document"]["sequence"] = json!(gateway["document"]["sequence"].as_u64().unwrap() + 1);
    let error = Index::parse(INDEX, &expected)
        .unwrap()
        .assemble(&objects)
        .unwrap_err();
    assert!(error.to_string().contains("archived digest"));
}

#[test]
fn rebuilds_signed_onion_addresses_and_rejects_an_index_without_them() {
    let mut evidence = evidence();
    evidence["document"]["onion_services"] = json!({
        "api": format!("{}d.onion", "a".repeat(55)),
        "app": format!("{}d.onion", "b".repeat(55)),
        "website": format!("{}d.onion", "c".repeat(55)),
    });
    let expected = payload_sha256(&evidence["document"]).unwrap();
    let mut index: Value = serde_json::from_slice(INDEX).unwrap();
    index["evidence_sha256"] = json!(expected);
    let objects = objects(&evidence["document"]);

    let without = Index::parse(&serde_json::to_vec(&index).unwrap(), &expected).unwrap();
    let error = without.assemble(&objects).unwrap_err();
    assert!(error.to_string().contains("archived digest"));

    index["onion_services"] = evidence["document"]["onion_services"].clone();
    let rebuilt = Index::parse(&serde_json::to_vec(&index).unwrap(), &expected)
        .unwrap()
        .assemble(&objects)
        .unwrap();
    assert_eq!(serde_json::from_slice::<Value>(&rebuilt).unwrap(), evidence);
}

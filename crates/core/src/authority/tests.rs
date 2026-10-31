use super::*;
use crate::signing::SigningKey;
use serde_json::json;

const NOW: i64 = 1_789_900_000_000;

fn key(seed: u8) -> (OnlineKey, SigningKey) {
    let signer = SigningKey::from_seeds(&[[seed; 32]; 2]);
    (
        OnlineKey {
            key_id: format!("key-{seed}"),
            public_key: STANDARD.encode(signer.public_key_spki().unwrap()),
            rekor_public_key: STANDARD.encode(
                crate::signing::RekorSubmissionKey::from_seed(&[seed; 32])
                    .unwrap()
                    .public_key_spki()
                    .unwrap(),
            ),
        },
        signer,
    )
}

fn root(seed: u8) -> RootKey {
    let key = key(seed).0;
    RootKey {
        key_id: key.key_id,
        public_key: key.public_key,
        rekor_public_key: key.rekor_public_key,
        rekor_v2: None,
    }
}

fn keys(generation: u64, seed: u8, retired: &[u8]) -> KeyManifest {
    let mut retired_keys: Vec<_> = retired.iter().map(|seed| key(*seed).0).collect();
    retired_keys.sort_by(|a, b| a.key_id.cmp(&b.key_id));
    KeyManifest {
        schema: KEY_MANIFEST_SCHEMA.into(),
        environment: Environment::Production,
        generation,
        expires_at: "2100-01-01T00:00:00Z".into(),
        active_key: key(seed).0,
        retired_keys,
    }
}

fn document(keys: &KeyManifest, revision: u64) -> EvidenceDocument {
    EvidenceDocument {
        schema: EVIDENCE_SCHEMA.into(),
        environment: keys.environment,
        revision,
        keys: SignedKeyManifest {
            signature: sign(&serde_json::to_value(keys).unwrap(), 1),
            document: keys.clone(),
            inclusion: Value::Null,
        },
        sigstore: sigstore_fixture().0.clone(),
        gateways: vec![crate::tests::release_fixture()],
        catalogs: vec![crate::tests::catalog_fixture()],
        hardware_policies: serde_json::from_str(include_str!(
            "../../tests/fixtures/milan-hardware-policy.json"
        ))
        .unwrap(),
        vendor_collateral: vec![],
        onion_services: None,
    }
}

fn onion_services() -> OnionServices {
    OnionServices {
        api: crate::tests::onion_address([1; 32], 3),
        app: crate::tests::onion_address([2; 32], 3),
        website: crate::tests::onion_address([3; 32], 3),
    }
}

fn sign(document: &Value, seed: u8) -> StogasSignature {
    let (key, signer) = key(seed);
    let mut payload = STOGAS_SIGNATURE_DOMAIN.to_vec();
    payload.extend_from_slice(&canonical_payload(document).unwrap());
    StogasSignature {
        key_id: key.key_id,
        signature: URL_SAFE_NO_PAD.encode(signer.sign(&payload).unwrap()),
    }
}

fn verified_keys(keys: &KeyManifest) -> VerifiedKeys {
    VerifiedKeys {
        digest: payload_sha256(keys).unwrap(),
        document: keys.clone(),
        published_unix_ms: 0,
    }
}

fn check(document: EvidenceDocument) -> Result<VerifiedEvidence, Error> {
    let keys = verified_keys(&document.keys.document);
    check_document(keys, document, Arc::clone(&sigstore_fixture().1), None)
}

// Exercises acceptance independently of Rekor's existing cryptographic test suite. Production
// candidates carry a proof only after the signature and the log inclusion pass.
fn candidate(document: EvidenceDocument, seed: u8) -> VerifiedEvidence {
    let mut candidate = check(document).unwrap();
    candidate.proof = Some(Proof {
        signature: sign(&serde_json::to_value(&candidate.document).unwrap(), seed),
        inclusion: Value::Null,
    });
    candidate
}

/// Refreshes as the verifier does: learn the manifest, check that the document may follow the
/// accepted evidence, then install it with its signature.
fn admit(authority: &mut Authority, document: EvidenceDocument, seed: u8) -> Result<(), Error> {
    let keys = verified_keys(&document.keys.document);
    authority.key_state.learn(keys.clone())?;
    let mut candidate = authority.check(keys, document, Arc::clone(&sigstore_fixture().1), NOW)?;
    candidate.proof = Some(Proof {
        signature: sign(&serde_json::to_value(&candidate.document).unwrap(), seed),
        inclusion: Value::Null,
    });
    authority.accept(candidate)
}

fn authority() -> Authority {
    Authority::new(Environment::Production, root(1)).unwrap()
}

#[cfg(all(feature = "snp", feature = "staging"))]
impl VerifiedEvidence {
    /// Appraisal tests vary already authenticated content without a signing authority.
    pub(crate) fn edited(mut self, edit: impl FnOnce(&mut EvidenceDocument)) -> Self {
        edit(&mut self.document);
        self
    }
}

#[cfg(feature = "staging")]
fn session() -> Value {
    serde_json::from_str(include_str!(
        "../../../../tests/fixtures/hardware-session-v1.json"
    ))
    .unwrap()
}

/// Verify logged evidence as a refresh does, without installing it.
#[cfg(feature = "staging")]
fn verify_logged(
    authority: &Authority,
    evidence: &Value,
    now: i64,
) -> Result<VerifiedEvidence, Error> {
    let document = &evidence["document"];
    let sigstore = Arc::new(VerifiedSigstore::verify(
        &serde_json::from_value(document["sigstore"].clone()).unwrap(),
    )?);
    let keys = authority.verify_keys(
        &serde_json::to_vec(&document["keys"]).unwrap(),
        sigstore.trusted_root(),
    )?;
    let signed: SignedEvidence = serde_json::from_value(evidence.clone()).map_err(invalid)?;
    let mut candidate = authority.check(keys, signed.document, sigstore, now)?;
    verify_proof(&mut candidate, signed.signature, signed.inclusion)?;
    Ok(candidate)
}

#[cfg(feature = "staging")]
#[test]
fn actual_logged_evidence_verifies_and_rejects_substituted_material() {
    let session = session();
    let evidence = &session["evidence"];
    let root: RootKey = serde_json::from_value(session["root"].clone()).unwrap();
    let mut authority = Authority::new(Environment::Staging, root).unwrap();
    let now = session["verified_at_ms"].as_i64().unwrap();
    let candidate = verify_logged(&authority, evidence, now).unwrap();
    assert_eq!(candidate.keys().generation, 1);
    authority.accept(candidate).unwrap();
    for pointer in [
        "/document/keys/document/active_key/public_key",
        "/document/keys/document/active_key/rekor_public_key",
        "/document/keys/signature/signature",
        "/document/keys/inclusion/verificationMaterial/publicKey/hint",
        "/document/keys/inclusion/verificationMaterial/tlogEntries/0/canonicalizedBody",
        "/document/keys/inclusion/verificationMaterial/tlogEntries/0/inclusionPromise/signedEntryTimestamp",
        "/document/keys/inclusion/verificationMaterial/tlogEntries/0/inclusionProof/rootHash",
        "/document/keys/inclusion/verificationMaterial/tlogEntries/0/inclusionProof/checkpoint/envelope",
        "/signature/signature",
        "/inclusion/verificationMaterial/tlogEntries/0/canonicalizedBody",
        "/inclusion/verificationMaterial/tlogEntries/0/inclusionProof/rootHash",
    ] {
        let mut changed = evidence.clone();
        *changed.pointer_mut(pointer).unwrap() = Value::String("invalid".into());
        assert!(
            verify_logged(&authority, &changed, now).is_err(),
            "accepted {pointer}"
        );
        assert_eq!(authority.accepted().unwrap().keys().generation, 1);
    }
}

#[cfg(feature = "staging")]
#[test]
fn only_the_designated_rekor_key_can_log_a_signature() {
    let session = session();
    let root: RootKey = serde_json::from_value(session["root"].clone()).unwrap();
    let authority = Authority::new(Environment::Staging, root.clone()).unwrap();
    let trust = sigstore_fixture().1.trusted_root();
    let mut keys = session["evidence"]["document"]["keys"].clone();
    let verify = |keys: &Value| authority.verify_keys(&serde_json::to_vec(keys).unwrap(), trust);
    verify(&keys).unwrap();
    // Another Rekor key logged the same root-signed manifest; a search by the root's key
    // would miss that entry.
    let republication: Value = serde_json::from_str(include_str!(
        "../../../../tests/fixtures/rekor-republication-v1.json"
    ))
    .unwrap();
    keys["inclusion"] = republication["inclusion"].clone();
    assert!(matches!(verify(&keys), Err(Error::Transparency(_))));

    let evidence: SignedEvidence = serde_json::from_value(session["evidence"].clone()).unwrap();
    let document = serde_json::to_value(&evidence.document).unwrap();
    let logged = |submitter: &str| {
        verify_document_inclusion(
            &document,
            &evidence.signature,
            &evidence.inclusion,
            trust,
            submitter,
            None,
        )
    };
    logged(&evidence.document.keys.document.active_key.rekor_public_key).unwrap();
    assert!(matches!(
        logged(&root.rekor_public_key),
        Err(Error::Transparency(_))
    ));
}

const V2_LOG: &str = "log2025-1.rekor.sigstore.dev";

fn scope(first_index: u64, opened_from: &str) -> RekorV2Scope {
    RekorV2Scope {
        first_indexes: BTreeMap::from([(V2_LOG.to_owned(), first_index)]),
        opened_from: opened_from.into(),
    }
}

fn position(origin: &str, index: u64, log_start: Option<i64>) -> LogPosition {
    LogPosition {
        origin: origin.into(),
        index,
        log_start,
    }
}

#[test]
fn rekor_v2_entries_count_only_where_the_watcher_reads_every_entry() {
    // 2026-10-31T00:00:00Z.
    const OPENED_FROM: i64 = 1_793_404_800;
    let scope = scope(1000, "2026-10-31T00:00:00Z");
    for (position, counts) in [
        // A listed log counts from its first index on, whenever it opened.
        (position(V2_LOG, 1000, Some(1_758_585_600)), true),
        (position(V2_LOG, u64::MAX, None), true),
        (position(V2_LOG, 999, Some(OPENED_FROM)), false),
        (position(V2_LOG, 0, Some(OPENED_FROM + 1)), false),
        // Another log counts whole if it opened at or after the scope's time.
        (
            position("log2026-1.rekor.sigstore.dev", 0, Some(OPENED_FROM)),
            true,
        ),
        (
            position("log2027-1.rekor.sigstore.dev", 7, Some(OPENED_FROM + 1)),
            true,
        ),
        (
            position("log2026-1.rekor.sigstore.dev", 0, Some(OPENED_FROM - 1)),
            false,
        ),
        (position("log2026-1.rekor.sigstore.dev", 0, None), false),
        // Origins match exactly.
        (position("LOG2025-1.rekor.sigstore.dev", 1000, None), false),
    ] {
        assert_eq!(
            check_rekor_v2_scope(Some(&position), Some(&scope)).is_ok(),
            counts,
            "{position:?}"
        );
    }
    // Rekor v1 has a search index, and a root without a scope accepts no Rekor v2 entry.
    check_rekor_v2_scope(None, None).unwrap();
    check_rekor_v2_scope(None, Some(&scope)).unwrap();
    assert_eq!(
        check_rekor_v2_scope(Some(&position(V2_LOG, 1000, Some(OPENED_FROM))), None),
        Err(Error::Transparency(format!(
            "Rekor v2 entry 1000 of {V2_LOG} is outside the root's Rekor v2 scope"
        )))
    );
}

#[test]
fn roots_name_rekor_v2_scopes_exactly() {
    let with = |rekor_v2| RootKey {
        rekor_v2,
        ..root(1)
    };
    Authority::new(Environment::Production, with(None)).unwrap();
    Authority::new(
        Environment::Production,
        with(Some(scope(0, "2026-10-31T00:00:00Z"))),
    )
    .unwrap();
    for opened_from in [
        "2026-10-31",
        "2026-10-31T00:00:00.5Z",
        "2026-10-31T00:00:00+00:00",
        "2026-10-31T01:00:00+01:00",
        "",
    ] {
        assert!(
            Authority::new(Environment::Production, with(Some(scope(0, opened_from)))).is_err(),
            "{opened_from}"
        );
    }
    for origin in [
        "",
        "Log.example",
        "log example",
        "https://log.example",
        "log.example/",
    ] {
        let mut scope = scope(0, "2026-10-31T00:00:00Z");
        scope.first_indexes = BTreeMap::from([(origin.to_owned(), 0)]);
        assert!(
            Authority::new(Environment::Production, with(Some(scope))).is_err(),
            "{origin}"
        );
    }
    // The compiled roots parse, and a root without a scope serializes as it did before.
    let json = serde_json::to_value(with(None)).unwrap();
    assert!(json.get("rekor_v2").is_none());
    let scoped: RootKey = serde_json::from_value(serde_json::json!({
        "key_id": "k", "public_key": "p", "rekor_public_key": "r",
        "rekor_v2": {"first_indexes": {V2_LOG: 5}, "opened_from": "2026-10-31T00:00:00Z"}
    }))
    .unwrap();
    assert_eq!(scoped.rekor_v2, Some(scope(5, "2026-10-31T00:00:00Z")));
    assert!(
        serde_json::from_value::<RootKey>(serde_json::json!({
            "key_id": "k", "public_key": "p", "rekor_public_key": "r",
            "rekor_v2": {"first_indexes": {}, "opened_from": "2026-10-31T00:00:00Z", "other": 1}
        }))
        .is_err()
    );
}

#[cfg(feature = "staging")]
#[test]
fn a_signature_needs_a_manifest_logged_before_it_and_unexpired_then() {
    let session = session();
    let root: RootKey = serde_json::from_value(session["root"].clone()).unwrap();
    let authority = Authority::new(Environment::Staging, root).unwrap();
    let trust = sigstore_fixture().1.trusted_root();
    let keys = &session["evidence"]["document"]["keys"];
    let bytes = serde_json::to_vec(keys).unwrap();
    let logged = authority
        .verify_keys(&bytes, trust)
        .unwrap()
        .published_unix_ms;
    let expiry = authority
        .verify_key_manifest_at(&bytes, trust, logged)
        .unwrap()
        .expiry_unix_ms()
        .unwrap();
    authority
        .verify_key_manifest_at(&bytes, trust, expiry - 1)
        .unwrap();
    assert!(matches!(
        authority.verify_key_manifest_at(&bytes, trust, logged - 1),
        Err(Error::Invalid(_))
    ));
    assert_eq!(
        authority
            .verify_key_manifest_at(&bytes, trust, expiry)
            .unwrap_err(),
        Error::Expired
    );
}

#[test]
fn each_signer_has_its_own_rekor_key() {
    let root = root(1);
    validate_keys(&keys(1, 3, &[2]), Environment::Production, &root).unwrap();
    let mut shared = keys(1, 3, &[2]);
    shared.retired_keys[0].rekor_public_key = shared.active_key.rekor_public_key.clone();
    assert!(validate_keys(&shared, Environment::Production, &root).is_err());
    let mut root_key = keys(1, 3, &[]);
    root_key.active_key.rekor_public_key = root.rekor_public_key.clone();
    assert!(validate_keys(&root_key, Environment::Production, &root).is_err());
}

#[test]
fn unsigned_payload_identity_ignores_wrapping_signatures_and_key_order() {
    let payload = json!({"schema":"stogas.gateway.release.v1", "build":{"z":2,"a":1}});
    let reordered = json!({"build":{"a":1,"z":2}, "schema":"stogas.gateway.release.v1"});
    assert_eq!(
        payload_sha256(&payload).unwrap(),
        payload_sha256(&reordered).unwrap()
    );
    assert_eq!(
        payload_sha256(&payload).unwrap(),
        hex::encode(Sha256::digest(
            br#"{"build":{"a":1,"z":2},"schema":"stogas.gateway.release.v1"}"#
        ))
    );
    assert_ne!(sign(&payload, 2).signature, sign(&payload, 3).signature);
}

#[test]
fn unsigned_candidates_are_checked_but_never_accepted() {
    let mut authority = authority();
    let keys = keys(1, 2, &[]);
    let unsigned = authority
        .check(
            verified_keys(&keys),
            document(&keys, 1),
            Arc::clone(&sigstore_fixture().1),
            NOW,
        )
        .unwrap();
    assert!(unsigned.proof().is_none());
    assert_eq!(authority.accept(unsigned).unwrap_err(), Error::Signature);
    assert!(authority.accepted().is_none());
}

#[test]
fn rotation_supersedes_a_compromised_max_revision() {
    let mut authority = authority();
    admit(&mut authority, document(&keys(1, 2, &[]), MAX_REVISION), 2).unwrap();
    admit(&mut authority, document(&keys(2, 3, &[2]), 1), 3).unwrap();
    assert_eq!(
        admit(&mut authority, document(&keys(1, 2, &[]), MAX_REVISION), 2).unwrap_err(),
        Error::Rollback
    );
    assert_eq!(authority.accepted().unwrap().keys().generation, 2);
}

#[test]
fn root_expiry_bounds_every_revision_and_renewal_needs_a_new_generation() {
    let mut authority = authority();
    let keys = keys(1, 2, &[]);
    let original = candidate(document(&keys, 1), 2);
    let deadline = keys.expiry_unix_ms().unwrap();
    assert_eq!(original.valid_until(deadline - 1).unwrap(), deadline);
    assert_eq!(original.valid_until(deadline), Err(Error::Expired));
    assert_eq!(original.valid_until(deadline + 1), Err(Error::Expired));
    let online_update = candidate(document(&keys, MAX_REVISION), 2);
    assert_eq!(online_update.valid_until(deadline), Err(Error::Expired));
    admit(&mut authority, document(&keys, 1), 2).unwrap();
    assert_eq!(
        authority
            .check(
                verified_keys(&keys),
                document(&keys, 2),
                Arc::clone(&sigstore_fixture().1),
                deadline
            )
            .unwrap_err(),
        Error::Expired
    );

    // Another root decision under the same generation conflicts with the accepted one.
    let mut renewed = keys.clone();
    renewed.expires_at = "2100-02-01T00:00:00Z".into();
    assert_eq!(
        admit(&mut authority, document(&renewed, 2), 2).unwrap_err(),
        Error::Equivocation
    );
    renewed.generation += 1;
    let renewal = candidate(document(&renewed, 2), 2);
    renewal.valid_until(deadline).unwrap();
    assert_eq!(renewal.keys().active_key, original.keys().active_key);
    admit(&mut authority, document(&renewed, 2), 2).unwrap();
    assert_eq!(
        admit(&mut authority, document(&keys, 1), 2).unwrap_err(),
        Error::Rollback
    );
}

#[test]
fn root_expiry_has_one_unambiguous_timestamp_representation() {
    let root = root(1);
    for expiry in [
        "",
        "2100-01-01",
        "2100-01-01T00:00:00.000Z",
        "2100-01-01T00:00:00+00:00",
        "2100-01-01T00:00:00+01:00",
        "2100-02-30T00:00:00Z",
        "2100-01-01T00:00:60Z",
    ] {
        let mut manifest = keys(1, 2, &[]);
        manifest.expires_at = expiry.into();
        assert!(
            validate_keys(&manifest, Environment::Production, &root).is_err(),
            "{expiry}"
        );
    }
}

#[test]
fn revisions_detect_only_conflicting_decisions_and_reject_older_ones() {
    let mut authority = authority();
    let keys = keys(1, 2, &[]);
    let first = document(&keys, 1);
    admit(&mut authority, first.clone(), 2).unwrap();
    admit(&mut authority, first, 2).unwrap();
    let mut conflict = document(&keys, 1);
    conflict.gateways.clear();
    assert_eq!(
        admit(&mut authority, conflict, 2).unwrap_err(),
        Error::Equivocation
    );
    admit(&mut authority, document(&keys, 2), 2).unwrap();
    assert_eq!(
        admit(&mut authority, document(&keys, 1), 2).unwrap_err(),
        Error::Rollback
    );
    assert_eq!(authority.accepted().unwrap().document().revision, 2);

    // Another manifest under the same generation stops that generation until a newer one.
    let other_key = self::keys(1, 3, &[2]);
    assert_eq!(
        admit(&mut authority, document(&other_key, 3), 3).unwrap_err(),
        Error::Equivocation
    );
    assert_eq!(
        admit(&mut authority, document(&keys, 3), 2).unwrap_err(),
        Error::Equivocation
    );
    admit(&mut authority, document(&self::keys(2, 3, &[2]), 1), 3).unwrap();
}

#[test]
fn root_decisions_can_omit_retired_keys_without_authorizing_them() {
    let mut authority = authority();
    admit(&mut authority, document(&keys(1, 2, &[]), 1), 2).unwrap();
    admit(&mut authority, document(&keys(2, 3, &[2]), 1), 3).unwrap();
    let pruned = keys(3, 3, &[]);
    admit(&mut authority, document(&pruned, 1), 3).unwrap();
    let mut fresh = self::authority();
    admit(&mut fresh, document(&pruned, 1), 3).unwrap();
    let mut unsigned = check(document(&pruned, 2)).unwrap();
    let value = serde_json::to_value(unsigned.document()).unwrap();
    for signer in [1, 2, 4] {
        assert_eq!(
            verify_proof(&mut unsigned, sign(&value, signer), Value::Null).unwrap_err(),
            Error::InactiveKey
        );
    }
    // The root can also rotate without carrying earlier public keys forward.
    admit(&mut authority, document(&keys(4, 4, &[]), 1), 4).unwrap();
}

#[test]
fn signatures_are_bound_to_the_active_key_document_and_purpose() {
    let keys = keys(2, 3, &[2]);
    let original = document(&keys, 1);
    let value = serde_json::to_value(&original).unwrap();
    let verify = |document: EvidenceDocument, signature: StogasSignature| {
        let mut candidate = check(document)?;
        verify_proof(&mut candidate, signature, Value::Null)
    };
    // The signature passes; only the absent unit-test log entry remains.
    assert!(matches!(
        verify(original.clone(), sign(&value, 3)),
        Err(Error::Transparency(_))
    ));
    for seed in [1, 2, 4] {
        assert_eq!(
            verify(original.clone(), sign(&value, seed)).unwrap_err(),
            Error::InactiveKey
        );
    }
    let mut other_signer = sign(&value, 3);
    other_signer.signature = sign(&value, 4).signature;
    assert_eq!(
        verify(original.clone(), other_signer).unwrap_err(),
        Error::Signature
    );
    let without_domain = StogasSignature {
        key_id: keys.active_key.key_id.clone(),
        signature: URL_SAFE_NO_PAD
            .encode(key(3).1.sign(&canonical_payload(&value).unwrap()).unwrap()),
    };
    assert_eq!(
        verify(original.clone(), without_domain).unwrap_err(),
        Error::Signature
    );
    let edits: [fn(&mut EvidenceDocument); 4] = [
        |document| document.revision += 1,
        |document| document.hardware_policies[0].minimum_tcb.snp -= 1,
        |document| document.gateways.clear(),
        |document| document.keys.signature.signature.clear(),
    ];
    for edit in edits {
        let mut tampered = original.clone();
        edit(&mut tampered);
        assert_eq!(
            verify(tampered, sign(&value, 3)).unwrap_err(),
            Error::Signature
        );
    }
    // The document must carry exactly the key manifest and Sigstore files the caller verified.
    let mut other_sigstore = original.clone();
    other_sigstore.sigstore.roots.push(String::new());
    let mut other_keys = original;
    other_keys.keys.document.generation += 1;
    for substituted in [other_sigstore, other_keys] {
        assert_eq!(
            check_document(
                verified_keys(&keys),
                substituted,
                Arc::clone(&sigstore_fixture().1),
                None
            )
            .unwrap_err(),
            Error::Invalid("verified keys or Sigstore files differ".into())
        );
    }
}

#[test]
fn documents_reject_ambiguous_ids_keys_versions_and_counters() {
    let root = root(1);
    for generation in [0, MAX_REVISION + 1, u64::MAX] {
        assert!(validate_keys(&keys(generation, 2, &[]), Environment::Production, &root).is_err());
    }
    for invalid in [keys(1, 1, &[]), keys(1, 2, &[2]), keys(1, 2, &[3, 3])] {
        assert!(validate_keys(&invalid, Environment::Production, &root).is_err());
    }
    let mut duplicate_public_key = keys(1, 2, &[3]);
    duplicate_public_key.retired_keys[0].public_key =
        duplicate_public_key.active_key.public_key.clone();
    assert!(validate_keys(&duplicate_public_key, Environment::Production, &root).is_err());
    let mut unordered = keys(1, 2, &[3, 4]);
    unordered.retired_keys.reverse();
    assert!(validate_keys(&unordered, Environment::Production, &root).is_err());
    let mut unknown_version = keys(1, 2, &[]);
    unknown_version.schema = "stogas.keys.v2".into();
    assert!(validate_keys(&unknown_version, Environment::Production, &root).is_err());
    for id in ["", "a b", "../key", "é", &"a".repeat(129)] {
        let mut invalid_key = key(2).0;
        invalid_key.key_id = id.into();
        assert!(decode_key(&invalid_key.key_id, &invalid_key.public_key).is_err());
    }
    let keys = keys(1, 2, &[]);
    for revision in [0, MAX_REVISION + 1, u64::MAX] {
        assert!(check(document(&keys, revision)).is_err());
    }
    let mut other_schema = document(&keys, 1);
    other_schema.schema = KEY_MANIFEST_SCHEMA.into();
    assert!(check(other_schema).is_err());
    for sequences in [[1, 1], [2, 1]] {
        let mut gateways = document(&keys, 1);
        gateways.gateways = sequences
            .iter()
            .map(|sequence| {
                let mut release = crate::tests::release_fixture();
                release.document.sequence = *sequence;
                release
            })
            .collect();
        let mut catalogs = document(&keys, 1);
        catalogs.catalogs = sequences
            .iter()
            .map(|sequence| {
                let mut catalog = crate::tests::catalog_fixture();
                catalog.document.sequence = *sequence;
                catalog
            })
            .collect();
        for invalid in [gateways, catalogs] {
            assert_eq!(
                check(invalid).unwrap_err(),
                Error::Invalid("approved releases must be ordered by unique sequence".into())
            );
        }
    }
}

#[test]
fn root_inclusion_is_mandatory_and_failure_never_advances_state() {
    let mut authority = authority();
    admit(&mut authority, document(&keys(1, 2, &[]), 1), 2).unwrap();
    let keys = SignedKeyManifest {
        signature: sign(&serde_json::to_value(keys(2, 3, &[2])).unwrap(), 1),
        document: keys(2, 3, &[2]),
        inclusion: json!({}),
    };
    let error = authority
        .observe_keys(
            &serde_json::to_vec(&keys).unwrap(),
            sigstore_fixture().1.trusted_root(),
        )
        .unwrap_err();
    assert!(matches!(error, Error::Transparency(_)));
    assert_eq!(authority.accepted().unwrap().keys().generation, 1);
}

#[test]
fn onion_addresses_must_be_canonical_version_3_addresses() {
    // The Tor Project's published address pins the encoding and checksum to Tor's own.
    for address in [
        "2gzyxa5ihm7nsggfxnu52rck2vv4rvmdlkiu3zzui5du4xyclen53wid.onion",
        &crate::tests::onion_address([0; 32], 3),
        &crate::tests::onion_address([255; 32], 3),
    ] {
        assert!(valid_onion_address(address), "{address}");
    }
    let valid = crate::tests::onion_address([9; 32], 3);
    let label = valid.trim_end_matches(".onion");
    let swapped = format!(
        "{}{}.onion",
        if label.starts_with('a') { 'b' } else { 'a' },
        &label[1..]
    );
    for address in [
        swapped.as_str(),
        &valid.to_uppercase(),
        &format!("{label}.onion."),
        &format!("http://{valid}"),
        &format!("www.{valid}"),
        label,
        &format!("{}.onion", &label[1..]),
        &format!("{label}a.onion"),
        &format!("{}1.onion", &label[1..]),
        "expyuzz4wqqyqhjn.onion",
        &crate::tests::onion_address([9; 32], 2),
        &crate::tests::onion_address([9; 32], 4),
        "",
    ] {
        assert!(!valid_onion_address(address), "{address}");
    }
}

#[test]
fn evidence_may_sign_onion_addresses_and_rejects_invalid_ones() {
    let keys = keys(1, 2, &[]);
    let mut signed = document(&keys, 1);
    signed.onion_services = Some(onion_services());
    let verified = check(signed.clone()).unwrap();
    assert_eq!(verified.document().onion_services, Some(onion_services()));
    // Signatures cover the serialized document, so the field must round-trip exactly, and
    // revisions from before it existed must serialize as they were signed.
    let value = serde_json::to_value(&signed).unwrap();
    assert_eq!(
        value["onion_services"]["api"],
        json!(crate::tests::onion_address([1; 32], 3))
    );
    let earlier = serde_json::to_value(document(&keys, 1)).unwrap();
    assert!(earlier.get("onion_services").is_none());
    assert!(
        serde_json::from_value::<EvidenceDocument>(earlier)
            .unwrap()
            .onion_services
            .is_none()
    );
    for edit in [
        |services: &mut OnionServices| services.api = "expyuzz4wqqyqhjn.onion".into(),
        |services: &mut OnionServices| services.app = services.app.to_uppercase(),
        |services: &mut OnionServices| services.website = crate::tests::onion_address([3; 32], 2),
    ] {
        let mut invalid = signed.clone();
        edit(invalid.onion_services.as_mut().unwrap());
        assert_eq!(
            check(invalid).unwrap_err(),
            Error::Invalid("onion address".into())
        );
    }
    let mut extra = value;
    extra["onion_services"]["status"] = json!("onion");
    assert!(serde_json::from_value::<EvidenceDocument>(extra).is_err());
}

#[test]
fn strict_boundary_rejects_unknown_duplicate_trailing_and_oversized_inputs() {
    let authority = authority();
    let keys = SignedKeyManifest {
        signature: sign(&serde_json::to_value(keys(1, 2, &[])).unwrap(), 1),
        document: keys(1, 2, &[]),
        inclusion: json!({}),
    };
    let valid = serde_json::to_string(&keys).unwrap();
    let trust = sigstore_fixture().1.trusted_root();
    for input in [
        format!("{valid}{{}}"),
        valid.replacen("\"generation\":1", "\"generation\":1,\"generation\":2", 1),
        valid.replacen("\"generation\":1", "\"generation\":1,\"extra\":true", 1),
    ] {
        assert!(matches!(
            authority.observe_keys(input.as_bytes(), trust),
            Err(Error::Invalid(_))
        ));
    }
    assert_eq!(
        authority
            .observe_keys(&vec![b' '; MAX_INPUT_BYTES + 1], trust)
            .unwrap_err(),
        Error::TooLarge
    );
    assert!(authority.accepted().is_none());
}

#[cfg(feature = "staging")]
#[test]
fn staging_capable_verifier_rejects_placeholders_in_a_production_context() {
    let mut gateway = crate::tests::release_fixture();
    let mut catalog = crate::tests::catalog_fixture();
    let file_sha256 =
        |document: Value| hex::encode(Sha256::digest(canonical_json(&document).unwrap()));
    gateway.provenance = json!({
        "_type": "https://in-toto.io/Statement/v1",
        "predicateType": "https://stogas.ai/attestations/staging-development/v1",
        "predicate": { "environment": "staging" },
        "subject": [
            { "name": "release-manifest.json", "digest": { "sha256": file_sha256(serde_json::to_value(&gateway.document).unwrap()) } },
            { "name": "gateway.igvm", "digest": { "sha256": gateway.document.artifacts.gateway_igvm.sha256 } }
        ]
    });
    catalog.provenance = json!({
        "_type": "https://in-toto.io/Statement/v1",
        "predicateType": "https://stogas.ai/attestations/staging-development/v1",
        "predicate": { "environment": "staging" },
        "subject": [
            { "name": "catalog-release.json", "digest": { "sha256": file_sha256(serde_json::to_value(&catalog.document).unwrap()) } },
            { "name": "catalog.json", "digest": { "sha256": &catalog.document.artifacts.root.sha256 } }
        ]
    });
    for (environment, allowed) in [
        (Environment::Staging, true),
        (Environment::Production, false),
    ] {
        let mut keys = keys(1, 2, &[]);
        keys.environment = environment;
        let evidence = check(document(&keys, 1)).unwrap();
        let gateway = evidence.verify_gateway(&gateway);
        let catalog = evidence.verify_catalog(&catalog);
        if allowed {
            gateway.unwrap();
            catalog.unwrap();
        } else {
            assert_eq!(gateway.unwrap_err(), Error::Authority);
            assert_eq!(catalog.unwrap_err(), Error::Authority);
        }
    }
}

#[cfg(feature = "staging")]
#[test]
fn environments_are_signed_and_cannot_share_candidates() {
    let authority = authority();
    let mut manifest = keys(1, 2, &[]);
    manifest.environment = Environment::Staging;
    assert_eq!(
        validate_keys(&manifest, authority.environment, &authority.root).unwrap_err(),
        Error::Authority
    );
    let mut production = document(&manifest, 1);
    production.environment = Environment::Production;
    assert_eq!(check(production).unwrap_err(), Error::Authority);
}

#[cfg(not(feature = "staging"))]
#[test]
fn production_build_cannot_parse_staging_authorization() {
    assert!(serde_json::from_value::<Environment>(json!("staging")).is_err());
}

#[cfg(feature = "staging")]
#[test]
fn compiled_staging_root_verifies_actual_logged_operational_delegation() {
    let bytes = include_bytes!("../../../../tests/fixtures/staging-key-manifest.json");
    let value: serde_json::Value = serde_json::from_slice(bytes).unwrap();
    let now = value["inclusion"]["verificationMaterial"]["tlogEntries"][0]["integratedTime"]
        .as_str()
        .unwrap()
        .parse::<i64>()
        .unwrap()
        * 1000
        + 1000;
    let verifier = crate::evidence::Verifier::stogas(Environment::Staging).unwrap();
    let sigstore = &sigstore_fixture().1;
    let keys = verifier.verify_key_manifest(bytes, sigstore, now).unwrap();
    assert_eq!(
        keys.active_key.key_id,
        "staging-stogas-online-2026-10-10-01"
    );
    assert_eq!(keys.generation, 58);
    assert!(keys.retired_keys.is_empty());
    let mut changed = value;
    changed["document"]["generation"] = json!(59);
    assert!(
        verifier
            .verify_key_manifest(&serde_json::to_vec(&changed).unwrap(), sigstore, now)
            .is_err()
    );
    // The production root has no Rekor key yet, so its authority fails closed; once it has one,
    // it must still reject this staging delegation.
    assert!(
        !crate::evidence::Verifier::stogas(Environment::Production)
            .is_ok_and(|production| production.verify_key_manifest(bytes, sigstore, now).is_ok())
    );
}

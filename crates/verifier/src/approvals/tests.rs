use super::*;
use crate::signing::SigningKey;
use serde_json::json;
use std::sync::LazyLock;

/// Sigstore files with no roots after the compiled one.
fn sigstore() -> Arc<VerifiedSigstore> {
    static SIGSTORE: LazyLock<Arc<VerifiedSigstore>> = LazyLock::new(|| {
        let files = SigstoreFiles {
            roots: vec![],
            targets: STANDARD.encode(include_bytes!(
                "../../../../tests/fixtures/sigstore-tuf/14.targets.json"
            )),
            trusted_root: STANDARD.encode(include_bytes!(
                "../../../../tests/fixtures/sigstore-tuf/trusted_root.json"
            )),
        };
        Arc::new(VerifiedSigstore::verify(&files).unwrap())
    });
    Arc::clone(&SIGSTORE)
}

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

fn signed(keys: &KeyManifest, revision: u64, seed: u8) -> SignedApprovalManifest {
    resign(
        ApprovalManifest {
            schema: APPROVAL_MANIFEST_SCHEMA.into(),
            environment: keys.environment,
            revision,
            key_manifest_sha256: payload_sha256(keys).unwrap(),
            sigstore_sha256: sigstore().digest().into(),
            gateways: vec![crate::tests::release_fixture()],
            catalogs: vec![crate::tests::catalog_fixture()],
            hardware_policy: serde_json::from_str(include_str!(
                "../../tests/fixtures/milan-hardware-policy.json"
            ))
            .unwrap(),
        },
        seed,
    )
}

fn resign(document: ApprovalManifest, seed: u8) -> SignedApprovalManifest {
    SignedApprovalManifest {
        signature: sign(&serde_json::to_value(&document).unwrap(), seed),
        document,
        inclusion: Value::Null,
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

// Exercises decision installation independently of Rekor's existing cryptographic test suite.
// Production candidates can only be constructed after the root signature and inclusion pass.
fn candidate(
    verifier: &ApprovalVerifier,
    generation: u64,
    revision: u64,
    seed: u8,
    retired: &[u8],
) -> VerifiedApprovals {
    let keys = keys(generation, seed, retired);
    validate_keys(&keys, verifier.environment, &verifier.root).unwrap();
    let signed = signed(&keys, revision, seed);
    verify_online_approval(verifier.authority, keys, signed, sigstore()).unwrap()
}

fn verifier() -> ApprovalVerifier {
    ApprovalVerifier::new(Environment::Production, root(1)).unwrap()
}

#[cfg(all(feature = "snp", feature = "staging"))]
impl VerifiedApprovals {
    /// Appraisal tests vary already authenticated content without a signing authority.
    pub(crate) fn edited(mut self, edit: impl FnOnce(&mut ApprovalManifest)) -> Self {
        edit(&mut self.approvals.document);
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

/// Verify a logged key manifest and the approval in `body` without installing them.
#[cfg(feature = "staging")]
fn verify_logged(
    verifier: &ApprovalVerifier,
    body: &Value,
    keys: &Value,
    now: i64,
) -> Result<VerifiedApprovals, Error> {
    let sigstore = Arc::new(VerifiedSigstore::verify(
        &serde_json::from_value(body["sigstore"].clone()).unwrap(),
    )?);
    let keys = verifier.verify_keys(
        &serde_json::to_vec(keys).unwrap(),
        sigstore.trusted_root(),
        now,
    )?;
    let approvals = serde_json::from_value(body["approvals"].clone()).unwrap();
    verifier.verify_with_keys(keys, approvals, sigstore, now)
}

#[cfg(feature = "staging")]
#[test]
fn actual_logged_root_manifest_verifies_and_rejects_substituted_material() {
    let session = session();
    let body = &session["bundle"]["body"];
    let root: RootKey = serde_json::from_value(session["root"].clone()).unwrap();
    let mut verifier = ApprovalVerifier::new(Environment::Staging, root).unwrap();
    let now = session["verified_at_ms"].as_i64().unwrap();
    let candidate = verify_logged(&verifier, body, &body["keys"], now).unwrap();
    assert_eq!(candidate.keys().generation, 1);
    verifier.accept(candidate).unwrap();
    for pointer in [
        "/document/active_key/public_key",
        "/document/active_key/rekor_public_key",
        "/signature/signature",
        "/inclusion/verificationMaterial/publicKey/hint",
        "/inclusion/verificationMaterial/tlogEntries/0/canonicalizedBody",
        "/inclusion/verificationMaterial/tlogEntries/0/inclusionPromise/signedEntryTimestamp",
        "/inclusion/verificationMaterial/tlogEntries/0/inclusionProof/rootHash",
        "/inclusion/verificationMaterial/tlogEntries/0/inclusionProof/checkpoint/envelope",
    ] {
        let mut changed = body["keys"].clone();
        *changed.pointer_mut(pointer).unwrap() = Value::String("invalid".into());
        assert!(
            verify_logged(&verifier, body, &changed, now).is_err(),
            "accepted {pointer}"
        );
        assert_eq!(verifier.accepted().unwrap().keys().generation, 1);
    }
}

#[cfg(feature = "staging")]
#[test]
fn another_publisher_can_log_the_same_root_authorization() {
    let session = session();
    let body = &session["bundle"]["body"];
    let mut keys = body["keys"].clone();
    let republication: Value = serde_json::from_str(include_str!(
        "../../../../tests/fixtures/rekor-republication-v1.json"
    ))
    .unwrap();
    let root: RootKey = serde_json::from_value(session["root"].clone()).unwrap();
    let verifier = ApprovalVerifier::new(Environment::Staging, root).unwrap();
    let now = session["verified_at_ms"].as_i64().unwrap();
    let original = verify_logged(&verifier, body, &keys, now).unwrap();
    keys["inclusion"] = republication["inclusion"].clone();
    let republished = verify_logged(&verifier, body, &keys, now).unwrap();
    assert_eq!(original.keys_digest, republished.keys_digest);
    assert_eq!(original.approvals_digest, republished.approvals_digest);

    // The manifest's publisher association is still root-signed public metadata.
    keys["document"]["active_key"]["rekor_public_key"] = json!(key(187).0.rekor_public_key);
    assert!(verify_logged(&verifier, body, &keys, now).is_err());
}

#[test]
fn distinct_signers_can_share_publisher_metadata() {
    let mut manifest = keys(1, 3, &[2]);
    manifest.retired_keys[0].rekor_public_key = manifest.active_key.rekor_public_key.clone();
    validate_keys(&manifest, Environment::Production, &root(1)).unwrap();
    manifest.retired_keys[0].public_key = manifest.active_key.public_key.clone();
    assert!(validate_keys(&manifest, Environment::Production, &root(1)).is_err());
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
fn rotation_supersedes_a_compromised_max_revision() {
    let mut verifier = verifier();
    let original = candidate(&verifier, 1, MAX_REVISION, 2, &[]);
    verifier.accept(original.clone()).unwrap();
    verifier
        .accept(candidate(&verifier, 2, 1, 3, &[2]))
        .unwrap();
    assert_eq!(verifier.accept(original).unwrap_err(), Error::Rollback);
    assert_eq!(verifier.accepted().unwrap().keys().generation, 2);
}

#[test]
fn root_expiry_bounds_online_updates_and_renewal_requires_a_new_approval() {
    let mut verifier = verifier();
    let original = candidate(&verifier, 1, 1, 2, &[]);
    let deadline = original.keys.expiry_unix_ms().unwrap();
    assert_eq!(original.valid_until(deadline - 1).unwrap(), deadline);
    assert_eq!(original.valid_until(deadline), Err(Error::Expired));
    assert_eq!(original.valid_until(deadline + 1), Err(Error::Expired));
    let online_update = candidate(&verifier, 1, MAX_REVISION, 2, &[]);
    assert_eq!(online_update.valid_until(deadline), Err(Error::Expired));
    verifier.accept(original.clone()).unwrap();

    let mut renewed_keys = original.keys.clone();
    renewed_keys.expires_at = "2100-02-01T00:00:00Z".into();
    // An approval names one exact key manifest, so a renewal cannot extend an older decision.
    assert_eq!(
        verify_online_approval(
            verifier.authority,
            renewed_keys.clone(),
            original.approvals.clone(),
            sigstore()
        )
        .unwrap_err(),
        Error::Invalid("key manifest digest mismatch".into())
    );
    let approval = signed(&renewed_keys, 1, 2);
    let conflict = verify_online_approval(
        verifier.authority,
        renewed_keys.clone(),
        approval,
        sigstore(),
    )
    .unwrap();
    assert_eq!(verifier.accept(conflict).unwrap_err(), Error::Equivocation);

    renewed_keys.generation += 1;
    let approval = signed(&renewed_keys, 1, 2);
    let renewed =
        verify_online_approval(verifier.authority, renewed_keys, approval, sigstore()).unwrap();
    renewed.valid_until(deadline).unwrap();
    assert_eq!(renewed.keys.active_key, original.keys.active_key);
    verifier.accept(renewed).unwrap();
    assert_eq!(verifier.accept(original).unwrap_err(), Error::Rollback);
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
fn revisions_detect_only_conflicting_decisions_and_reject_stale_concurrent_candidates() {
    let mut verifier = verifier();
    let first = candidate(&verifier, 1, 1, 2, &[]);
    verifier.accept(first.clone()).unwrap();
    verifier.accept(first.clone()).unwrap();
    let mut conflict = signed(first.keys(), 1, 2);
    conflict.document.gateways.clear();
    conflict.signature = sign(&serde_json::to_value(&conflict.document).unwrap(), 2);
    let conflicting =
        verify_online_approval(verifier.authority, first.keys.clone(), conflict, sigstore())
            .unwrap();
    assert_eq!(
        verifier.accept(conflicting).unwrap_err(),
        Error::Equivocation
    );
    let same_generation_other_key = candidate(&verifier, 1, 2, 3, &[2]);
    assert_eq!(
        verifier.accept(same_generation_other_key).unwrap_err(),
        Error::Equivocation
    );
    verifier.accept(candidate(&verifier, 1, 2, 2, &[])).unwrap();
    assert_eq!(verifier.accept(first).unwrap_err(), Error::Rollback);
    assert_eq!(verifier.accepted().unwrap().manifest().revision, 2);
}

#[test]
fn a_hardware_policy_version_names_one_set_of_rules_and_never_decreases() {
    let mut verifier = verifier();
    let authority = verifier.authority;
    let keys = keys(1, 2, &[]);
    let approve = |revision: u64, version: u64, snp: u8| {
        let mut document = signed(&keys, revision, 2).document;
        document.hardware_policy.version = version;
        document.hardware_policy.policies[0].minimum_tcb.snp = snp;
        verify_online_approval(authority, keys.clone(), resign(document, 2), sigstore()).unwrap()
    };
    verifier.accept(approve(1, 1, 29)).unwrap();
    verifier.accept(approve(2, 2, 30)).unwrap();
    assert_eq!(
        verifier.accept(approve(3, 1, 29)).unwrap_err(),
        Error::Rollback
    );
    assert_eq!(
        verifier.accept(approve(3, 2, 31)).unwrap_err(),
        Error::Equivocation
    );
    // Renewal signs the same rules again under a new revision.
    verifier.accept(approve(3, 2, 30)).unwrap();
    // A new root-signed key manifest supersedes every number the old online key signed.
    verifier
        .accept(candidate(&verifier, 2, 1, 3, &[2]))
        .unwrap();
    assert_eq!(
        verifier
            .accepted()
            .unwrap()
            .manifest()
            .hardware_policy
            .version,
        1
    );
}

#[test]
fn root_decisions_can_omit_retired_keys_without_authorizing_them() {
    let mut verifier = verifier();
    verifier.accept(candidate(&verifier, 1, 1, 2, &[])).unwrap();
    verifier
        .accept(candidate(&verifier, 2, 1, 3, &[2]))
        .unwrap();
    let pruned = candidate(&verifier, 3, 1, 3, &[]);
    verifier.accept(pruned.clone()).unwrap();
    let mut fresh = self::verifier();
    fresh.accept(candidate(&fresh, 3, 1, 3, &[])).unwrap();
    for signer in [1, 2, 4] {
        assert_eq!(
            verify_online_approval(
                verifier.authority,
                pruned.keys.clone(),
                signed(pruned.keys(), 2, signer),
                sigstore()
            )
            .unwrap_err(),
            Error::InactiveKey
        );
    }
    // The root can also rotate without carrying earlier public keys forward.
    verifier.accept(candidate(&verifier, 4, 1, 4, &[])).unwrap();
}

#[test]
fn signatures_are_bound_to_active_key_payload_purpose_and_delegation() {
    let keys = keys(2, 3, &[2]);
    let valid = signed(&keys, 1, 3);
    assert!(verify_online_approval([0; 32], keys.clone(), valid.clone(), sigstore()).is_ok());
    for seed in [1, 2, 4] {
        assert_eq!(
            verify_online_approval([0; 32], keys.clone(), signed(&keys, 1, seed), sigstore())
                .unwrap_err(),
            Error::InactiveKey
        );
    }
    let mut invalid_signature = valid.clone();
    invalid_signature.signature.signature =
        sign(&serde_json::to_value(&valid.document).unwrap(), 4).signature;
    assert_eq!(
        verify_online_approval([0; 32], keys.clone(), invalid_signature, sigstore()).unwrap_err(),
        Error::Signature
    );
    for mutation in [
        "revision",
        "hardware",
        "delegation",
        "sigstore",
        "purpose",
        "gateway",
    ] {
        let mut tampered = valid.clone();
        match mutation {
            "revision" => tampered.document.revision += 1,
            "hardware" => {
                tampered.document.hardware_policy.policies[0]
                    .minimum_tcb
                    .snp -= 1;
            }
            "delegation" => tampered.document.key_manifest_sha256 = "4".repeat(64),
            "sigstore" => tampered.document.sigstore_sha256 = "4".repeat(64),
            "purpose" => tampered.document.schema = KEY_MANIFEST_SCHEMA.into(),
            _ => tampered.document.gateways.clear(),
        }
        assert!(
            verify_online_approval([0; 32], keys.clone(), tampered, sigstore()).is_err(),
            "{mutation}"
        );
    }
    let mut wrong_purpose = valid.clone();
    wrong_purpose.signature.signature = URL_SAFE_NO_PAD.encode(
        key(3)
            .1
            .sign(&canonical_payload(&serde_json::to_value(&valid.document).unwrap()).unwrap())
            .unwrap(),
    );
    assert_eq!(
        verify_online_approval([0; 32], keys.clone(), wrong_purpose, sigstore()).unwrap_err(),
        Error::Signature
    );
    // A validly signed approval selects only the Sigstore files it names.
    let mut other_sigstore = valid.document;
    other_sigstore.sigstore_sha256 = "5".repeat(64);
    assert_eq!(
        verify_online_approval([0; 32], keys, resign(other_sigstore, 3), sigstore()).unwrap_err(),
        Error::Invalid("Sigstore files digest mismatch".into())
    );
}

#[test]
fn manifests_reject_ambiguous_ids_keys_versions_and_counters() {
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
        assert!(
            verify_online_approval(
                [0; 32],
                keys.clone(),
                signed(&keys, revision, 2),
                sigstore()
            )
            .is_err()
        );
    }
    for sequences in [[1, 1], [2, 1]] {
        let mut gateways = signed(&keys, 1, 2).document;
        gateways.gateways = sequences
            .iter()
            .map(|sequence| {
                let mut release = crate::tests::release_fixture();
                release.document.sequence = *sequence;
                release
            })
            .collect();
        let mut catalogs = signed(&keys, 1, 2).document;
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
                verify_online_approval([0; 32], keys.clone(), resign(invalid, 2), sigstore())
                    .unwrap_err(),
                Error::Invalid("approved releases must be ordered by unique sequence".into())
            );
        }
    }
}

#[test]
fn root_inclusion_is_mandatory_and_failure_never_advances_state() {
    let mut verifier = verifier();
    verifier.accept(candidate(&verifier, 1, 1, 2, &[])).unwrap();
    let keys = SignedKeyManifest {
        signature: sign(&serde_json::to_value(keys(2, 3, &[2])).unwrap(), 1),
        document: keys(2, 3, &[2]),
        inclusion: json!({}),
    };
    let error = verifier
        .observe_keys(
            &serde_json::to_vec(&keys).unwrap(),
            sigstore().trusted_root(),
            1_789_900_000_000,
        )
        .unwrap_err();
    assert!(matches!(error, Error::Transparency(_)));
    assert_eq!(verifier.accepted().unwrap().keys().generation, 1);
}

#[test]
fn strict_boundary_rejects_unknown_duplicate_trailing_and_oversized_inputs() {
    let verifier = verifier();
    let keys = SignedKeyManifest {
        signature: sign(&serde_json::to_value(keys(1, 2, &[])).unwrap(), 1),
        document: keys(1, 2, &[]),
        inclusion: json!({}),
    };
    let valid = serde_json::to_string(&keys).unwrap();
    let trust = sigstore();
    for input in [
        format!("{valid}{{}}"),
        valid.replacen("\"generation\":1", "\"generation\":1,\"generation\":2", 1),
        valid.replacen("\"generation\":1", "\"generation\":1,\"extra\":true", 1),
    ] {
        assert!(matches!(
            verifier.observe_keys(input.as_bytes(), trust.trusted_root(), 0),
            Err(Error::Invalid(_))
        ));
    }
    assert_eq!(
        verifier
            .observe_keys(&vec![b' '; MAX_INPUT_BYTES + 1], trust.trusted_root(), 0)
            .unwrap_err(),
        Error::TooLarge
    );
    assert!(verifier.accepted().is_none());
}

#[test]
fn a_candidate_from_another_root_cannot_be_installed() {
    let mut verifier = verifier();
    let other = ApprovalVerifier::new(Environment::Production, root(5)).unwrap();
    assert_eq!(
        verifier
            .accept(candidate(&other, 1, 1, 2, &[]))
            .unwrap_err(),
        Error::Authority
    );
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
            { "name": "catalog.runtime.json", "digest": { "sha256": &catalog.document.artifacts.runtime.sha256 } },
            { "name": "catalog.public.json", "digest": { "sha256": &catalog.document.artifacts.public.sha256 } }
        ]
    });
    let now = 1_789_900_000_000;
    for (environment, allowed) in [
        (Environment::Staging, true),
        (Environment::Production, false),
    ] {
        let mut keys = keys(1, 2, &[]);
        keys.environment = environment;
        let approvals =
            verify_online_approval([0; 32], keys.clone(), signed(&keys, 1, 2), sigstore()).unwrap();
        let gateway = approvals.verify_gateway(&gateway, now);
        let catalog = approvals.verify_catalog(&catalog, now);
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
    let verifier = verifier();
    let mut manifest = keys(1, 2, &[]);
    manifest.environment = Environment::Staging;
    assert_eq!(
        validate_keys(&manifest, verifier.environment, &verifier.root).unwrap_err(),
        Error::Authority
    );
    let mut signed = signed(&manifest, 1, 2);
    signed.document.environment = Environment::Production;
    signed.signature = sign(&serde_json::to_value(&signed.document).unwrap(), 2);
    assert_eq!(
        verify_online_approval(verifier.authority, manifest, signed, sigstore()).unwrap_err(),
        Error::Authority
    );
    let mut staging = ApprovalVerifier::new(Environment::Staging, root(1)).unwrap();
    assert_eq!(
        staging
            .accept(candidate(&verifier, 1, 1, 2, &[]))
            .unwrap_err(),
        Error::Authority
    );
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
    let keys = verifier.verify_key_manifest(bytes, now).unwrap();
    assert_eq!(
        keys.active_key.key_id,
        "staging-stogas-online-2026-10-10-01"
    );
    assert_eq!(keys.generation, 1);
    assert!(keys.retired_keys.is_empty());
    let mut changed = value;
    changed["document"]["generation"] = json!(2);
    assert!(
        verifier
            .verify_key_manifest(&serde_json::to_vec(&changed).unwrap(), now)
            .is_err()
    );
    assert!(
        crate::evidence::Verifier::stogas(Environment::Production)
            .unwrap()
            .verify_key_manifest(bytes, now)
            .is_err()
    );
}

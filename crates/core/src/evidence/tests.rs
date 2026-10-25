use super::*;

/// Attach the signature and log entry that the fixture generator published for one evidence
/// document.
#[cfg(feature = "staging")]
pub(super) fn logged_evidence(document: &Value) -> Value {
    let fixtures: Value = serde_json::from_str(include_str!(
        "../../../../tests/fixtures/evidence-proofs-v1.json"
    ))
    .unwrap();
    let id = payload_sha256(document).unwrap();
    let proof = &fixtures["proofs"][&id];
    assert!(proof.is_object(), "missing logged evidence fixture {id}");
    serde_json::json!({
        "document": document,
        "signature": proof["signature"],
        "inclusion": proof["inclusion"]
    })
}

#[test]
fn strict_delivery_boundary_rejects_unknown_duplicate_and_oversized_inputs() {
    assert!(matches!(
        parse_json(&vec![b' '; crate::MAX_INPUT_BYTES + 1]),
        Err(Error::TooLarge)
    ));
    for bytes in [
        br#"{"document":{},"document":{}}"#.as_slice(),
        b"{}{}",
        b"null trailing",
    ] {
        assert!(parse_json(bytes).is_err());
    }
}

#[cfg(feature = "staging")]
mod staging {
    use super::*;
    use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
    use serde_json::json;

    fn encode(evidence: &Value) -> Vec<u8> {
        serde_json::to_vec(evidence).unwrap()
    }

    fn fixture() -> (Verifier, Value, i64) {
        let session: Value = serde_json::from_str(include_str!(
            "../../../../tests/fixtures/hardware-session-v1.json"
        ))
        .unwrap();
        let now = session["verified_at_ms"].as_i64().unwrap();
        (
            Verifier::new(
                Environment::Staging,
                serde_json::from_value(session["root"].clone()).unwrap(),
            )
            .unwrap(),
            session["evidence"].clone(),
            now,
        )
    }

    fn revised(evidence: &Value, revision: u64, edit: impl FnOnce(&mut Value)) -> Value {
        let mut document = evidence["document"].clone();
        document["revision"] = json!(revision);
        edit(&mut document);
        logged_evidence(&document)
    }

    fn gateway_id(evidence: &Value) -> String {
        payload_sha256(&evidence["document"]["gateways"][0]["document"]).unwrap()
    }

    #[test]
    fn complete_logged_evidence_installs_and_revisions_reuse_unchanged_releases() {
        let (mut verifier, evidence, now) = fixture();
        let mut checks = Vec::new();
        let first = verifier
            .refresh_observed(&encode(&evidence), now, |check| {
                checks.push((check.step, check.cached));
            })
            .unwrap();
        assert_eq!(checks.last().unwrap().0, VerificationStep::Accepted);
        assert!(checks.iter().all(|check| !check.1));
        for step in [
            VerificationStep::Sigstore,
            VerificationStep::KeyManifest,
            VerificationStep::Signature,
            VerificationStep::GatewayRelease,
            VerificationStep::CatalogRelease,
            VerificationStep::HardwarePolicy,
            VerificationStep::VendorCollateral,
        ] {
            assert!(checks.iter().any(|check| check.0 == step));
        }
        let summary = first.summary();
        assert_eq!(
            summary["evidence_sha256"],
            payload_sha256(&evidence["document"]).unwrap()
        );
        for field in ["document", "signature", "inclusion"] {
            assert_eq!(summary[field], evidence[field]);
        }

        // The next revision lists the same releases and Sigstore files; their checks are not
        // repeated.
        let next = revised(&evidence, 2, |_| {});
        checks.clear();
        let second = verifier
            .refresh_observed(&encode(&next), now + 1000, |check| {
                checks.push((check.step, check.cached));
            })
            .unwrap();
        assert!(checks.contains(&(VerificationStep::Sigstore, true)));
        let releases = checks
            .iter()
            .filter(|check| {
                matches!(
                    check.0,
                    VerificationStep::GatewayRelease | VerificationStep::CatalogRelease
                )
            })
            .collect::<Vec<_>>();
        assert_eq!(releases.len(), 3);
        assert!(releases.iter().all(|check| check.1));
        let id = gateway_id(&evidence);
        assert!(Arc::ptr_eq(
            &first.gateways[&id].value,
            &second.gateways[&id].value
        ));
        assert!(second.compatible_catalog(&id).is_some());
        assert!(second.compatible_catalog(&"0".repeat(64)).is_none());

        let mut altered = next;
        altered["document"]["hardware_policies"][0]["minimum_tcb"]["snp"] = json!(0);
        checks.clear();
        assert!(
            verifier
                .refresh_observed(&encode(&altered), now + 2000, |check| {
                    checks.push((check.step, check.cached));
                })
                .is_err()
        );
        assert!(
            !checks
                .iter()
                .any(|check| check.0 == VerificationStep::Accepted)
        );
        assert!(Arc::ptr_eq(verifier.current().unwrap(), &second));
    }

    #[test]
    fn repeated_delivery_keeps_its_snapshot_until_its_deadline_or_a_new_root_decision() {
        let (mut verifier, evidence, now) = fixture();
        let bytes = encode(&evidence);
        let mut full = Vec::new();
        let first = verifier
            .refresh_observed(&bytes, now, |check| {
                full.push((check.step, check.reference.map(str::to_owned)));
            })
            .unwrap();
        // The same bytes return the same snapshot, so bound sessions need no new appraisal, and
        // every check of the complete verification is reported as reused.
        let mut repeated = Vec::new();
        let again = verifier
            .refresh_observed(&bytes, now + 60_000, |check| {
                repeated.push((check.step, check.reference.map(str::to_owned), check.cached));
            })
            .unwrap();
        assert!(Arc::ptr_eq(&first, &again));
        assert_eq!(
            repeated,
            full.iter()
                .map(|(step, reference)| (*step, reference.clone(), true))
                .collect::<Vec<_>>()
        );

        // A clock behind the verification repeats it completely.
        let earlier = verifier.refresh(&bytes, now - 1).unwrap();
        assert!(!Arc::ptr_eq(&first, &earlier));
        assert!(Arc::ptr_eq(
            &earlier,
            &verifier.refresh(&bytes, now).unwrap()
        ));

        // Other bytes for the same document verify completely.
        let reformatted = serde_json::to_vec_pretty(&evidence).unwrap();
        let other = verifier.refresh(&reformatted, now).unwrap();
        assert!(!Arc::ptr_eq(&earlier, &other));
        assert_eq!(other.evidence_sha256(), first.evidence_sha256());

        // A repeat fails at the root deadline exactly as a complete verification does.
        let deadline = first.evidence().valid_until(now).unwrap();
        for bytes in [&reformatted, &bytes] {
            assert!(matches!(
                verifier.refresh(bytes, deadline),
                Err(Error::Authority(authority::Error::Expired))
            ));
        }
        assert!(Arc::ptr_eq(verifier.current().unwrap(), &other));
        assert!(Arc::ptr_eq(
            &other,
            &verifier.refresh(&reformatted, deadline - 1).unwrap()
        ));

        // A root decision learned since, even from a delivery that fails, rejects the repeat.
        let rotated: Value = serde_json::from_str(include_str!(
            "../../../../tests/fixtures/hardware-session-rotated-v1.json"
        ))
        .unwrap();
        let mut partial = rotated;
        partial["document"]["revision"] = json!(99);
        assert!(verifier.refresh(&encode(&partial), now).is_err());
        assert!(matches!(
            verifier.refresh(&reformatted, now),
            Err(Error::Authority(authority::Error::Rollback))
        ));
    }

    #[cfg(feature = "snp")]
    #[test]
    fn vendor_revocation_learned_since_a_delivery_repeats_its_complete_verification() {
        let (mut verifier, evidence, now) = fixture();
        let bytes = encode(&evidence);
        let first = verifier.refresh(&bytes, now).unwrap();
        assert!(Arc::ptr_eq(&first, &verifier.refresh(&bytes, now).unwrap()));
        // Another product's genuine AMD root is a new revocation issuer, learned even though
        // the document that carries it is incomplete.
        let pem = std::str::from_utf8(sev::certs::snp::builtin::genoa::ARK).unwrap();
        let der = base64::engine::general_purpose::STANDARD
            .decode(
                pem.lines()
                    .filter(|line| !line.starts_with("-----"))
                    .collect::<String>(),
            )
            .unwrap();
        let mut document = evidence["document"].clone();
        document["vendor_collateral"]
            .as_array_mut()
            .unwrap()
            .push(json!({
                "ca_product_name": "Genoa",
                "collateral_type": "ark",
                "der_base64url": URL_SAFE_NO_PAD.encode(der)
            }));
        let learned = verifier.revocations.changes();
        assert!(verifier.check_unsigned(&encode(&document), now).is_err());
        assert_eq!(verifier.revocations.changes(), learned + 1);
        let second = verifier.refresh(&bytes, now).unwrap();
        assert!(!Arc::ptr_eq(&first, &second));
        assert!(Arc::ptr_eq(
            &second,
            &verifier.refresh(&bytes, now).unwrap()
        ));
        // Observing the same root again changes nothing.
        assert!(verifier.check_unsigned(&encode(&document), now).is_err());
        assert_eq!(verifier.revocations.changes(), learned + 1);
    }

    #[test]
    fn generated_evidence_verifies_and_synthetic_boots_never_gain_hardware_trust() {
        let (mut verifier, evidence, now) = fixture();
        let snapshot = verifier.refresh(&encode(&evidence), now).unwrap();
        assert_eq!(snapshot.gateways.len(), 1);
        assert_eq!(snapshot.catalogs.len(), 2);

        let synthetic: Value =
            serde_json::from_str(include_str!("../../../../tests/fixtures/node-boot-v1.json"))
                .unwrap();
        let mut record = synthetic["record"].clone();
        record["gateway_release_id"] = json!(gateway_id(&evidence));
        record["report_data"]["environment"] = json!("staging");
        let challenge: [u8; 32] = hex::decode(
            record["report_data"]["registration_challenge"]
                .as_str()
                .unwrap(),
        )
        .unwrap()
        .try_into()
        .unwrap();
        let document = crate::canonical_json(&record).unwrap();
        assert!(matches!(
            snapshot.verify_registration(document.as_bytes(), &challenge, now),
            Err(Error::Attestation(_) | Error::MissingCollateral)
        ));
        assert!(
            snapshot
                .verify_logged_boot(document.as_bytes(), b"{}", now)
                .is_err()
        );
        let certificate: Value = serde_json::from_str(include_str!(
            "../../../../tests/fixtures/native-certificate-v1.json"
        ))
        .unwrap();
        let der = URL_SAFE_NO_PAD
            .decode(certificate["certificate"].as_str().unwrap())
            .unwrap();
        assert!(
            snapshot
                .verify_native_certificate(&der, challenge, now)
                .is_err()
        );
    }

    #[test]
    fn altered_candidate_never_replaces_an_accepted_snapshot_and_withdrawal_is_signed() {
        let (mut verifier, evidence, now) = fixture();
        let first = verifier.refresh(&encode(&evidence), now).unwrap();
        for pointer in [
            "/document/gateways",
            "/document/catalogs",
            "/document/gateways/0/provenance",
            "/document/keys/inclusion",
            "/signature",
            "/inclusion",
        ] {
            let mut bad = evidence.clone();
            *bad.pointer_mut(pointer).unwrap() = json!([]);
            assert!(
                verifier.refresh(&encode(&bad), now).is_err(),
                "accepted {pointer}"
            );
            assert!(Arc::ptr_eq(verifier.current().unwrap(), &first));
        }
        let withdrawal = revised(&evidence, 2, |document| document["gateways"] = json!([]));
        let withdrawn = verifier.refresh(&encode(&withdrawal), now).unwrap();
        assert!(withdrawn.gateways.is_empty());
        assert!(matches!(
            verifier.refresh(&encode(&evidence), now),
            Err(Error::Authority(authority::Error::Rollback))
        ));
        // The request's retained immutable context remains available after a live withdrawal.
        assert_eq!(first.gateways.len(), 1);
    }

    #[test]
    fn unsigned_candidates_are_checked_like_deliveries_but_never_installed() {
        let (mut verifier, evidence, now) = fixture();
        let unsigned = verifier
            .check_unsigned(&encode(&evidence["document"]), now)
            .unwrap();
        assert!(unsigned.summary()["signature"].is_null());
        assert!(verifier.current().is_none());
        let current = verifier.refresh(&encode(&evidence), now).unwrap();
        // Publishers check each candidate against the current revision before signing it.
        let mut conflicting = evidence["document"].clone();
        conflicting["gateways"] = json!([]);
        assert!(matches!(
            verifier.check_unsigned(&encode(&conflicting), now),
            Err(Error::Authority(authority::Error::Equivocation))
        ));
        conflicting["revision"] = json!(2);
        let next = verifier.check_unsigned(&encode(&conflicting), now).unwrap();
        assert!(next.gateways.is_empty());
        assert!(Arc::ptr_eq(verifier.current().unwrap(), &current));
    }

    #[test]
    fn edits_and_unsigned_extensions_do_not_grant_authority() {
        let (mut verifier, evidence, now) = fixture();
        for pointer in [
            "/document/gateways/0/document/sequence",
            "/document/hardware_policies/0/cpuid_family",
            "/document/revision",
        ] {
            let mut bad = evidence.clone();
            *bad.pointer_mut(pointer).unwrap() = json!(99);
            assert!(verifier.refresh(&encode(&bad), now).is_err());
        }
        for (field, value) in [
            ("gateways", json!([])),
            ("nodes", json!([])),
            ("sequence", json!(99)),
            ("node_id", json!("attacker-controlled")),
        ] {
            let mut bad = evidence.clone();
            bad[field] = value;
            assert!(
                verifier.refresh(&encode(&bad), now).is_err(),
                "accepted unsigned {field}"
            );
        }
        assert!(verifier.current().is_none());
    }

    #[test]
    fn logged_root_retirement_survives_partial_delivery_and_rotation_preserves_release_identity() {
        let (mut verifier, evidence, now) = fixture();
        let first = verifier.refresh(&encode(&evidence), now).unwrap();
        let next: Value = serde_json::from_str(include_str!(
            "../../../../tests/fixtures/hardware-session-rotated-v1.json"
        ))
        .unwrap();
        let mut partial = next.clone();
        partial["document"]["revision"] = json!(99);
        assert!(verifier.refresh(&encode(&partial), now).is_err());
        assert!(Arc::ptr_eq(verifier.current().unwrap(), &first));
        assert!(matches!(
            first.require_current_keys(),
            Err(Error::Authority(authority::Error::Rollback))
        ));
        assert!(matches!(
            verifier.refresh(&encode(&evidence), now),
            Err(Error::Authority(authority::Error::Rollback))
        ));
        let second = verifier.refresh(&encode(&next), now).unwrap();
        second.require_current_keys().unwrap();
        assert!(first.gateways.keys().eq(second.gateways.keys()));
        assert!(first.catalogs.keys().eq(second.catalogs.keys()));
        let id = gateway_id(&next);
        assert!(second.compatible_catalog(&id).is_some());
        assert_eq!(
            first.gateway(&id).unwrap().measurement,
            second.gateway(&id).unwrap().measurement
        );
        // Already-running requests retain their original evidence; new work uses the current set.
        assert_eq!(
            first.evidence().keys().active_key.key_id,
            "stogas-fixture-online-20260920"
        );
    }

    #[test]
    fn catalog_selection_needs_each_release_to_meet_the_minimum_of_the_other() {
        let (mut verifier, evidence, now) = fixture();
        let snapshot = verifier.refresh(&encode(&evidence), now).unwrap();
        drop(verifier);
        let mut snapshot = Arc::try_unwrap(snapshot).unwrap();
        let id = gateway_id(&evidence);
        let sequences: Vec<u64> = snapshot
            .catalogs
            .values()
            .map(|entry| entry.value.sequence)
            .collect();
        let (oldest, newest) = (
            *sequences.iter().min().unwrap(),
            *sequences.iter().max().unwrap(),
        );
        assert!(oldest < newest);
        let selected = |snapshot: &Snapshot| {
            snapshot
                .compatible_catalog(&id)
                .map(|(_, catalog)| catalog.sequence)
        };
        let set_minimum = |snapshot: &mut Snapshot, minimum| {
            Arc::make_mut(&mut snapshot.gateways.get_mut(&id).unwrap().value)
                .minimum_catalog_sequence = minimum;
        };
        assert_eq!(selected(&snapshot), Some(newest));
        set_minimum(&mut snapshot, newest + 1);
        assert_eq!(selected(&snapshot), None);
        // A gateway that reads only the newest catalog gets no older one when the newest needs a
        // newer gateway.
        set_minimum(&mut snapshot, newest);
        let gateway_sequence = snapshot.gateway(&id).unwrap().sequence;
        for entry in snapshot.catalogs.values_mut() {
            if entry.value.sequence == newest {
                Arc::make_mut(&mut entry.value).minimum_gateway_sequence = gateway_sequence + 1;
            }
        }
        assert_eq!(selected(&snapshot), None);
        set_minimum(&mut snapshot, oldest);
        assert_eq!(selected(&snapshot), Some(oldest));
    }

    #[cfg(feature = "snp")]
    fn registered_report() -> Vec<u8> {
        let registration: Value = serde_json::from_str(include_str!(
            "../../../../tests/fixtures/hardware-registration-v1.json"
        ))
        .unwrap();
        URL_SAFE_NO_PAD
            .decode(registration["boot"]["report"].as_str().unwrap())
            .unwrap()
    }

    #[cfg(feature = "snp")]
    #[test]
    fn expired_collateral_remains_a_local_platform_failure_not_a_withdrawal() {
        let (mut verifier, evidence, now) = fixture();
        let report = registered_report();
        let chip = hex::encode(&report[0x1a0..0x1e0]);
        let tcb = hex::encode(&report[0x180..0x188]);
        let snapshot = verifier.refresh(&encode(&evidence), now).unwrap();
        let expiry = snapshot
            .collateral_validity(&chip, &tcb, now)
            .unwrap()
            .not_after_unix_ms;
        assert!(matches!(
            snapshot.collateral_validity(&chip, &tcb, expiry),
            Err(Error::CollateralExpired)
        ));
        assert!(
            snapshot
                .collateral_summary(now)
                .iter()
                .all(|row| row["error"].is_null()
                    && row["not_before_unix_ms"].as_i64().unwrap() <= now
                    && row["not_after_unix_ms"].as_i64().unwrap() > now)
        );
        // Expired vendor collateral blocks only that platform, never the signed evidence.
        let refreshed = verifier.refresh(&encode(&evidence), expiry).unwrap();
        assert!(matches!(
            refreshed.collateral_validity(&chip, &tcb, expiry),
            Err(Error::CollateralExpired)
        ));
        assert!(
            refreshed
                .collateral_summary(expiry)
                .iter()
                .any(|row| row["error"] == "expired_collateral"
                    && row.get("not_after_unix_ms").is_none())
        );
        assert_eq!(refreshed.gateways.len(), 1);
        // An expired CRL does not make the chip certificate itself due for renewal.
        assert!(
            refreshed
                .vcek_validity(&chip, &tcb)
                .unwrap()
                .not_after_unix_ms
                > expiry
        );
    }

    #[cfg(feature = "snp")]
    #[test]
    fn genuine_snp_report_requires_current_evidence_binding_and_complete_hardware_appraisal() {
        let (mut verifier, evidence, now) = fixture();
        let report = registered_report();
        let expected: [u8; 64] = report[0x50..0x90].try_into().unwrap();
        let release_id = gateway_id(&evidence);
        let snapshot = verifier.refresh(&encode(&evidence), now).unwrap();
        // Historical report appraisal, not a claim that this fixture establishes a fresh session.
        let session = snapshot
            .verify_snp_report(&report, &expected, &release_id, now)
            .unwrap();
        assert_eq!(session.report_id().as_slice(), &report[0x140..0x160]);
        assert_eq!(
            session.node_id(),
            crate::attestation::snp_node_id(session.report_id())
        );
        assert_eq!(session.chip_id(), hex::encode(&report[0x1a0..0x1e0]));
        assert_eq!(session.reported_tcb(), hex::encode(&report[0x180..0x188]));
        assert!(matches!(
            snapshot.verify_snp_report(
                &report,
                &expected,
                &release_id,
                session.validity().not_after_unix_ms
            ),
            Err(Error::CollateralExpired)
        ));
        assert!(matches!(
            snapshot.verify_snp_report(&report, &expected, &"ff".repeat(32), now),
            Err(Error::Authority(authority::Error::NotApproved("gateway")))
        ));
        let mut wrong_binding = expected;
        wrong_binding[0] ^= 1;
        assert!(
            snapshot
                .verify_snp_report(&report, &wrong_binding, &release_id, now)
                .is_err()
        );
        for vmpl in [1_u32, 2, 3, u32::MAX] {
            let mut altered = report.clone();
            altered[0x30..0x34].copy_from_slice(&vmpl.to_le_bytes());
            assert!(
                snapshot
                    .verify_snp_report(&altered, &expected, &release_id, now)
                    .is_err(),
                "accepted VMPL {vmpl}"
            );
        }
        // Measurement, launch flags, instance ID, chip/TCB, mitigations, reserved bytes and
        // signature must all remain authenticated, including fields outside report_data.
        for offset in [
            0, 8, 0x10, 0x20, 0x34, 0x38, 0x40, 0x48, 0x4c, 0x50, 0x90, 0xc0, 0xe0, 0x110, 0x140,
            0x160, 0x180, 0x188, 0x1a0, 0x1e0, 0x1f0, 0x1f8, 0x200, 0x208, 0x2a0, 0x2d0, 0x2e8,
            0x318, 0x330,
        ] {
            let mut altered = report.clone();
            altered[offset] ^= 1;
            assert!(
                snapshot
                    .verify_snp_report(&altered, &expected, &release_id, now)
                    .is_err(),
                "accepted report mutation at {offset:x}"
            );
        }
        for size in [0, 0x140, 0x49f, 0x4a1] {
            let mut altered = report.clone();
            altered.resize(size, 0);
            assert!(
                snapshot
                    .verify_snp_report(&altered, &expected, &release_id, now)
                    .is_err()
            );
        }
        let withdrawal = revised(&evidence, 2, |document| document["gateways"] = json!([]));
        let withdrawn = verifier.refresh(&encode(&withdrawal), now).unwrap();
        assert!(matches!(
            withdrawn.verify_snp_report(&report, &expected, &release_id, now),
            Err(Error::Authority(authority::Error::NotApproved("gateway")))
        ));
    }
}

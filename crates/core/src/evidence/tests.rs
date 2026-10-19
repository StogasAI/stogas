use super::*;

/// Attach the logged signature of an approval manifest that a fixture variant already published.
#[cfg(feature = "staging")]
pub(super) fn logged_approval(document: &Value) -> Value {
    let fixtures: Value = serde_json::from_str(include_str!(
        "../../../../tests/fixtures/logged-approval-variants.json"
    ))
    .unwrap();
    let id = payload_sha256(document).unwrap();
    let logged = &fixtures["approvals"][&id];
    assert!(logged.is_object(), "missing logged approval fixture {id}");
    serde_json::json!({
        "document": document,
        "signature": logged["signature"],
        "inclusion": logged["inclusion"]
    })
}

#[test]
fn strict_delivery_boundary_rejects_unknown_duplicate_and_oversized_inputs() {
    assert!(matches!(
        parse_json(&vec![b' '; crate::MAX_INPUT_BYTES + 1]),
        Err(Error::TooLarge)
    ));
    for bytes in [
        br#"{"body":{},"body":{}}"#.as_slice(),
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

    fn encode(body: &Value) -> Vec<u8> {
        serde_json::to_vec(&json!({"schema": crate::BUNDLE_ENVELOPE_SCHEMA,
            "body":body, "body_sha256":payload_sha256(body).unwrap()}))
        .unwrap()
    }

    fn fixture() -> (Verifier, Value, i64) {
        let session: Value = serde_json::from_str(include_str!(
            "../../../../tests/fixtures/hardware-session-v1.json"
        ))
        .unwrap();
        let variants: Value = serde_json::from_str(include_str!(
            "../../../../tests/fixtures/logged-approval-variants.json"
        ))
        .unwrap();
        let now = session["verified_at_ms"]
            .as_i64()
            .unwrap()
            .max(variants["verified_at_ms"].as_i64().unwrap());
        (
            Verifier::new(
                Environment::Staging,
                serde_json::from_value(session["root"].clone()).unwrap(),
            )
            .unwrap(),
            session["bundle"]["body"].clone(),
            now,
        )
    }

    fn revised(body: &Value, revision: u64, edit: impl FnOnce(&mut Value)) -> Value {
        let mut body = body.clone();
        let mut document = body["approvals"]["document"].clone();
        document["revision"] = json!(revision);
        edit(&mut document);
        body["approvals"] = logged_approval(&document);
        body
    }

    fn gateway_id(body: &Value) -> String {
        payload_sha256(&body["approvals"]["document"]["gateways"][0]["document"]).unwrap()
    }

    #[test]
    fn complete_logged_bundle_installs_and_renewals_reuse_unchanged_releases() {
        let (mut verifier, body, now) = fixture();
        let mut checks = Vec::new();
        let first = verifier
            .refresh_observed(&encode(&body), now, |check| {
                checks.push((check.step, check.cached));
            })
            .unwrap();
        assert_eq!(checks.last().unwrap().0, VerificationStep::Accepted);
        assert!(checks.iter().all(|check| !check.1));
        for step in [
            VerificationStep::Sigstore,
            VerificationStep::KeyManifest,
            VerificationStep::ApprovalManifest,
            VerificationStep::GatewayRelease,
            VerificationStep::CatalogRelease,
            VerificationStep::HardwarePolicy,
        ] {
            assert!(checks.iter().any(|check| check.0 == step));
        }
        let summary = first.summary();
        assert_eq!(summary["keys"], body["keys"]);
        assert_eq!(summary["approvals"], body["approvals"]);
        assert_eq!(summary["hardware_policy"]["policy_count"], 1);

        // A renewal signs the same releases and Sigstore files again; their checks are not
        // repeated.
        let renewal = revised(&body, 2, |_| {});
        checks.clear();
        let second = verifier
            .refresh_observed(&encode(&renewal), now + 1000, |check| {
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
        let id = gateway_id(&body);
        assert!(Arc::ptr_eq(
            &first.gateways[&id].value,
            &second.gateways[&id].value
        ));
        assert!(second.compatible_catalog(&id).is_some());
        assert!(second.compatible_catalog(&"0".repeat(64)).is_none());

        let mut altered = renewal;
        altered["approvals"]["document"]["hardware_policy"]["schema"] = json!("altered");
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
    fn typescript_current_bundle_verifies_and_synthetic_boots_never_gain_hardware_trust() {
        let (mut verifier, body, now) = fixture();
        let snapshot = verifier.refresh(&encode(&body), now).unwrap();
        assert_eq!(snapshot.gateways.len(), 1);
        assert_eq!(snapshot.catalogs.len(), 2);

        let synthetic: Value =
            serde_json::from_str(include_str!("../../../../tests/fixtures/node-boot-v1.json"))
                .unwrap();
        let mut record = synthetic["record"].clone();
        record["gateway_release_id"] = json!(gateway_id(&body));
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
        let (mut verifier, body, now) = fixture();
        let first = verifier.refresh(&encode(&body), now).unwrap();
        for pointer in [
            "/approvals/document/gateways",
            "/approvals/document/catalogs",
            "/approvals/document/gateways/0/provenance",
            "/approvals/signature",
            "/approvals/inclusion",
            "/keys/inclusion",
        ] {
            let mut bad = body.clone();
            *bad.pointer_mut(pointer).unwrap() = json!([]);
            assert!(
                verifier.refresh(&encode(&bad), now).is_err(),
                "accepted {pointer}"
            );
            assert!(Arc::ptr_eq(verifier.current().unwrap(), &first));
        }
        let withdrawal = revised(&body, 2, |document| document["gateways"] = json!([]));
        let withdrawn = verifier.refresh(&encode(&withdrawal), now).unwrap();
        assert!(withdrawn.gateways.is_empty());
        assert!(matches!(
            verifier.refresh(&encode(&body), now),
            Err(Error::Approval(approvals::Error::Rollback))
        ));
        // The request's retained immutable context remains available after a live withdrawal.
        assert_eq!(first.gateways.len(), 1);
    }

    #[test]
    fn delivery_checksum_and_extensions_do_not_grant_authority() {
        let (mut verifier, body, now) = fixture();
        for pointer in [
            "/approvals/document/gateways/0/document/sequence",
            "/approvals/document/hardware_policy/policies/0/cpuid_family",
            "/approvals/document/revision",
        ] {
            let mut bad = body.clone();
            *bad.pointer_mut(pointer).unwrap() = json!(99);
            assert!(verifier.refresh(&encode(&bad), now).is_err());
        }
        for (field, value) in [
            ("gateways", json!([])),
            ("nodes", json!([])),
            ("sequence", json!(99)),
            ("node_id", json!("attacker-controlled")),
        ] {
            let mut bad = body.clone();
            bad[field] = value;
            assert!(
                verifier.refresh(&encode(&bad), now).is_err(),
                "accepted unsigned {field}"
            );
        }
        let mut envelope: Value = serde_json::from_slice(&encode(&body)).unwrap();
        envelope["body_sha256"] = json!("0".repeat(64));
        assert!(
            verifier
                .refresh(&serde_json::to_vec(&envelope).unwrap(), now)
                .is_err()
        );
        assert!(verifier.current().is_none());
    }

    #[test]
    fn logged_root_retirement_survives_partial_delivery_and_rotation_preserves_release_identity() {
        let (mut verifier, body, now) = fixture();
        let first = verifier.refresh(&encode(&body), now).unwrap();
        let rotated: Value = serde_json::from_str(include_str!(
            "../../../../tests/fixtures/hardware-session-rotated-v1.json"
        ))
        .unwrap();
        let next = rotated["body"].clone();
        let mut partial = next.clone();
        partial["approvals"]["document"]["revision"] = json!(99);
        assert!(verifier.refresh(&encode(&partial), now).is_err());
        assert!(Arc::ptr_eq(verifier.current().unwrap(), &first));
        assert!(matches!(
            first.require_current_keys(),
            Err(Error::Approval(approvals::Error::Rollback))
        ));
        assert!(matches!(
            verifier.refresh(&encode(&body), now),
            Err(Error::Approval(approvals::Error::Rollback))
        ));
        let second = verifier.refresh(&encode(&next), now).unwrap();
        second.require_current_keys().unwrap();
        assert!(first.gateways.keys().eq(second.gateways.keys()));
        assert!(first.catalogs.keys().eq(second.catalogs.keys()));
        assert_eq!(
            first.hardware_policy().sha256,
            second.hardware_policy().sha256
        );
        let id = gateway_id(&next);
        assert!(second.compatible_catalog(&id).is_some());
        assert_eq!(
            first.gateway(&id).unwrap().measurement,
            second.gateway(&id).unwrap().measurement
        );
        // Already-running requests retain their original evidence; new work uses the current set.
        assert_eq!(
            first.approvals.keys().active_key.key_id,
            "stogas-fixture-online-20260920"
        );
    }

    #[test]
    fn catalog_selection_needs_each_release_to_meet_the_minimum_of_the_other() {
        let (mut verifier, body, now) = fixture();
        let snapshot = verifier.refresh(&encode(&body), now).unwrap();
        drop(verifier);
        let mut snapshot = Arc::try_unwrap(snapshot).unwrap();
        let id = gateway_id(&body);
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
    fn expired_collateral_remains_a_local_platform_failure_not_a_manifest_withdrawal() {
        let (mut verifier, mut body, now) = fixture();
        let report = registered_report();
        let chip = hex::encode(&report[0x1a0..0x1e0]);
        let tcb = hex::encode(&report[0x180..0x188]);
        let snapshot = verifier.refresh(&encode(&body), now).unwrap();
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
        // Delivery timestamps cannot extend the vendor's signed nextUpdate, and expired
        // collateral does not reject the approved evidence itself.
        for row in body["vendor_collateral"].as_array_mut().unwrap() {
            row["fetched_at"] = json!("2099-01-01T00:00:00Z");
        }
        let refreshed = verifier.refresh(&encode(&body), expiry).unwrap();
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
    }

    #[cfg(feature = "snp")]
    #[test]
    fn genuine_snp_report_requires_current_approval_binding_and_complete_hardware_appraisal() {
        let (mut verifier, body, now) = fixture();
        let report = registered_report();
        let expected: [u8; 64] = report[0x50..0x90].try_into().unwrap();
        let release_id = gateway_id(&body);
        let snapshot = verifier.refresh(&encode(&body), now).unwrap();
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
            Err(Error::Approval(crate::approvals::Error::NotApproved(
                "gateway"
            )))
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
        let withdrawal = revised(&body, 2, |document| document["gateways"] = json!([]));
        let withdrawn = verifier.refresh(&encode(&withdrawal), now).unwrap();
        assert!(matches!(
            withdrawn.verify_snp_report(&report, &expected, &release_id, now),
            Err(Error::Approval(crate::approvals::Error::NotApproved(
                "gateway"
            )))
        ));
    }
}

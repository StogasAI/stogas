use super::*;

/// 2026-11-14, when AMD's KDS CRLs are valid and the CRLs of 2026-09-22 have expired.
const NOW: i64 = 1_794_614_400_000;
const ALWAYS: Validity = Validity {
    not_before_unix_ms: 0,
    not_after_unix_ms: i64::MAX,
};
/// AMD revoked its first Genoa ASK in 2022 and issued the current one.
const FIRST_GENOA_ASK: &[u8] = &[2, 0, 1];
const GENOA_ASK: &[u8] = &[2, 0, 2];

fn crl(path: &str) -> Vec<u8> {
    std::fs::read(format!(
        "{}/../../tests/fixtures/sev-snp/{path}",
        env!("CARGO_MANIFEST_DIR")
    ))
    .unwrap()
}

fn document(crls: &[&[u8]]) -> Value {
    let rows: Vec<_> = crls
        .iter()
        .map(|der| serde_json::json!({"collateral_type": "crl", "der_base64url": URL_SAFE_NO_PAD.encode(der)}))
        .collect();
    serde_json::json!({ "vendor_collateral": rows })
}

#[test]
fn amd_crls_advance_and_never_roll_back() {
    let state = Revocations::default();
    let older = crl("attestation-rs/genoa-2026-09-22.crl");
    let newer = crl("amd-kds/genoa.crl");
    state.observe(&document(&[&older]), NOW).unwrap();
    assert_eq!(state.changes(), 1);
    // The expired CRL still shows the revocation, and nothing else.
    assert!(matches!(
        state.validity(Product::Genoa, FIRST_GENOA_ASK, ALWAYS, NOW),
        Err(Error::Revoked)
    ));
    assert!(matches!(
        state.validity(Product::Genoa, GENOA_ASK, ALWAYS, NOW),
        Err(Error::CollateralExpired)
    ));
    state.observe(&document(&[&newer]), NOW).unwrap();
    assert_eq!(state.changes(), 2);
    assert_eq!(
        state
            .validity(Product::Genoa, GENOA_ASK, ALWAYS, NOW)
            .unwrap(),
        Validity {
            not_before_unix_ms: 1_793_082_166_000,
            not_after_unix_ms: 1_796_778_000_000,
        }
    );
    // A repeat changes nothing, and the older CRL cannot replace the newer.
    state.observe(&document(&[&newer]), NOW).unwrap();
    assert!(matches!(
        state.observe(&document(&[&older]), NOW),
        Err(Error::CrlOrder)
    ));
    assert_eq!(state.changes(), 2);
    assert!(matches!(
        state.validity(Product::Milan, &[1, 0, 1], ALWAYS, NOW),
        Err(Error::MissingCollateral)
    ));
}

#[test]
fn a_crl_that_is_not_valid_yet_or_was_changed_teaches_nothing() {
    let state = Revocations::default();
    let milan = crl("amd-kds/milan.crl");
    // KDS issued it at 1_793_082_435 seconds.
    let earliest = 1_793_082_435_000 - crate::MAX_CLOCK_SKEW_MS;
    assert!(state.observe(&document(&[&milan]), earliest - 1).is_err());
    let mut changed = milan.clone();
    *changed.last_mut().unwrap() ^= 1;
    assert!(state.observe(&document(&[&changed]), NOW).is_err());
    assert_eq!(state.changes(), 0);
    state.observe(&document(&[&milan]), earliest).unwrap();
    assert_eq!(state.changes(), 1);
}

#[test]
fn a_malformed_row_does_not_hide_an_authentic_crl() {
    let authentic = document(&[&crl("amd-kds/genoa.crl")])["vendor_collateral"][0].clone();
    let invalid = serde_json::json!({"collateral_type": "crl", "der_base64url": "bad"});
    for rows in [[invalid.clone(), authentic.clone()], [authentic, invalid]] {
        let state = Revocations::default();
        assert!(
            state
                .observe(&serde_json::json!({ "vendor_collateral": rows }), NOW)
                .is_err()
        );
        assert!(matches!(
            state.validity(Product::Genoa, FIRST_GENOA_ASK, ALWAYS, NOW),
            Err(Error::Revoked)
        ));
    }
}

/// A CRL with this number, last update and revoked serial numbers.
fn latest(number: u8, not_before: i64, revoked: &[&[u8]]) -> Latest {
    let mut digits = [0; 20];
    digits[19] = number;
    Latest {
        revocation: Revocation {
            number: digits,
            validity: Validity {
                not_before_unix_ms: not_before,
                not_after_unix_ms: not_before + 1_000,
            },
            revoked: revoked.iter().map(|serial| serial.to_vec()).collect(),
        },
        der_sha256: [number; 32],
        conflicting: false,
    }
}

#[test]
fn only_a_newer_crl_replaces_the_latest_and_a_conflict_blocks_its_product() {
    let mut state = latest(2, 10, &[]);
    // Another signature over the same contents is the same CRL.
    let mut resigned = latest(2, 10, &[]);
    resigned.der_sha256 = [9; 32];
    assert!(matches!(learn(&mut state, resigned), (false, Ok(()))));
    assert!(matches!(
        learn(&mut state, latest(1, 20, &[])),
        (false, Err(Error::CrlOrder))
    ));
    // A higher number with an earlier last update is out of order too.
    assert!(matches!(
        learn(&mut state, latest(3, 5, &[])),
        (false, Err(Error::CrlOrder))
    ));
    // The same number with other contents conflicts, which changes the state once.
    assert!(matches!(
        learn(&mut state, latest(2, 10, &[GENOA_ASK])),
        (true, Err(Error::CrlOrder))
    ));
    assert!(matches!(
        learn(&mut state, latest(2, 10, &[GENOA_ASK])),
        (false, Err(Error::CrlOrder))
    ));
    assert!(matches!(
        learn(&mut state, latest(2, 10, &[])),
        (false, Err(Error::CrlOrder))
    ));
    let revocations = Revocations::default();
    revocations.lock().unwrap().insert(
        Product::Genoa,
        Latest {
            conflicting: true,
            ..latest(2, 10, &[])
        },
    );
    assert!(matches!(
        revocations.validity(Product::Genoa, FIRST_GENOA_ASK, ALWAYS, 10),
        Err(Error::CrlOrder)
    ));
    // A newer CRL settles the conflict, and numbers compare across all 20 bytes.
    assert!(matches!(
        learn(&mut state, latest(3, 10, &[])),
        (true, Ok(()))
    ));
    assert!(!state.conflicting);
    let mut large = latest(0, 10, &[]);
    large.revocation.number[0] = 1;
    assert!(matches!(learn(&mut state, large), (true, Ok(()))));
}

fn collateral() -> Vec<crate::AmdCollateral> {
    let fixture: Value = serde_json::from_str(include_str!(
        "../../../../../tests/fixtures/hardware-session-v1.json"
    ))
    .unwrap();
    serde_json::from_value(fixture["evidence"]["document"]["vendor_collateral"].clone()).unwrap()
}

type Edit<'a> = &'a dyn Fn(&mut Vec<crate::AmdCollateral>);

#[test]
fn each_vcek_row_names_its_certificates_chip_tcb_and_product() {
    let rows = collateral();
    Store::verify(&rows, None, Arc::default()).unwrap();
    let find = |kind| {
        rows.iter()
            .position(|row| row.collateral_type == kind)
            .unwrap()
    };
    let (vcek, ark) = (
        find(crate::AmdCollateralType::Vcek),
        find(crate::AmdCollateralType::Ark),
    );
    let edits: [Edit; 5] = [
        &|rows| rows[vcek].chip_id = Some("11".repeat(64)),
        &|rows| rows[vcek].reported_tcb = Some("0400000000001ddf".into()),
        &|rows| rows[vcek].product_name = Some("Genoa".into()),
        // Another product's ARK.
        &|rows| rows[ark].der_base64url = URL_SAFE_NO_PAD.encode(Product::Genoa.roots().ark),
        &|rows| {
            rows.retain(|row| row.collateral_type != crate::AmdCollateralType::Crl);
        },
    ];
    for (index, edit) in edits.iter().enumerate() {
        let mut changed = rows.clone();
        edit(&mut changed);
        assert!(
            Store::verify(&changed, None, Arc::default()).is_err(),
            "edit {index}"
        );
    }
}

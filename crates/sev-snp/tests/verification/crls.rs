use stogas_sev_snp::{
    Crl, Endorsement, Endorsements, ErrorKind, Policy, Product, Validity, verify,
};

use crate::fixtures::{NOW, case, permissive, read};

#[test]
fn amd_crls_verify_with_the_pinned_roots() {
    for (path, product, number, not_before) in [
        ("amd-kds/milan.crl", Product::Milan, 13, 1_793_082_435),
        ("amd-kds/genoa.crl", Product::Genoa, 12, 1_793_082_166),
        ("amd-kds/turin.crl", Product::Turin, 9, 1_793_082_647),
    ] {
        let crl = Crl::verify(&read(path)).unwrap();
        assert_eq!(crl.product(), product, "{path}");
        let mut expected = [0; 20];
        expected[19] = number;
        assert_eq!(crl.number(), expected, "{path}");
        assert_eq!(
            crl.validity(),
            Validity {
                not_before,
                not_after: 1_796_778_000,
            },
            "{path}"
        );
    }
}

#[test]
fn the_genoa_crl_revokes_the_first_genoa_ask() {
    let crl = Crl::verify(&read("amd-kds/genoa.crl")).unwrap();
    assert!(crl.is_revoked(&[0x02, 0x00, 0x01]));
    assert!(crl.revoked().eq([&[0x02, 0x00, 0x01][..]]));
    // The current Genoa ASK, which the built-in roots hold.
    let genoa = Endorsement::verify(&case("trustee-azure-genoa").inputs().leaf, None).unwrap();
    assert!(!crl.is_revoked(genoa.intermediate_serial()));
    let milan = Crl::verify(&read("amd-kds/milan.crl")).unwrap();
    assert_eq!(milan.revoked().len(), 0);
    assert!(!milan.is_revoked(&[0x01, 0x00, 0x01]));
    assert!(!milan.is_revoked(&[]));
}

#[test]
fn amd_numbers_its_crls_in_order() {
    for product in ["milan", "genoa", "turin"] {
        let older =
            Crl::verify(&read(&format!("attestation-rs/{product}-2026-09-22.crl"))).unwrap();
        let newer = Crl::verify(&read(&format!("amd-kds/{product}.crl"))).unwrap();
        assert_eq!(older.product(), newer.product());
        assert!(older.number() < newer.number(), "{product}");
        assert!(older.validity().not_after < newer.validity().not_after);
        assert_ne!(older, newer);
    }
}

#[test]
fn a_crl_must_be_for_the_reports_product_and_valid_now() {
    let inputs = case("gcp-milan-vmpl0").inputs();
    let with_crl = |path: &str| {
        let crl = read(path);
        let endorsements = Endorsements {
            crl: Some(&crl),
            ..inputs.endorsements()
        };
        verify(&inputs.report, &endorsements, &permissive(), NOW)
            .map(|verified| verified.validity())
    };
    assert_eq!(
        with_crl("amd-kds/genoa.crl").unwrap_err().kind(),
        ErrorKind::Binding
    );
    // The older CRL's next update was 2026-11-09.
    assert_eq!(
        with_crl("attestation-rs/milan-2026-09-22.crl")
            .unwrap_err()
            .kind(),
        ErrorKind::Expired
    );
    // A checked CRL bounds the result's validity.
    assert_eq!(
        with_crl("amd-kds/milan.crl").unwrap().not_after,
        1_796_778_000
    );
    assert_eq!(
        with_crl("amd-kds/milan.crl").unwrap().not_before,
        1_793_555_065
    );
}

#[test]
fn a_policy_can_require_a_crl() {
    let inputs = case("gcp-milan-vmpl0").inputs();
    let policy = Policy {
        require_crl: true,
        ..permissive()
    };
    assert!(verify(&inputs.report, &inputs.endorsements(), &policy, NOW).is_ok());
    let without = Endorsements {
        crl: None,
        ..inputs.endorsements()
    };
    assert_eq!(
        verify(&inputs.report, &without, &policy, NOW)
            .unwrap_err()
            .kind(),
        ErrorKind::MissingEndorsement
    );
}

#[test]
fn every_change_to_a_crl_fails() {
    let crl = read("amd-kds/genoa.crl");
    for offset in 0..crl.len() {
        let mut changed = crl.clone();
        changed[offset] ^= 1;
        assert!(Crl::verify(&changed).is_err(), "{offset}");
    }
    for length in [0, 1, crl.len() - 1] {
        assert_eq!(
            Crl::verify(&crl[..length]).unwrap_err().kind(),
            ErrorKind::Certificate
        );
    }
    let mut longer = crl;
    longer.push(0);
    assert_eq!(
        Crl::verify(&longer).unwrap_err().kind(),
        ErrorKind::Certificate
    );
    // A certificate is not a CRL.
    assert_eq!(
        Crl::verify(&read("go-sev-guest/vcek.der"))
            .unwrap_err()
            .kind(),
        ErrorKind::Certificate
    );
}

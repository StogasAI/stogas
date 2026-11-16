use stogas_sev_snp::{
    CertificateTable, Endorsement, Endorsements, ErrorKind, Policy, Product, Report, SigningKey,
    TcbVersion, Validity, verify,
};

use crate::fixtures::{NOW, case, cases, permissive, read, unhex};

const MILAN_ASVK: &[u8] = include_bytes!("../../src/amd/milan-asvk.der");
const MILAN_ARK: &[u8] = include_bytes!("../../src/amd/milan-ark.der");
const MILAN_ASK: &[u8] = include_bytes!("../../src/amd/milan-ask.der");
const GENOA_ASK: &[u8] = include_bytes!("../../src/amd/genoa-ask.der");

fn gcp_vcek() -> Vec<u8> {
    case("gcp-milan-vmpl0").inputs().leaf
}

fn rejection(report: &str, leaf: &[u8], intermediate: Option<&[u8]>) -> ErrorKind {
    let endorsements = Endorsements {
        leaf,
        intermediate,
        crl: None,
    };
    verify(&read(report), &endorsements, &permissive(), NOW)
        .unwrap_err()
        .kind()
}

#[test]
fn every_report_verifies_with_its_certificate() {
    for case in cases() {
        let inputs = case.inputs();
        let verified = verify(
            &inputs.report,
            &inputs.endorsements(),
            &permissive(),
            case.time,
        )
        .unwrap_or_else(|error| panic!("{}: {error}", case.name));
        let endorsement =
            Endorsement::verify(&inputs.leaf, inputs.intermediate.as_deref()).unwrap();
        let report = verified.report();
        assert_eq!(endorsement.tcb(), report.reported_tcb(), "{}", case.name);
        assert_eq!(
            endorsement.chip_id(),
            (case.signing_key == SigningKey::Vcek).then_some(report.chip_id()),
            "{}",
            case.name
        );
        assert_eq!(verified.product(), case.product, "{}", case.name);
        assert_eq!(verified.signing_key(), case.signing_key, "{}", case.name);
        assert_eq!(
            verified.revocation_checked(),
            case.crl.is_some(),
            "{}",
            case.name
        );
        assert!(verified.validity().contains(case.time), "{}", case.name);
        assert_eq!(
            verified.csp_id(),
            (case.signing_key == SigningKey::Vlek).then_some("CN=cc-us-east-2.amazonaws.com"),
            "{}",
            case.name
        );
    }
}

#[test]
fn the_default_policy_rejects_a_guest_that_the_host_may_debug() {
    let inputs = case("go-sev-guest").inputs();
    let error = verify(
        &inputs.report,
        &inputs.endorsements(),
        &Policy::default(),
        NOW,
    )
    .unwrap_err();
    assert_eq!(error.kind(), ErrorKind::Policy);
}

#[test]
fn an_endorsement_verifies_many_reports() {
    let endorsement = Endorsement::verify(&gcp_vcek(), None).unwrap();
    assert_eq!(endorsement.product(), Product::Milan);
    assert_eq!(endorsement.signing_key(), SigningKey::Vcek);
    assert_eq!(endorsement.csp_id(), None);
    assert_eq!(endorsement.intermediate_serial(), [0x01, 0x00, 0x01]);
    // The VCEK is valid for seven years, within the ASK and ARK.
    assert_eq!(
        endorsement.validity(),
        Validity {
            not_before: 1_793_555_065,
            not_after: 2_014_479_865,
        }
    );
    for vmpl in 0..4 {
        let report = Report::parse(&read(&format!("gcp-milan/report-vmpl{vmpl}.bin"))).unwrap();
        let verified = endorsement.verify_report(report).unwrap();
        assert_eq!(verified.report().vmpl(), vmpl);
        assert!(!verified.revocation_checked());
    }
}

#[test]
fn a_vlek_names_its_cloud_provider() {
    let endorsement = Endorsement::verify(&case("aws-milan-vmpl0").inputs().leaf, None).unwrap();
    assert_eq!(endorsement.signing_key(), SigningKey::Vlek);
    assert_eq!(endorsement.csp_id(), Some("CN=cc-us-east-2.amazonaws.com"));
    assert_eq!(endorsement.intermediate_serial(), [0x01, 0x01, 0x01]);
    assert_eq!(
        endorsement.validity(),
        Validity {
            not_before: 1_790_830_883,
            not_after: 1_822_366_883,
        }
    );
}

#[test]
fn a_turin_vcek_names_the_first_8_bytes_of_the_chip_id() {
    let endorsement = Endorsement::verify(&read("virtee-sev/turin-vcek.der"), None).unwrap();
    assert_eq!(endorsement.product(), Product::Turin);
    assert_eq!(endorsement.signing_key(), SigningKey::Vcek);
    // OpenSSL reads the hardware ID extension 1e550a8ee5cf9f4d and the SPLs FMC 0, bootloader 0,
    // TEE 0, SNP 0 and microcode 9.
    let mut chip_id = [0; 64];
    chip_id[..8].copy_from_slice(&unhex("1e550a8ee5cf9f4d"));
    assert_eq!(endorsement.chip_id(), Some(&chip_id));
    assert_eq!(
        endorsement.tcb(),
        TcbVersion {
            fmc: Some(0),
            bootloader: 0,
            tee: 0,
            snp: 0,
            microcode: 9,
        }
    );
    assert_eq!(endorsement.intermediate_serial(), [0x03, 0x00, 0x01]);
    assert_eq!(
        endorsement.validity(),
        Validity {
            not_before: 1_730_927_640,
            not_after: 1_951_766_040,
        }
    );
    // A Turin certificate cannot endorse a version 2 report, which Milan and Genoa produced.
    let report = Report::parse(&read("go-sev-guest/report.bin")).unwrap();
    assert_eq!(
        endorsement.verify_report(report).unwrap_err().kind(),
        ErrorKind::Binding
    );
}

#[test]
fn genoa_and_siena_share_the_genoa_ask() {
    for name in ["attestation-rs-siena", "trustee-azure-genoa"] {
        let endorsement = Endorsement::verify(&case(name).inputs().leaf, None).unwrap();
        assert_eq!(endorsement.product(), Product::Genoa);
        assert_eq!(endorsement.intermediate_serial(), [0x02, 0x00, 0x02]);
    }
}

#[test]
fn a_certificate_whose_chip_id_was_replaced_fails_its_signature() {
    // The second wraps the chip ID in an OCTET STRING, which the parser accepts.
    for leaf in [
        "trustee/vcek-invalid-legacy.der",
        "trustee/vcek-invalid-new.der",
    ] {
        assert_eq!(
            Endorsement::verify(&read(leaf), None).unwrap_err().kind(),
            ErrorKind::Signature,
            "{leaf}"
        );
    }
}

#[test]
fn a_certificate_must_describe_the_report() {
    // A VCEK at the same TCB for another chip.
    assert_eq!(
        rejection("trustee/report.bin", &read("virtee-sev/vcek.der"), None),
        ErrorKind::Binding
    );
    // A VCEK for the same chip at an older TCB.
    assert_eq!(
        rejection(
            "gcp-milan/report-vmpl0.bin",
            &read("attestation-rs/gcp-older-tcb-vcek.der"),
            None
        ),
        ErrorKind::Binding
    );
    // A Milan VCEK and a Genoa report.
    assert_eq!(
        rejection("attestation-rs/siena-report.bin", &gcp_vcek(), None),
        ErrorKind::Binding
    );
    // A VCEK and a report that a VLEK signed, and the reverse.
    assert_eq!(
        rejection("aws-milan/report-vmpl0.bin", &gcp_vcek(), None),
        ErrorKind::Binding
    );
    assert_eq!(
        rejection(
            "gcp-milan/report-vmpl0.bin",
            &case("aws-milan-vmpl0").inputs().leaf,
            None
        ),
        ErrorKind::Binding
    );
}

#[test]
fn an_intermediate_must_be_the_products_ask_or_asvk() {
    let report = "gcp-milan/report-vmpl0.bin";
    let table_ask = case("gcp-milan-vmpl0").inputs().intermediate.unwrap();
    assert!(
        verify(
            &read(report),
            &Endorsements {
                leaf: &gcp_vcek(),
                intermediate: Some(&table_ask),
                crl: None,
            },
            &permissive(),
            NOW
        )
        .is_ok()
    );
    for intermediate in [MILAN_ASVK, MILAN_ARK, GENOA_ASK] {
        assert_eq!(
            rejection(report, &gcp_vcek(), Some(intermediate)),
            ErrorKind::Binding
        );
    }
}

#[test]
fn a_certificate_is_valid_only_within_its_validity() {
    let inputs = case("gcp-milan-vmpl0").inputs();
    let endorsements = Endorsements {
        crl: None,
        ..inputs.endorsements()
    };
    let at = |time| verify(&inputs.report, &endorsements, &permissive(), time);
    assert!(at(1_793_555_065).is_ok());
    assert!(at(2_014_479_865).is_ok());
    assert_eq!(at(1_793_555_064).unwrap_err().kind(), ErrorKind::Expired);
    assert_eq!(at(2_014_479_866).unwrap_err().kind(), ErrorKind::Expired);
    // AWS's VLEK in the trustee fixtures expired on 2025-12-10.
    let vlek = case("trustee-aws-vlek").inputs();
    assert_eq!(
        verify(&vlek.report, &vlek.endorsements(), &permissive(), NOW)
            .unwrap_err()
            .kind(),
        ErrorKind::Expired
    );
}

#[test]
fn an_unsigned_report_has_no_endorsement() {
    let mut bytes = read("gcp-milan/report-vmpl0.bin");
    bytes[0x48] = 7 << 2;
    let report = Report::parse(&bytes).unwrap();
    let endorsement = Endorsement::verify(&gcp_vcek(), None).unwrap();
    assert_eq!(
        endorsement.verify_report(report).unwrap_err().kind(),
        ErrorKind::Unsigned
    );
    let table = read("gcp-milan/certificates.bin");
    assert_eq!(
        CertificateTable::parse(&table)
            .unwrap()
            .endorsements(SigningKey::None)
            .unwrap_err()
            .kind(),
        ErrorKind::Unsigned
    );
}

#[test]
fn every_change_to_the_signed_report_fails() {
    let endorsement = Endorsement::verify(&gcp_vcek(), None).unwrap();
    let report = read("gcp-milan/report-vmpl0.bin");
    // Every field, and then every 17th byte.
    let offsets = [
        0x00, 0x04, 0x08, 0x10, 0x20, 0x30, 0x34, 0x38, 0x40, 0x48, 0x50, 0x90, 0xc0, 0xe0, 0x110,
        0x140, 0x160, 0x180, 0x188, 0x1a0, 0x1e0, 0x1e8, 0x1ec, 0x1f0, 0x1f8, 0x200, 0x208,
    ]
    .into_iter()
    .chain((0..0x2a0).step_by(17));
    for offset in offsets {
        let mut changed = report.clone();
        changed[offset] ^= 1;
        let result = Report::parse(&changed).and_then(|report| endorsement.verify_report(report));
        assert!(result.is_err(), "{offset:#x}");
    }
    // Both signature scalars.
    for offset in [0x2a0, 0x2a0 + 47, 0x2e8, 0x2e8 + 47] {
        let mut changed = report.clone();
        changed[offset] ^= 1;
        let report = Report::parse(&changed).unwrap();
        assert_eq!(
            endorsement.verify_report(report).unwrap_err().kind(),
            ErrorKind::Signature,
            "{offset:#x}"
        );
    }
}

#[test]
fn every_change_to_a_certificate_fails() {
    let vcek = gcp_vcek();
    for offset in (0..vcek.len()).step_by(3) {
        let mut changed = vcek.clone();
        changed[offset] ^= 1;
        assert!(Endorsement::verify(&changed, None).is_err(), "{offset}");
    }
}

/// GUIDs from the GHCB specification, and the CRL's from the `sev` crate.
const VCEK_GUID: &str = "63da758de6644564adc5f4b93be8accd";
const ASK_GUID: &str = "4ab7b379bbac4fe4a02f05aef327c782";
const ARK_GUID: &str = "c0b406a4a803495297433fb6014cd0ae";
const CRL_GUID: &str = "92f81bc358114d3d97ffd19f88dc67ea";

/// A certificate table as a host writes it: the entries, an empty entry and the certificates.
fn table(certificates: &[(&str, &[u8])]) -> Vec<u8> {
    let mut offset = (certificates.len() + 1) * 24;
    let mut entries = Vec::new();
    let mut data = Vec::new();
    for (guid, certificate) in certificates {
        entries.extend(unhex(guid));
        entries.extend(u32::try_from(offset).unwrap().to_le_bytes());
        entries.extend(u32::try_from(certificate.len()).unwrap().to_le_bytes());
        data.extend_from_slice(certificate);
        offset += certificate.len();
    }
    entries.extend([0; 24]);
    entries.extend(data);
    entries
}

#[test]
fn a_certificate_table_holds_the_hosts_certificates() {
    let gcp = read("gcp-milan/certificates.bin");
    let table = CertificateTable::parse(&gcp).unwrap();
    assert_eq!(table.ask, Some(MILAN_ASK));
    assert_eq!(table.ark, Some(MILAN_ARK));
    assert!(table.vcek.is_some() && table.vlek.is_none() && table.crl.is_none());
    let endorsements = table.endorsements(SigningKey::Vcek).unwrap();
    assert_eq!(endorsements.intermediate, Some(MILAN_ASK));
    assert_eq!(
        table.endorsements(SigningKey::Vlek).unwrap_err().kind(),
        ErrorKind::MissingEndorsement
    );
    let aws = read("aws-milan/certificates.bin");
    let table = CertificateTable::parse(&aws).unwrap();
    assert!(table.vlek.is_some() && table.vcek.is_none() && table.ask.is_none());
    assert_eq!(
        table.endorsements(SigningKey::Vcek).unwrap_err().kind(),
        ErrorKind::MissingEndorsement
    );
    assert!(
        table
            .endorsements(SigningKey::Vlek)
            .unwrap()
            .intermediate
            .is_none()
    );
    assert_eq!(
        table.endorsements(SigningKey::None).unwrap_err().kind(),
        ErrorKind::Unsigned
    );
    // A host without certificates may return no table, or only the empty entry.
    for empty in [&[][..], &[0; 24], &[0; 4096]] {
        assert_eq!(
            CertificateTable::parse(empty).unwrap(),
            CertificateTable::default()
        );
    }
}

#[test]
fn a_certificate_table_may_carry_amds_crl() {
    let inputs = case("gcp-milan-vmpl0").inputs();
    let crl = read("amd-kds/milan.crl");
    let bytes = table(&[
        (VCEK_GUID, &inputs.leaf),
        (ASK_GUID, MILAN_ASK),
        (ARK_GUID, MILAN_ARK),
        (CRL_GUID, &crl),
    ]);
    let table = CertificateTable::parse(&bytes).unwrap();
    assert_eq!(table.crl, Some(&crl[..]));
    let endorsements = table.endorsements(SigningKey::Vcek).unwrap();
    // The caller chooses whether to check the host's CRL.
    assert!(endorsements.crl.is_none());
    let checked = Endorsements {
        crl: table.crl,
        ..endorsements
    };
    let verified = verify(&inputs.report, &checked, &permissive(), NOW).unwrap();
    assert!(verified.revocation_checked());
}

#[test]
fn a_certificate_table_ends_with_an_empty_entry() {
    let vcek = gcp_vcek();
    let valid = table(&[(VCEK_GUID, &vcek)]);
    assert!(CertificateTable::parse(&valid).unwrap().vcek.is_some());
    // Without the empty entry, or with one that is not entirely zero.
    for length in [1, 24, 47] {
        assert_eq!(
            CertificateTable::parse(&valid[..length])
                .unwrap_err()
                .kind(),
            ErrorKind::Certificate,
            "{length}"
        );
    }
    let mut terminator = valid.clone();
    terminator[40] = 1;
    assert_eq!(
        CertificateTable::parse(&terminator).unwrap_err().kind(),
        ErrorKind::Certificate
    );
    // A certificate must lie after the entries and inside the table, and must not be empty.
    let length = u32::try_from(vcek.len()).unwrap();
    for (offset, length) in [
        (0, 24),
        (24, length),
        (47, length),
        (48, length + 1),
        (49, length),
        (u32::MAX, 2),
        (48, 0),
    ] {
        let mut changed = valid.clone();
        changed[16..20].copy_from_slice(&offset.to_le_bytes());
        changed[20..24].copy_from_slice(&length.to_le_bytes());
        assert_eq!(
            CertificateTable::parse(&changed).unwrap_err().kind(),
            ErrorKind::Certificate,
            "{offset} {length}"
        );
    }
    let repeated = table(&[(VCEK_GUID, &vcek), (VCEK_GUID, &vcek)]);
    assert_eq!(
        CertificateTable::parse(&repeated).unwrap_err().kind(),
        ErrorKind::Certificate
    );
    // Entries with other GUIDs are skipped, and the certificates may be followed by padding.
    let mut other = table(&[
        ("00112233445566778899aabbccddeeff", &[1]),
        (VCEK_GUID, &vcek),
    ]);
    other.resize(4096, 0);
    assert_eq!(
        CertificateTable::parse(&other).unwrap().vcek,
        Some(&vcek[..])
    );
}

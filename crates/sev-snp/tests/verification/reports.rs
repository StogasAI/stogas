use stogas_sev_snp::{
    ErrorKind, FirmwareVersion, Product, REPORT_SIZE, Report, SigningKey, TcbVersion, guest_policy,
    platform_info,
};

use crate::fixtures::{cases, hex, read};

const GCP: &str = "gcp-milan/report-vmpl0.bin";
const V2: &str = "go-sev-guest/report.bin";

fn with(path: &str, change: impl FnOnce(&mut [u8])) -> Vec<u8> {
    let mut bytes = read(path);
    change(&mut bytes);
    bytes
}

fn rejection(bytes: &[u8]) -> ErrorKind {
    Report::parse(bytes).unwrap_err().kind()
}

const fn milan_tcb(bootloader: u8, tee: u8, snp: u8, microcode: u8) -> TcbVersion {
    TcbVersion {
        fmc: None,
        bootloader,
        tee,
        snp,
        microcode,
    }
}

#[test]
fn every_report_parses_with_the_values_an_independent_parser_read() {
    for case in cases() {
        let report = Report::parse(&read(&case.report))
            .unwrap_or_else(|error| panic!("{}: {error}", case.name));
        assert_eq!(report.version(), case.version, "{}", case.name);
        assert_eq!(
            report.product(),
            (case.version >= 3).then_some(case.product),
            "{}",
            case.name
        );
        assert_eq!(report.cpuid(), case.cpuid, "{}", case.name);
        assert_eq!(report.vmpl(), case.vmpl, "{}", case.name);
        assert_eq!(report.signing_key(), case.signing_key, "{}", case.name);
        assert_eq!(
            hex(&report.reported_tcb().to_bytes()),
            case.reported_tcb,
            "{}",
            case.name
        );
        assert_eq!(report.as_bytes()[..], read(&case.report)[..]);
    }
}

#[test]
fn an_aws_report_names_its_fields() {
    let report = Report::parse(&read("aws-milan/report-vmpl0.bin")).unwrap();
    assert_eq!(report.guest_policy(), 0x0203_0000);
    assert_eq!(guest_policy::abi(report.guest_policy()), (0, 0));
    assert_eq!(
        report.guest_policy() & guest_policy::PAGE_SWAP_DISABLE,
        guest_policy::PAGE_SWAP_DISABLE
    );
    assert_eq!(
        report.platform_info(),
        platform_info::SMT_EN
            | platform_info::TSME_EN
            | platform_info::ECC_EN
            | platform_info::ALIAS_CHECK_COMPLETE
    );
    let tcb = milan_tcb(4, 0, 31, 225);
    assert_eq!(report.current_tcb(), tcb);
    assert_eq!(report.reported_tcb(), tcb);
    assert_eq!(report.committed_tcb(), tcb);
    assert_eq!(report.launch_tcb(), tcb);
    let firmware = FirmwareVersion {
        major: 1,
        minor: 58,
        build: 3,
    };
    assert_eq!(report.current_version(), firmware);
    assert_eq!(report.committed_version(), firmware);
    assert_eq!(report.launch_mitigations(), Some(0xfef));
    assert_eq!(report.current_mitigations(), Some(0xfef));
    // AWS masks the chip ID, and Milan writes all ones without a migration agent.
    assert_eq!(report.chip_id(), &[0; 64]);
    assert_eq!(report.report_id_ma(), &[0xff; 32]);
    assert_eq!(report.report_data().to_vec(), (0..64).collect::<Vec<u8>>());
    assert!(!report.author_key_enabled());
    assert!(!report.mask_chip_key());
    assert_eq!(report.guest_svn(), 0);
}

#[test]
fn a_version_2_report_has_no_cpuid_or_mitigations() {
    let report = Report::parse(&read("trustee/report.bin")).unwrap();
    assert_eq!(report.cpuid(), None);
    assert_eq!(report.product(), None);
    assert_eq!(report.launch_mitigations(), None);
    assert_eq!(report.facts().launch_mitigations, 0);
    assert_eq!(report.guest_svn(), 4);
    assert_eq!(guest_policy::abi(report.guest_policy()), (0, 31));
    // The host loaded newer microcode than it committed.
    assert_eq!(report.current_tcb(), milan_tcb(3, 0, 8, 206));
    assert_eq!(report.committed_tcb(), milan_tcb(3, 0, 8, 115));
    assert_eq!(report.reported_tcb(), milan_tcb(3, 0, 8, 115));
}

#[test]
fn a_genoa_report_names_its_fields() {
    let report = Report::parse(&read("attestation-rs/azure-genoa-report.bin")).unwrap();
    assert_eq!(report.product(), Some(Product::Genoa));
    assert_eq!(report.cpuid(), Some([0x19, 0x11, 0x01]));
    assert_eq!(report.current_tcb(), milan_tcb(12, 0, 28, 88));
    assert_eq!(
        report.current_version(),
        FirmwareVersion {
            major: 1,
            minor: 58,
            build: 2
        }
    );
    assert_eq!(report.current_mitigations(), Some(7));
    assert_eq!(report.guest_svn(), 3);
    let siena = Report::parse(&read("attestation-rs/siena-report.bin")).unwrap();
    assert_eq!(siena.product(), Some(Product::Genoa));
}

#[test]
fn a_report_has_exactly_its_size() {
    let report = read(GCP);
    for length in [0, 0x2a0, REPORT_SIZE - 1] {
        assert_eq!(rejection(&report[..length]), ErrorKind::Report);
    }
    let mut longer = report;
    longer.push(0);
    assert_eq!(rejection(&longer), ErrorKind::Report);
}

#[test]
fn report_versions_2_to_6_parse() {
    // A Milan report keeps the version 5 layout as version 6.
    let six = with(GCP, |bytes| bytes[0] = 6);
    assert_eq!(Report::parse(&six).unwrap().version(), 6);
    // Versions 3 and 4 reserve the mitigation vectors, which this report sets.
    for version in [3, 4] {
        assert_eq!(
            rejection(&with(GCP, |bytes| bytes[0] = version)),
            ErrorKind::Report
        );
    }
    for version in [0, 1, 7, 0xff] {
        assert_eq!(
            rejection(&with(GCP, |bytes| bytes[0] = version)),
            ErrorKind::Report
        );
    }
    assert_eq!(
        rejection(&with(GCP, |bytes| bytes[1] = 1)),
        ErrorKind::Report
    );
    // A version 2 report leaves the CPUID fields empty, which no product has.
    assert_eq!(
        rejection(&with(V2, |bytes| bytes[0] = 3)),
        ErrorKind::UnsupportedProduct
    );
}

#[test]
fn the_cpuid_names_the_product() {
    for (family, model, product) in [
        (0x19, 0x00, Product::Milan),
        (0x19, 0x0f, Product::Milan),
        (0x19, 0x10, Product::Genoa),
        (0x19, 0x1f, Product::Genoa),
        (0x19, 0xa0, Product::Genoa),
        (0x19, 0xaf, Product::Genoa),
        (0x1a, 0x00, Product::Turin),
        (0x1a, 0x1f, Product::Turin),
    ] {
        assert_eq!(Product::from_cpuid(family, model).unwrap(), product);
    }
    // Zen 2, gaps between product lines, and Venice.
    for (family, model) in [
        (0x17, 0x31),
        (0x19, 0x20),
        (0x19, 0x9f),
        (0x19, 0xb0),
        (0x1a, 0x20),
        (0x1a, 0x50),
        (0x1a, 0xc0),
    ] {
        assert_eq!(
            Product::from_cpuid(family, model).unwrap_err().kind(),
            ErrorKind::UnsupportedProduct
        );
    }
    let venice = with(GCP, |bytes| {
        bytes[0x188] = 0x1a;
        bytes[0x189] = 0x50;
    });
    assert_eq!(rejection(&venice), ErrorKind::UnsupportedProduct);
}

#[test]
fn turin_reports_use_turins_tcb_layout() {
    let turin = |bytes: &mut [u8]| {
        bytes[0x188] = 0x1a;
        bytes[0x189] = 0x02;
    };
    // The Milan TCB sets a byte that Turin reserves.
    assert_eq!(rejection(&with(GCP, turin)), ErrorKind::Report);
    let tcb = [1, 2, 3, 4, 0, 0, 0, 5];
    let report = with(GCP, |bytes| {
        turin(bytes);
        for offset in [0x38, 0x180, 0x1e0, 0x1f0] {
            bytes[offset..offset + 8].copy_from_slice(&tcb);
        }
    });
    let parsed = Report::parse(&report).unwrap();
    assert_eq!(parsed.product(), Some(Product::Turin));
    let expected = TcbVersion {
        fmc: Some(1),
        bootloader: 2,
        tee: 3,
        snp: 4,
        microcode: 5,
    };
    assert_eq!(parsed.reported_tcb(), expected);
    assert_eq!(expected.to_bytes(), tcb);
    // Turin firmware writes version 5 or later.
    let mut old = report;
    old[0] = 3;
    old[0x1f8..0x208].fill(0);
    let error = Report::parse(&old).unwrap_err();
    assert_eq!(error.kind(), ErrorKind::Report);
    assert!(error.message().contains("version 5 or later"), "{error}");
}

#[test]
fn every_reserved_byte_must_be_zero() {
    let signature = 0x2a0;
    let v5 = (0x4c..0x50)
        .chain(0x18b..0x1a0)
        .chain([0x1eb, 0x1ef])
        .chain(0x208..signature)
        .chain(signature + 48..signature + 72)
        .chain(signature + 120..REPORT_SIZE);
    let report = read(GCP);
    for offset in v5 {
        let mut changed = report.clone();
        changed[offset] = 1;
        assert_eq!(rejection(&changed), ErrorKind::Report, "{offset:#x}");
    }
    // Version 2 also reserves the CPUID fields and the mitigation vectors.
    let report = read(V2);
    for offset in (0x188..0x1a0).chain(0x1f8..0x208) {
        let mut changed = report.clone();
        changed[offset] = 1;
        assert_eq!(rejection(&changed), ErrorKind::Report, "{offset:#x}");
    }
    // Milan and Genoa TCBs reserve bytes 2 to 5.
    for tcb in [0x38, 0x180, 0x1e0, 0x1f0] {
        for offset in tcb + 2..tcb + 6 {
            let mut changed = read(GCP);
            changed[offset] = 1;
            assert_eq!(rejection(&changed), ErrorKind::Report, "{offset:#x}");
        }
    }
}

#[test]
fn fields_that_the_firmware_does_not_constrain_take_any_value() {
    let report = read(GCP);
    let signature = 0x2a0;
    let free = (0x04..0x08)
        .chain(0x10..0x34)
        .chain(0x50..0x180)
        .chain(0x1a0..0x1e0)
        .chain(signature..signature + 48)
        .chain(signature + 72..signature + 120);
    for offset in free {
        let mut changed = report.clone();
        changed[offset] ^= 0xff;
        assert!(Report::parse(&changed).is_ok(), "{offset:#x}");
    }
}

#[test]
fn the_guest_policy_sets_bit_17_and_no_unknown_bit() {
    assert_eq!(
        rejection(&with(GCP, |bytes| bytes[0x0a] &= !0x02)),
        ErrorKind::Report
    );
    for bit in 26..64 {
        let policy = 0x3_0000_u64 | 1 << bit;
        let report = with(GCP, |bytes| {
            bytes[0x08..0x10].copy_from_slice(&policy.to_le_bytes());
        });
        assert_eq!(rejection(&report), ErrorKind::Report, "bit {bit}");
    }
    for bit in (0..17).chain(18..26) {
        let policy = 0x2_0000_u64 | 1 << bit;
        let report = with(GCP, |bytes| {
            bytes[0x08..0x10].copy_from_slice(&policy.to_le_bytes());
        });
        assert_eq!(
            Report::parse(&report).unwrap().guest_policy(),
            policy,
            "bit {bit}"
        );
    }
}

#[test]
fn the_signature_algorithm_is_ecdsa_p384_with_sha384() {
    for algorithm in [0_u32, 2, 0x100] {
        let report = with(GCP, |bytes| {
            bytes[0x34..0x38].copy_from_slice(&algorithm.to_le_bytes());
        });
        assert_eq!(rejection(&report), ErrorKind::Report);
    }
}

#[test]
fn platform_information_keeps_every_bit_that_firmware_sets() {
    for bit in 0..64 {
        let info = 1_u64 << bit;
        let report = with(GCP, |bytes| {
            bytes[0x40..0x48].copy_from_slice(&info.to_le_bytes());
        });
        assert_eq!(Report::parse(&report).unwrap().platform_info(), info);
    }
    // Turin firmware sets bit 6, which AMD's ABI reserves.
    let turin = Report::parse(&read("oak/turin-report.bin")).unwrap();
    assert_eq!(turin.platform_info() & !platform_info::KNOWN, 1 << 6);
}

#[test]
fn key_information_names_a_known_key() {
    let key_info = |value: u32| {
        with(GCP, |bytes| {
            bytes[0x48..0x4c].copy_from_slice(&value.to_le_bytes());
        })
    };
    for (value, key) in [
        (0, SigningKey::Vcek),
        (1 << 2, SigningKey::Vlek),
        (7 << 2, SigningKey::None),
    ] {
        assert_eq!(Report::parse(&key_info(value)).unwrap().signing_key(), key);
    }
    // Revision 1.59 of AMD's ABI names key 2, the chip-secret VCEK, and reserves keys 3 to 6.
    let chip_secret = Report::parse(&key_info(2 << 2)).unwrap_err();
    assert_eq!(chip_secret.kind(), ErrorKind::Report);
    assert!(chip_secret.message().contains("chip-secret VCEK"));
    for reserved in 3..7 {
        assert_eq!(rejection(&key_info(reserved << 2)), ErrorKind::Report);
    }
    for bit in 5..32 {
        assert_eq!(
            rejection(&key_info(1 << bit)),
            ErrorKind::Report,
            "bit {bit}"
        );
    }
    let report = Report::parse(&key_info(7 << 2 | 3)).unwrap();
    assert!(report.author_key_enabled());
    assert!(report.mask_chip_key());
}

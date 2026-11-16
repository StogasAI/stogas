use stogas_sev_snp::{
    ErrorKind, FirmwareVersion, GuestPolicyRule, PlatformRule, Policy, Product, SigningKey,
    TcbVersion, Verified, guest_policy, platform_info, verify,
};

use crate::fixtures::{case, permissive};

fn verified(name: &str) -> Verified {
    let case = case(name);
    let inputs = case.inputs();
    verify(
        &inputs.report,
        &inputs.endorsements(),
        &permissive(),
        case.time,
    )
    .unwrap()
}

fn result(policy: &Policy, verified: &Verified) -> Result<(), ErrorKind> {
    policy.check(verified).map_err(|error| error.kind())
}

fn platforms(verified: &Verified, rules: &[PlatformRule]) -> Result<(), ErrorKind> {
    let policy = Policy {
        platforms: rules.to_vec(),
        ..Policy::default()
    };
    result(&policy, verified)
}

/// The TCB of the AWS and Google Cloud captures.
const MILAN: TcbVersion = TcbVersion {
    fmc: None,
    bootloader: 4,
    tee: 0,
    snp: 31,
    microcode: 225,
};

fn milan(minimum_tcb: TcbVersion) -> PlatformRule {
    PlatformRule {
        product: Some(Product::Milan),
        minimum_tcb: Some(minimum_tcb),
        ..PlatformRule::default()
    }
}

#[test]
fn report_values_must_match_the_policy() {
    let gcp = verified("gcp-milan-vmpl0");
    let report = gcp.report();
    let matching = Policy {
        report_data: Some(core::array::from_fn(|index| u8::try_from(index).unwrap())),
        measurements: vec![[0; 48], *report.measurement()],
        host_data: Some([0; 32]),
        family_id: Some(*report.family_id()),
        image_id: Some(*report.image_id()),
        id_key_digests: vec![[0; 48]],
        author_key_digests: vec![[0; 48]],
        report_id: Some(*report.report_id()),
        report_id_ma: Some([0xff; 32]),
        vmpl: Some(0),
        minimum_guest_svn: Some(0),
        ..Policy::default()
    };
    assert_eq!(result(&matching, &gcp), Ok(()));
    for differing in [
        Policy {
            report_data: Some([0; 64]),
            ..matching.clone()
        },
        Policy {
            measurements: vec![[0; 48]],
            ..matching.clone()
        },
        Policy {
            host_data: Some([1; 32]),
            ..matching.clone()
        },
        Policy {
            family_id: Some([1; 16]),
            ..matching.clone()
        },
        Policy {
            image_id: Some([1; 16]),
            ..matching.clone()
        },
        Policy {
            id_key_digests: vec![[1; 48]],
            ..matching.clone()
        },
        Policy {
            author_key_digests: vec![[1; 48]],
            ..matching.clone()
        },
        Policy {
            report_id: Some([0; 32]),
            ..matching.clone()
        },
        Policy {
            report_id_ma: Some([0; 32]),
            ..matching.clone()
        },
        Policy {
            vmpl: Some(1),
            ..matching.clone()
        },
        Policy {
            minimum_guest_svn: Some(1),
            ..matching
        },
    ] {
        assert_eq!(
            result(&differing, &gcp),
            Err(ErrorKind::Policy),
            "{differing:?}"
        );
    }
}

#[test]
fn a_policy_names_the_keys_and_cloud_providers_it_trusts() {
    let aws = verified("aws-milan-vmpl0");
    let gcp = verified("gcp-milan-vmpl0");
    let vcek = Policy {
        signers: vec![SigningKey::Vcek],
        ..Policy::default()
    };
    assert_eq!(result(&vcek, &gcp), Ok(()));
    assert_eq!(result(&vcek, &aws), Err(ErrorKind::Policy));
    let us_east_2 = Policy {
        csp_ids: vec!["CN=cc-us-east-2.amazonaws.com".into()],
        ..Policy::default()
    };
    assert_eq!(result(&us_east_2, &aws), Ok(()));
    // CSP IDs constrain only reports that a VLEK signed.
    assert_eq!(result(&us_east_2, &gcp), Ok(()));
    let eu_west_1 = Policy {
        csp_ids: vec!["CN=cc-eu-west-1.amazonaws.com".into()],
        ..Policy::default()
    };
    assert_eq!(result(&eu_west_1, &aws), Err(ErrorKind::Policy));
    let unsigned = Policy {
        signers: vec![SigningKey::None],
        ..Policy::default()
    };
    assert_eq!(result(&unsigned, &gcp), Err(ErrorKind::InvalidPolicy));
}

#[test]
fn the_guest_policy_rule_requires_and_forbids_flags() {
    // Google Cloud launches with SMT allowed and ABI 0.0.
    let gcp = verified("gcp-milan-vmpl0");
    let rule = |guest_policy| Policy {
        guest_policy,
        ..Policy::default()
    };
    for admitted in [
        GuestPolicyRule::default(),
        GuestPolicyRule {
            exact: Some(0x3_0000),
            ..GuestPolicyRule::default()
        },
        GuestPolicyRule {
            minimum_abi: Some((0, 0)),
            require: guest_policy::SMT,
            ..GuestPolicyRule::default()
        },
    ] {
        assert_eq!(
            result(&rule(admitted.clone()), &gcp),
            Ok(()),
            "{admitted:?}"
        );
    }
    for rejected in [
        GuestPolicyRule {
            exact: Some(0x2_0000),
            ..GuestPolicyRule::default()
        },
        GuestPolicyRule {
            forbid: guest_policy::SMT,
            ..GuestPolicyRule::default()
        },
        GuestPolicyRule {
            require: guest_policy::SINGLE_SOCKET,
            ..GuestPolicyRule::default()
        },
        GuestPolicyRule {
            minimum_abi: Some((1, 51)),
            ..GuestPolicyRule::default()
        },
    ] {
        assert_eq!(
            result(&rule(rejected.clone()), &gcp),
            Err(ErrorKind::Policy),
            "{rejected:?}"
        );
    }
    for invalid in [
        GuestPolicyRule {
            require: guest_policy::SMT,
            forbid: guest_policy::SMT,
            ..GuestPolicyRule::default()
        },
        GuestPolicyRule {
            require: 1 << 26,
            ..GuestPolicyRule::default()
        },
        GuestPolicyRule {
            forbid: 0xff,
            ..GuestPolicyRule::default()
        },
        // Bit 17 is always set.
        GuestPolicyRule {
            exact: Some(0x1_0000),
            ..GuestPolicyRule::default()
        },
        // The default rule forbids debugging.
        GuestPolicyRule {
            exact: Some(0x3_0000 | guest_policy::DEBUG),
            ..GuestPolicyRule::default()
        },
    ] {
        assert_eq!(
            result(&rule(invalid.clone()), &gcp),
            Err(ErrorKind::InvalidPolicy),
            "{invalid:?}"
        );
    }
}

#[test]
fn a_platform_rule_sets_minimum_spls() {
    let gcp = verified("gcp-milan-vmpl0");
    assert_eq!(platforms(&gcp, &[milan(MILAN)]), Ok(()));
    for higher in [
        TcbVersion {
            bootloader: 5,
            ..MILAN
        },
        TcbVersion { tee: 1, ..MILAN },
        TcbVersion { snp: 32, ..MILAN },
        TcbVersion {
            microcode: 226,
            ..MILAN
        },
    ] {
        assert_eq!(platforms(&gcp, &[milan(higher)]), Err(ErrorKind::Policy));
        let launch = PlatformRule {
            minimum_launch_tcb: Some(higher),
            ..milan(MILAN)
        };
        assert_eq!(platforms(&gcp, &[launch]), Err(ErrorKind::Policy));
    }
}

#[test]
fn a_platform_rule_names_products_cpuids_and_chips() {
    let gcp = verified("gcp-milan-vmpl0");
    let genoa = PlatformRule {
        product: Some(Product::Genoa),
        ..PlatformRule::default()
    };
    let error = Policy {
        platforms: vec![genoa.clone()],
        ..Policy::default()
    }
    .check(&gcp)
    .unwrap_err();
    assert_eq!(error.kind(), ErrorKind::Policy);
    assert!(
        error.message().contains("no platform rule names"),
        "{error}"
    );
    // Rules that do not name the platform do not count against it.
    assert_eq!(platforms(&gcp, &[genoa, milan(MILAN)]), Ok(()));
    let cpuid = |stepping| PlatformRule {
        cpuid_family: Some(0x19),
        cpuid_model: Some(0x01),
        cpuid_stepping: Some(stepping),
        ..PlatformRule::default()
    };
    assert_eq!(platforms(&gcp, &[cpuid(1)]), Ok(()));
    assert_eq!(platforms(&gcp, &[cpuid(0)]), Err(ErrorKind::Policy));
    let chips = |chip_ids| PlatformRule {
        chip_ids,
        ..PlatformRule::default()
    };
    assert_eq!(
        platforms(&gcp, &[chips(vec![*gcp.report().chip_id()])]),
        Ok(())
    );
    assert_eq!(
        platforms(&gcp, &[chips(vec![[1; 64]])]),
        Err(ErrorKind::Policy)
    );
    // Siena is a Genoa product line with its own CPUID model.
    let siena = verified("attestation-rs-siena");
    assert_eq!(
        platforms(
            &siena,
            &[PlatformRule {
                product: Some(Product::Genoa),
                cpuid_family: Some(0x19),
                cpuid_model: Some(0xa0),
                ..PlatformRule::default()
            }]
        ),
        Ok(())
    );
}

#[test]
fn a_platform_rule_checks_firmware_platform_information_and_mitigations() {
    let gcp = verified("gcp-milan-vmpl0");
    let aws = verified("aws-milan-vmpl0");
    let firmware = |major, minor, build| PlatformRule {
        minimum_firmware_version: Some(FirmwareVersion {
            major,
            minor,
            build,
        }),
        ..PlatformRule::default()
    };
    assert_eq!(platforms(&gcp, &[firmware(1, 58, 3)]), Ok(()));
    assert_eq!(platforms(&gcp, &[firmware(1, 57, 99)]), Ok(()));
    assert_eq!(
        platforms(&gcp, &[firmware(1, 58, 4)]),
        Err(ErrorKind::Policy)
    );
    assert_eq!(
        platforms(&gcp, &[firmware(1, 59, 0)]),
        Err(ErrorKind::Policy)
    );
    // Google Cloud enables SMT and ECC and completed alias detection.
    let info = |required, forbidden| PlatformRule {
        required_platform_info_mask: required,
        forbidden_platform_info_mask: forbidden,
        ..PlatformRule::default()
    };
    let ecc_alias = platform_info::ECC_EN | platform_info::ALIAS_CHECK_COMPLETE;
    assert_eq!(platforms(&gcp, &[info(ecc_alias, 0)]), Ok(()));
    assert_eq!(
        platforms(&gcp, &[info(platform_info::TSME_EN, 0)]),
        Err(ErrorKind::Policy)
    );
    assert_eq!(
        platforms(&gcp, &[info(0, platform_info::SMT_EN)]),
        Err(ErrorKind::Policy)
    );
    // Google Cloud's mitigation vectors are 0xfeb and AWS's are 0xfef.
    let mitigations = |launch, current| PlatformRule {
        required_launch_mitigation_mask: launch,
        required_current_mitigation_mask: current,
        ..PlatformRule::default()
    };
    assert_eq!(platforms(&gcp, &[mitigations(0xb, 0xb)]), Ok(()));
    assert_eq!(
        platforms(&gcp, &[mitigations(0, 0x4)]),
        Err(ErrorKind::Policy)
    );
    assert_eq!(
        platforms(&gcp, &[mitigations(0x4, 0)]),
        Err(ErrorKind::Policy)
    );
    assert_eq!(platforms(&aws, &[mitigations(0x4, 0x4)]), Ok(()));
    // A version 4 report carries no mitigation vectors.
    let version_4 = verified("automata-gcp");
    assert_eq!(platforms(&version_4, &[mitigations(0, 0)]), Ok(()));
    assert_eq!(
        platforms(&version_4, &[mitigations(0, 1)]),
        Err(ErrorKind::Policy)
    );
}

#[test]
fn a_platform_rule_can_refuse_bits_that_the_crate_does_not_name() {
    let turin = verified("oak-turin");
    assert_eq!(platforms(&turin, &[PlatformRule::default()]), Ok(()));
    let strict = PlatformRule {
        forbidden_platform_info_mask: !platform_info::KNOWN,
        ..PlatformRule::default()
    };
    assert!(strict.validate().is_ok());
    let rules = [strict];
    assert_eq!(platforms(&turin, &rules), Err(ErrorKind::Policy));
    assert_eq!(platforms(&verified("gcp-milan-vmpl0"), &rules), Ok(()));
}

#[test]
fn uncommitted_firmware_needs_the_rules_permission() {
    // The host loaded microcode 206 and committed 115.
    let trustee = verified("trustee");
    let rule = PlatformRule {
        product: Some(Product::Milan),
        ..PlatformRule::default()
    };
    assert_eq!(
        platforms(&trustee, std::slice::from_ref(&rule)),
        Err(ErrorKind::Policy)
    );
    let permitted = PlatformRule {
        permit_provisional_firmware: true,
        ..rule
    };
    assert_eq!(
        platforms(&trustee, std::slice::from_ref(&permitted)),
        Ok(())
    );
    // Minimums still apply to the committed TCB, to which the platform can roll back.
    let minimum = PlatformRule {
        minimum_tcb: Some(TcbVersion {
            fmc: None,
            bootloader: 3,
            tee: 0,
            snp: 8,
            microcode: 200,
        }),
        ..permitted.clone()
    };
    assert_eq!(platforms(&trustee, &[minimum]), Err(ErrorKind::Policy));
    // AWS reported microcode 217 and committed 219, and loaded 220.
    let vlek = verified("trustee-aws-vlek");
    assert_eq!(platforms(&vlek, &[permitted]), Ok(()));
}

#[test]
fn stored_facts_are_appraised_again() {
    let gcp = verified("gcp-milan-vmpl0");
    let facts = gcp.facts();
    let chip_id = gcp.report().chip_id();
    let rules = [milan(MILAN)];
    assert_eq!(
        PlatformRule::find(&rules, Product::Milan, chip_id, &facts).unwrap(),
        &rules[0]
    );
    let raised = [milan(TcbVersion {
        microcode: 226,
        ..MILAN
    })];
    assert_eq!(
        PlatformRule::find(&raised, Product::Milan, chip_id, &facts)
            .unwrap_err()
            .kind(),
        ErrorKind::Policy
    );
    // A rule must be valid even when an earlier rule admits the platform.
    let invalid = [
        milan(MILAN),
        PlatformRule {
            minimum_tcb: Some(MILAN),
            ..PlatformRule::default()
        },
    ];
    assert_eq!(
        PlatformRule::find(&invalid, Product::Milan, chip_id, &facts)
            .unwrap_err()
            .kind(),
        ErrorKind::InvalidPolicy
    );
}

#[test]
fn an_incoherent_platform_rule_is_invalid() {
    let fmc = TcbVersion {
        fmc: Some(1),
        ..MILAN
    };
    for rule in [
        // SPLs need a product.
        PlatformRule {
            minimum_tcb: Some(MILAN),
            ..PlatformRule::default()
        },
        PlatformRule {
            product: Some(Product::Turin),
            minimum_tcb: Some(MILAN),
            ..PlatformRule::default()
        },
        PlatformRule {
            product: Some(Product::Milan),
            minimum_launch_tcb: Some(fmc),
            ..PlatformRule::default()
        },
        PlatformRule {
            product: Some(Product::Genoa),
            cpuid_family: Some(0x19),
            cpuid_model: Some(0x01),
            ..PlatformRule::default()
        },
        PlatformRule {
            cpuid_model: Some(0x01),
            ..PlatformRule::default()
        },
        PlatformRule {
            cpuid_family: Some(0x19),
            cpuid_stepping: Some(0x01),
            ..PlatformRule::default()
        },
        // Venice.
        PlatformRule {
            cpuid_family: Some(0x1a),
            cpuid_model: Some(0x50),
            ..PlatformRule::default()
        },
        PlatformRule {
            required_platform_info_mask: platform_info::SMT_EN | 1 << 6,
            forbidden_platform_info_mask: 1 << 6,
            ..PlatformRule::default()
        },
    ] {
        assert_eq!(
            rule.validate().unwrap_err().kind(),
            ErrorKind::InvalidPolicy,
            "{rule:?}"
        );
    }
    let turin = PlatformRule {
        product: Some(Product::Turin),
        minimum_tcb: Some(fmc),
        ..PlatformRule::default()
    };
    assert!(turin.validate().is_ok());
}

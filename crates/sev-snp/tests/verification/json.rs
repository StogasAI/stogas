use serde_json::{Value, json};
use stogas_sev_snp::{
    FirmwareVersion, GuestPolicyRule, PlatformFacts, PlatformRule, Policy, Product, Report,
    SigningKey, TcbVersion, Validity, verify,
};

use crate::fixtures::{NOW, case, hex, permissive};

const GCP_CHIP: &str = "3e449e94094eaab2cfe4b44b27c9ae28cb56c196d85fe963c933a1cf1b8aff302956eee51582bf0a03038b821a42d533228865ba9ded2b9690ff7e195ddc888f";

fn gcp() -> stogas_sev_snp::Verified {
    let inputs = case("gcp-milan-vmpl0").inputs();
    verify(&inputs.report, &inputs.endorsements(), &permissive(), NOW).unwrap()
}

fn rejects<T: serde::de::DeserializeOwned + std::fmt::Debug>(value: &Value) {
    let parsed = T::deserialize(value);
    assert!(parsed.is_err(), "{value} parsed as {parsed:?}");
}

#[test]
fn a_hardware_policy_in_stogas_evidence_reads_and_writes_the_same_json() {
    // The shape of the hardware policies in Stogas's signed evidence.
    let stored = json!({
        "chip_ids": [GCP_CHIP],
        "cpuid_family": 25,
        "cpuid_model": 1,
        "cpuid_stepping": 1,
        "forbidden_platform_info_mask": "0x0000000000000000",
        "minimum_tcb": { "bootloader": 4, "microcode": 222, "snp": 29, "tee": 0 },
        "required_current_mitigation_mask": "0x000000000000000b",
        "required_launch_mitigation_mask": "0x000000000000000b",
        "required_platform_info_mask": "0x0000000000000024"
    });
    let rule: PlatformRule = serde_json::from_value(stored.clone()).unwrap();
    assert_eq!(serde_json::to_value(&rule).unwrap(), stored);
    rule.validate().unwrap();
    let gcp = gcp();
    let rules = [rule];
    assert!(
        PlatformRule::find(&rules, Product::Milan, gcp.report().chip_id(), &gcp.facts()).is_ok()
    );
}

#[test]
fn platform_facts_read_and_write_the_json_that_stogas_stores() {
    let tcb = json!({ "bootloader": 4, "microcode": 225, "snp": 31, "tee": 0 });
    let stored = json!({
        "report_version": 5,
        "cpuid": [25, 1, 1],
        "current_tcb": tcb,
        "reported_tcb": tcb,
        "committed_tcb": tcb,
        "launch_tcb": tcb,
        "current_version": [1, 58, 3],
        "committed_version": [1, 58, 3],
        "platform_info": "0x0000000000000025",
        "launch_mitigations": "0x0000000000000feb",
        "current_mitigations": "0x0000000000000feb"
    });
    let facts: PlatformFacts = serde_json::from_value(stored.clone()).unwrap();
    assert_eq!(facts, gcp().facts());
    assert_eq!(serde_json::to_value(facts).unwrap(), stored);
    // A version 2 report carries no CPUID.
    let version_2 = case("go-sev-guest").inputs();
    let facts = Report::parse(&version_2.report).unwrap().facts();
    let written = serde_json::to_value(facts).unwrap();
    assert!(written.get("cpuid").is_none());
    assert_eq!(
        serde_json::from_value::<PlatformFacts>(written).unwrap(),
        facts
    );
}

#[test]
fn the_readme_policy_is_valid() {
    let readme = include_str!("../../README.md");
    let (_, rest) = readme.split_once("```json").unwrap();
    let (example, _) = rest.split_once("```").unwrap();
    let example = example.replace("<96 lowercase hexadecimal digits>", &"ab".repeat(48));
    let policy: Policy = serde_json::from_str(&example).unwrap();
    policy.validate().unwrap();
    assert_eq!(policy.measurements, vec![[0xab; 48]]);
    assert_eq!(policy.guest_policy.minimum_abi, Some((1, 55)));
    assert_eq!(policy.platforms[0].product, Some(Product::Milan));
    assert!(policy.require_crl);
}

#[test]
fn an_absent_guest_policy_rule_forbids_debugging_and_migration_agents() {
    let empty: Policy = serde_json::from_value(json!({})).unwrap();
    assert_eq!(empty, Policy::default());
    let rule: Policy = serde_json::from_value(json!({ "guest_policy": {} })).unwrap();
    assert_eq!(rule.guest_policy, GuestPolicyRule::default());
    assert_eq!(
        serde_json::to_value(Policy::default()).unwrap(),
        json!({
            "guest_policy": { "require": "0x0000000000000000", "forbid": "0x00000000000c0000" },
            "require_crl": false
        })
    );
}

#[test]
fn every_policy_field_reads_back_as_it_was_written() {
    let gcp = gcp();
    let report = gcp.report();
    let policy = Policy {
        report_data: Some(*report.report_data()),
        measurements: vec![*report.measurement()],
        host_data: Some(*report.host_data()),
        family_id: Some(*report.family_id()),
        image_id: Some(*report.image_id()),
        id_key_digests: vec![*report.id_key_digest()],
        author_key_digests: vec![*report.author_key_digest()],
        report_id: Some(*report.report_id()),
        report_id_ma: Some(*report.report_id_ma()),
        vmpl: Some(0),
        minimum_guest_svn: Some(0),
        guest_policy: GuestPolicyRule {
            exact: Some(0x3_0000),
            minimum_abi: Some((0, 0)),
            require: 1 << 16,
            forbid: 1 << 19,
        },
        platforms: vec![PlatformRule {
            product: Some(Product::Milan),
            cpuid_family: Some(0x19),
            cpuid_model: Some(0x01),
            cpuid_stepping: Some(0x01),
            chip_ids: vec![*report.chip_id()],
            minimum_tcb: Some(report.reported_tcb()),
            minimum_launch_tcb: Some(report.launch_tcb()),
            minimum_firmware_version: Some(report.committed_version()),
            permit_provisional_firmware: true,
            required_platform_info_mask: 0x24,
            forbidden_platform_info_mask: 0x2,
            required_launch_mitigation_mask: 0xb,
            required_current_mitigation_mask: 0xb,
        }],
        signers: vec![SigningKey::Vcek, SigningKey::Vlek],
        csp_ids: vec!["CN=cc-us-east-2.amazonaws.com".into()],
        require_crl: true,
    };
    let written = serde_json::to_value(&policy).unwrap();
    assert_eq!(written["report_data"], hex(report.report_data()));
    assert_eq!(written["platforms"][0]["chip_ids"][0], GCP_CHIP);
    assert_eq!(
        written["platforms"][0]["minimum_firmware_version"],
        json!([1, 58, 3])
    );
    assert_eq!(written["signers"], json!(["vcek", "vlek"]));
    assert_eq!(written["guest_policy"]["exact"], "0x0000000000030000");
    assert_eq!(written["guest_policy"]["minimum_abi"], json!([0, 0]));
    assert_eq!(serde_json::from_value::<Policy>(written).unwrap(), policy);
    assert!(policy.check(&gcp).is_ok());
}

#[test]
fn json_names_products_keys_and_versions() {
    for (product, name) in [
        (Product::Milan, "Milan"),
        (Product::Genoa, "Genoa"),
        (Product::Turin, "Turin"),
    ] {
        assert_eq!(serde_json::to_value(product).unwrap(), name);
        assert_eq!(name.parse::<Product>().unwrap(), product);
    }
    for name in ["Siena", "Bergamo", "Venice", "milan"] {
        rejects::<Product>(&json!(name));
        assert!(name.parse::<Product>().is_err());
    }
    assert_eq!(serde_json::to_value(SigningKey::None).unwrap(), "none");
    rejects::<SigningKey>(&json!("VCEK"));
    let version = FirmwareVersion {
        major: 1,
        minor: 58,
        build: 3,
    };
    assert_eq!(serde_json::to_value(version).unwrap(), json!([1, 58, 3]));
    assert_eq!(version.to_string(), "1.58.3");
    for invalid in [
        json!([1, 58]),
        json!([1, 58, 3, 0]),
        json!([256, 0, 0]),
        json!("1.58.3"),
    ] {
        rejects::<FirmwareVersion>(&invalid);
    }
    let turin = TcbVersion {
        fmc: Some(1),
        bootloader: 2,
        tee: 3,
        snp: 4,
        microcode: 5,
    };
    let written = serde_json::to_value(turin).unwrap();
    assert_eq!(
        written,
        json!({ "fmc": 1, "bootloader": 2, "tee": 3, "snp": 4, "microcode": 5 })
    );
    assert_eq!(
        serde_json::from_value::<TcbVersion>(written).unwrap(),
        turin
    );
    assert_eq!(
        serde_json::to_value(TcbVersion { fmc: None, ..turin }).unwrap(),
        json!({ "bootloader": 2, "tee": 3, "snp": 4, "microcode": 5 })
    );
    let validity = Validity {
        not_before: 1,
        not_after: 2,
    };
    assert_eq!(
        serde_json::to_value(validity).unwrap(),
        json!({ "not_before": 1, "not_after": 2 })
    );
}

#[test]
fn json_rejects_unknown_fields_and_inexact_encodings() {
    for policy in [
        json!({ "measurement": [] }),
        json!({ "guest_policy": { "allow": "0x0000000000000000" } }),
        json!({ "platforms": [{ "products": "Milan" }] }),
        json!({ "platforms": [{ "minimum_tcb": { "bootloader": 0, "tee": 0, "snp": 0, "microcode": 0, "spl4": 0 } }] }),
        // Masks are 0x and 16 lowercase digits.
        json!({ "guest_policy": { "forbid": "0xc0000" } }),
        json!({ "guest_policy": { "forbid": "0X00000000000C0000" } }),
        json!({ "guest_policy": { "forbid": "0x00000000000C0000" } }),
        json!({ "guest_policy": { "forbid": "00000000000c000000" } }),
        json!({ "guest_policy": { "forbid": 786_432 } }),
        json!({ "platforms": [{ "required_platform_info_mask": "0x+000000000000024" }] }),
        // Byte fields are lowercase hexadecimal of their exact length.
        json!({ "host_data": "AB".repeat(32) }),
        json!({ "host_data": "ab".repeat(31) }),
        json!({ "host_data": "ab".repeat(33) }),
        json!({ "measurements": ["ab".repeat(47)] }),
        json!({ "measurements": "ab".repeat(48) }),
        json!({ "platforms": [{ "chip_ids": [GCP_CHIP.to_uppercase()] }] }),
        json!({ "vmpl": -1 }),
        json!({ "signers": ["VCEK"] }),
    ] {
        rejects::<Policy>(&policy);
    }
    let facts = serde_json::to_value(gcp().facts()).unwrap();
    for field in [
        "report_version",
        "current_tcb",
        "platform_info",
        "current_mitigations",
    ] {
        let mut missing = facts.clone();
        missing.as_object_mut().unwrap().remove(field);
        rejects::<PlatformFacts>(&missing);
    }
    let mut extra = facts;
    extra["chip_id"] = json!(GCP_CHIP);
    rejects::<PlatformFacts>(&extra);
}

#[test]
fn a_report_writes_every_field() {
    let gcp = gcp();
    let written = serde_json::to_value(gcp.report()).unwrap();
    let tcb = json!({ "bootloader": 4, "tee": 0, "snp": 31, "microcode": 225 });
    assert_eq!(
        written,
        json!({
            "version": 5,
            "product": "Milan",
            "cpuid": [25, 1, 1],
            "guest_svn": 0,
            "guest_policy": "0x0000000000030000",
            "family_id": hex(gcp.report().family_id()),
            "image_id": hex(gcp.report().image_id()),
            "vmpl": 0,
            "current_tcb": tcb,
            "platform_info": "0x0000000000000025",
            "author_key_enabled": false,
            "mask_chip_key": false,
            "signing_key": "vcek",
            "report_data": hex(&core::array::from_fn::<u8, 64, _>(|index| u8::try_from(index).unwrap())),
            "measurement": hex(gcp.report().measurement()),
            "host_data": "00".repeat(32),
            "id_key_digest": "00".repeat(48),
            "author_key_digest": "00".repeat(48),
            "report_id": hex(gcp.report().report_id()),
            "report_id_ma": "ff".repeat(32),
            "reported_tcb": tcb,
            "chip_id": GCP_CHIP,
            "committed_tcb": tcb,
            "current_version": [1, 58, 3],
            "committed_version": [1, 58, 3],
            "launch_tcb": tcb,
            "launch_mitigations": "0x0000000000000feb",
            "current_mitigations": "0x0000000000000feb"
        })
    );
    let version_2 = Report::parse(&case("virtee-sev").inputs().report).unwrap();
    let written = serde_json::to_value(&version_2).unwrap();
    for field in [
        "product",
        "cpuid",
        "launch_mitigations",
        "current_mitigations",
    ] {
        assert_eq!(written[field], Value::Null, "{field}");
    }
}

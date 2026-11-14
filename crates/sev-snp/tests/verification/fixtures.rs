use std::path::Path;

use stogas_sev_snp::{
    CertificateTable, Endorsements, GuestPolicyRule, Policy, Product, Report, SigningKey,
};

/// 2026-11-14T00:00:00Z, when every current certificate and AMD CRL among the fixtures is valid.
pub const NOW: u64 = 1_794_614_400;
/// 2025-06-01T00:00:00Z, when the VLEK in the `trustee` fixtures was valid.
pub const JUNE_2025: u64 = 1_748_736_000;

pub fn read(path: &str) -> Vec<u8> {
    let path = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../tests/fixtures/sev-snp")
        .join(path);
    std::fs::read(&path).unwrap_or_else(|error| panic!("{}: {error}", path.display()))
}

pub fn hex(bytes: &[u8]) -> String {
    bytes
        .iter()
        .flat_map(|byte| [byte >> 4, byte & 0xf])
        .map(|nibble| char::from_digit(u32::from(nibble), 16).unwrap())
        .collect()
}

pub fn unhex(text: &str) -> Vec<u8> {
    (0..text.len())
        .step_by(2)
        .map(|index| u8::from_str_radix(&text[index..index + 2], 16).unwrap())
        .collect()
}

/// A policy that admits every guest policy, for cases about endorsements rather than guests.
pub fn permissive() -> Policy {
    Policy {
        guest_policy: GuestPolicyRule {
            forbid: 0,
            ..GuestPolicyRule::default()
        },
        ..Policy::default()
    }
}

/// Where a case's VCEK or VLEK comes from.
pub enum Leaf {
    /// The host's certificate table, whose ASK the case also uses.
    Table(&'static str),
    File(&'static str),
}

/// A report and the certificate that signed it, with facts that an independent implementation
/// read from them.
pub struct Case {
    pub name: String,
    pub report: String,
    pub leaf: Leaf,
    pub crl: Option<&'static str>,
    pub time: u64,
    pub product: Product,
    pub signing_key: SigningKey,
    pub version: u32,
    pub cpuid: Option<[u8; 3]>,
    pub vmpl: u32,
    /// The reported TCB, as the report stores it.
    pub reported_tcb: &'static str,
}

pub struct Inputs {
    pub report: Vec<u8>,
    pub leaf: Vec<u8>,
    pub intermediate: Option<Vec<u8>>,
    pub crl: Option<Vec<u8>>,
}

impl Inputs {
    pub fn endorsements(&self) -> Endorsements<'_> {
        Endorsements {
            leaf: &self.leaf,
            intermediate: self.intermediate.as_deref(),
            crl: self.crl.as_deref(),
        }
    }
}

impl Case {
    pub fn inputs(&self) -> Inputs {
        let report = read(&self.report);
        let (leaf, intermediate) = match self.leaf {
            Leaf::File(path) => (read(path), None),
            Leaf::Table(path) => {
                let table = read(path);
                let signing_key = Report::parse(&report).unwrap().signing_key();
                let endorsements = CertificateTable::parse(&table)
                    .unwrap()
                    .endorsements(signing_key)
                    .unwrap();
                (
                    endorsements.leaf.to_vec(),
                    endorsements.intermediate.map(<[u8]>::to_vec),
                )
            }
        };
        Inputs {
            report,
            leaf,
            intermediate,
            crl: self.crl.map(read),
        }
    }
}

pub fn case(name: &str) -> Case {
    cases()
        .into_iter()
        .find(|case| case.name == name)
        .unwrap_or_else(|| panic!("no case {name}"))
}

const MILAN: Option<[u8; 3]> = Some([0x19, 0x01, 0x01]);

#[allow(
    clippy::too_many_lines,
    reason = "A table of every signed report among the fixtures."
)]
pub fn cases() -> Vec<Case> {
    let mut cases = Vec::new();
    for vmpl in 0..4 {
        cases.push(Case {
            name: format!("aws-milan-vmpl{vmpl}"),
            report: format!("aws-milan/report-vmpl{vmpl}.bin"),
            leaf: Leaf::Table("aws-milan/certificates.bin"),
            crl: Some("amd-kds/milan.crl"),
            time: NOW,
            product: Product::Milan,
            signing_key: SigningKey::Vlek,
            version: 5,
            cpuid: MILAN,
            vmpl,
            reported_tcb: "0400000000001fe1",
        });
        cases.push(Case {
            name: format!("gcp-milan-vmpl{vmpl}"),
            report: format!("gcp-milan/report-vmpl{vmpl}.bin"),
            leaf: Leaf::Table("gcp-milan/certificates.bin"),
            crl: Some("amd-kds/milan.crl"),
            time: NOW,
            product: Product::Milan,
            signing_key: SigningKey::Vcek,
            version: 5,
            cpuid: MILAN,
            vmpl,
            reported_tcb: "0400000000001fe1",
        });
    }
    let file = |name: &str,
                report: &'static str,
                leaf: &'static str,
                product: Product,
                version: u32,
                cpuid: Option<[u8; 3]>,
                reported_tcb: &'static str| Case {
        name: name.into(),
        report: report.into(),
        leaf: Leaf::File(leaf),
        crl: Some(match product {
            Product::Genoa => "amd-kds/genoa.crl",
            _ => "amd-kds/milan.crl",
        }),
        time: NOW,
        product,
        signing_key: SigningKey::Vcek,
        version,
        cpuid,
        vmpl: 0,
        reported_tcb,
    };
    cases.extend([
        file(
            "azure-genoa",
            "azure-genoa/report.bin",
            "azure-genoa/vcek.der",
            Product::Genoa,
            3,
            Some([0x19, 0x11, 0x01]),
            "0a00000000001754",
        ),
        file(
            "go-sev-guest",
            "go-sev-guest/report.bin",
            "go-sev-guest/vcek.der",
            Product::Milan,
            2,
            None,
            "0200000000000544",
        ),
        file(
            "virtee-sev",
            "virtee-sev/report.bin",
            "virtee-sev/vcek.der",
            Product::Milan,
            2,
            None,
            "0300000000000873",
        ),
        file(
            "trustee",
            "trustee/report.bin",
            "trustee/vcek.der",
            Product::Milan,
            2,
            None,
            "0300000000000873",
        ),
        file(
            "trustee-azure-genoa",
            "trustee/azure-genoa-report.bin",
            "trustee/azure-genoa-vcek.der",
            Product::Genoa,
            3,
            Some([0x19, 0x11, 0x01]),
            "0a00000000001754",
        ),
        file(
            "attestation-rs-siena",
            "attestation-rs/siena-report.bin",
            "attestation-rs/siena-vcek.der",
            Product::Genoa,
            5,
            Some([0x19, 0xa0, 0x02]),
            "0a00000000001b1b",
        ),
        file(
            "attestation-rs-azure-genoa",
            "attestation-rs/azure-genoa-report.bin",
            "attestation-rs/azure-genoa-vcek.der",
            Product::Genoa,
            5,
            Some([0x19, 0x11, 0x01]),
            "0c00000000001c58",
        ),
        file(
            "automata-gcp",
            "automata/gcp-report.bin",
            "automata/gcp-vcek.der",
            Product::Milan,
            4,
            MILAN,
            "04000000000019db",
        ),
        file(
            "automata-azure",
            "automata/azure-report.bin",
            "automata/azure-vcek.der",
            Product::Milan,
            3,
            MILAN,
            "04000000000018db",
        ),
    ]);
    cases.push(Case {
        name: "trustee-aws-vlek".into(),
        report: "trustee/vlek-report.bin".into(),
        leaf: Leaf::File("trustee/vlek.der"),
        crl: None,
        time: JUNE_2025,
        product: Product::Milan,
        signing_key: SigningKey::Vlek,
        version: 3,
        cpuid: MILAN,
        vmpl: 1,
        reported_tcb: "04000000000018d9",
    });
    cases
}

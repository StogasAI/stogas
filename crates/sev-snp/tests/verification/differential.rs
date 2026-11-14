//! The `sev` crate, the most used Rust implementation, as an independent one. It parses reports
//! and verifies signatures and certificate chains, but leaves reserved bytes, bindings and policy
//! to its callers, so this crate may reject what it accepts, never the reverse.

use sev::certs::snp::{Certificate, Chain, Verifiable as _, builtin, ca};
use sev::firmware::guest::AttestationReport;
use sev::firmware::host::TcbVersion as SevTcb;
use sev::parser::ByteParser as _;
use stogas_sev_snp::{Endorsement, ErrorKind, Product, Report, SigningKey, TcbVersion};

use crate::fixtures::{case, cases};

struct Roots {
    product: Product,
    ark: &'static [u8],
    ask: &'static [u8],
    asvk: &'static [u8],
}

const ROOTS: [Roots; 3] = [
    Roots {
        product: Product::Milan,
        ark: include_bytes!("../../src/amd/milan-ark.der"),
        ask: include_bytes!("../../src/amd/milan-ask.der"),
        asvk: include_bytes!("../../src/amd/milan-asvk.der"),
    },
    Roots {
        product: Product::Genoa,
        ark: include_bytes!("../../src/amd/genoa-ark.der"),
        ask: include_bytes!("../../src/amd/genoa-ask.der"),
        asvk: include_bytes!("../../src/amd/genoa-asvk.der"),
    },
    Roots {
        product: Product::Turin,
        ark: include_bytes!("../../src/amd/turin-ark.der"),
        ask: include_bytes!("../../src/amd/turin-ask.der"),
        asvk: include_bytes!("../../src/amd/turin-asvk.der"),
    },
];

const fn tcb(theirs: SevTcb) -> TcbVersion {
    TcbVersion {
        fmc: theirs.fmc,
        bootloader: theirs.bootloader.unwrap(),
        tee: theirs.tee,
        snp: theirs.snp,
        microcode: theirs.microcode.unwrap(),
    }
}

#[test]
fn both_implementations_hold_the_same_amd_roots() {
    for roots in ROOTS {
        let theirs = match roots.product {
            Product::Milan => [builtin::milan::ark(), builtin::milan::ask()],
            Product::Genoa => [builtin::genoa::ark(), builtin::genoa::ask()],
            Product::Turin => [builtin::turin::ark(), builtin::turin::ask()],
        };
        for (theirs, ours) in theirs.into_iter().zip([roots.ark, roots.ask]) {
            assert_eq!(theirs.unwrap().to_der().unwrap(), ours, "{}", roots.product);
        }
    }
}

#[test]
fn both_parsers_read_every_field_alike() {
    for case in cases() {
        let inputs = case.inputs();
        let ours = Report::parse(&inputs.report).unwrap();
        let theirs = AttestationReport::from_bytes(&inputs.report).unwrap();
        let name = &case.name;
        assert_eq!(theirs.version, ours.version(), "{name}");
        assert_eq!(theirs.guest_svn, ours.guest_svn(), "{name}");
        assert_eq!(u64::from(theirs.policy), ours.guest_policy(), "{name}");
        assert_eq!(&theirs.family_id, ours.family_id(), "{name}");
        assert_eq!(&theirs.image_id, ours.image_id(), "{name}");
        assert_eq!(theirs.vmpl, ours.vmpl(), "{name}");
        assert_eq!(theirs.sig_algo, 1, "{name}");
        assert_eq!(tcb(theirs.current_tcb), ours.current_tcb(), "{name}");
        assert_eq!(u64::from(theirs.plat_info), ours.platform_info(), "{name}");
        let key_info = u32::from(theirs.key_info);
        assert_eq!(key_info & 1 != 0, ours.author_key_enabled(), "{name}");
        assert_eq!(key_info & 2 != 0, ours.mask_chip_key(), "{name}");
        let signing_key = match (key_info >> 2) & 7 {
            0 => SigningKey::Vcek,
            1 => SigningKey::Vlek,
            _ => SigningKey::None,
        };
        assert_eq!(signing_key, ours.signing_key(), "{name}");
        assert_eq!(&theirs.report_data, ours.report_data(), "{name}");
        assert_eq!(&theirs.measurement, ours.measurement(), "{name}");
        assert_eq!(&theirs.host_data, ours.host_data(), "{name}");
        assert_eq!(&theirs.id_key_digest, ours.id_key_digest(), "{name}");
        assert_eq!(
            &theirs.author_key_digest,
            ours.author_key_digest(),
            "{name}"
        );
        assert_eq!(&theirs.report_id, ours.report_id(), "{name}");
        assert_eq!(&theirs.report_id_ma, ours.report_id_ma(), "{name}");
        assert_eq!(tcb(theirs.reported_tcb), ours.reported_tcb(), "{name}");
        let cpuid = theirs.cpuid_fam_id.map(|family| {
            [
                family,
                theirs.cpuid_mod_id.unwrap(),
                theirs.cpuid_step.unwrap(),
            ]
        });
        assert_eq!(cpuid, ours.cpuid(), "{name}");
        assert_eq!(&theirs.chip_id, ours.chip_id(), "{name}");
        assert_eq!(tcb(theirs.committed_tcb), ours.committed_tcb(), "{name}");
        for (theirs, ours) in [
            (theirs.current, ours.current_version()),
            (theirs.committed, ours.committed_version()),
        ] {
            assert_eq!(
                (theirs.major, theirs.minor, theirs.build),
                (ours.major, ours.minor, ours.build),
                "{name}"
            );
        }
        assert_eq!(tcb(theirs.launch_tcb), ours.launch_tcb(), "{name}");
        assert_eq!(
            theirs.launch_mit_vector,
            ours.launch_mitigations(),
            "{name}"
        );
        assert_eq!(
            theirs.current_mit_vector,
            ours.current_mitigations(),
            "{name}"
        );
    }
}

#[test]
fn both_verify_every_chain_and_signature() {
    for case in cases() {
        let inputs = case.inputs();
        let roots = ROOTS
            .into_iter()
            .find(|roots| roots.product == case.product)
            .unwrap();
        let default = match case.signing_key {
            SigningKey::Vlek => roots.asvk,
            _ => roots.ask,
        };
        let chain = Chain {
            ca: ca::Chain {
                ark: Certificate::from_der(roots.ark).unwrap(),
                ask: Certificate::from_der(inputs.intermediate.as_deref().unwrap_or(default))
                    .unwrap(),
            },
            vek: Certificate::from_der(&inputs.leaf).unwrap(),
        };
        let vek = (&chain).verify().unwrap();
        let report = AttestationReport::from_bytes(&inputs.report).unwrap();
        (vek, &report).verify().unwrap();
        let endorsement =
            Endorsement::verify(&inputs.leaf, inputs.intermediate.as_deref()).unwrap();
        endorsement
            .verify_report(Report::parse(&inputs.report).unwrap())
            .unwrap();
    }
}

/// A change that the `sev` crate accepts breaks only bytes that it ignores: reserved bytes, which
/// it writes as zeros before it checks the signature, and the unused high bytes of R and S.
#[test]
fn this_crate_also_rejects_changes_that_the_sev_crate_misses() {
    for name in [
        "gcp-milan-vmpl0",
        "aws-milan-vmpl1",
        "virtee-sev",
        "attestation-rs-siena",
    ] {
        let inputs = case(name).inputs();
        let endorsement =
            Endorsement::verify(&inputs.leaf, inputs.intermediate.as_deref()).unwrap();
        let vek = Certificate::from_der(&inputs.leaf).unwrap();
        let mut stricter = 0;
        for offset in (0..inputs.report.len()).step_by(7) {
            let mut changed = inputs.report.clone();
            changed[offset] ^= 0x01;
            let ours = Report::parse(&changed).and_then(|report| endorsement.verify_report(report));
            let theirs = AttestationReport::from_bytes(&changed)
                .is_ok_and(|report| (&vek, &report).verify().is_ok());
            let kind = ours.unwrap_err().kind();
            if theirs {
                assert_eq!(kind, ErrorKind::Report, "{name} {offset:#x}");
                stricter += 1;
            }
        }
        // The `sev` crate misses changes to reserved bytes, which this crate rejects.
        assert!(stricter > 0, "{name}");
    }
}

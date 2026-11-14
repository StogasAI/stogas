#![no_main]
//! SEV-SNP parsing and verification. The first byte picks the input: a report, a certificate
//! table or a CRL, each as raw bytes or as changes to a real one, or a policy in JSON. A report
//! that this crate parses must read the same in the `sev` crate whenever that one parses it.

use std::sync::LazyLock;

use libfuzzer_sys::fuzz_target;
use sev::firmware::guest::AttestationReport;
use sev::parser::ByteParser as _;
use stogas_sev_snp::{
    CertificateTable, Crl, Endorsement, Endorsements, GuestPolicyRule, PlatformFacts, PlatformRule,
    Policy, Report, SigningKey, TcbVersion, Verified, verify,
};

const REPORT: &[u8] = include_bytes!("../../tests/fixtures/sev-snp/gcp-milan/report-vmpl0.bin");
const TABLE: &[u8] = include_bytes!("../../tests/fixtures/sev-snp/gcp-milan/certificates.bin");
const CRL: &[u8] = include_bytes!("../../tests/fixtures/sev-snp/amd-kds/milan.crl");
/// 2026-11-14, when the fixtures are valid.
const NOW: u64 = 1_794_614_400;

static ENDORSEMENTS: LazyLock<Endorsements<'static>> = LazyLock::new(|| {
    let table = CertificateTable::parse(TABLE).unwrap();
    Endorsements {
        crl: Some(CRL),
        ..table.endorsements(SigningKey::Vcek).unwrap()
    }
});
static ENDORSEMENT: LazyLock<Endorsement> =
    LazyLock::new(|| Endorsement::verify(ENDORSEMENTS.leaf, ENDORSEMENTS.intermediate).unwrap());
static PERMISSIVE: LazyLock<Policy> = LazyLock::new(|| Policy {
    guest_policy: GuestPolicyRule {
        forbid: 0,
        ..GuestPolicyRule::default()
    },
    ..Policy::default()
});
static VERIFIED: LazyLock<Verified> =
    LazyLock::new(|| verify(REPORT, &ENDORSEMENTS, &PERMISSIVE, NOW).unwrap());

fuzz_target!(|data: &[u8]| {
    let Some((&selector, rest)) = data.split_first() else {
        return;
    };
    match selector % 7 {
        0 => report(rest),
        1 => report(&mutate(REPORT, rest)),
        2 => table(rest),
        3 => table(&mutate(TABLE, rest)),
        4 => crl(rest),
        5 => crl(&mutate(CRL, rest)),
        _ => policy(rest),
    }
});

/// The fixture with each 3 bytes of `data` setting one byte: a 2-byte offset, then the value.
fn mutate(fixture: &[u8], data: &[u8]) -> Vec<u8> {
    let mut candidate = fixture.to_vec();
    for change in data.chunks_exact(3) {
        let offset = usize::from(u16::from_be_bytes([change[0], change[1]])) % candidate.len();
        candidate[offset] = change[2];
    }
    candidate
}

fn report(bytes: &[u8]) {
    let _ = verify(bytes, &ENDORSEMENTS, &PERMISSIVE, NOW);
    let Ok(ours) = Report::parse(bytes) else {
        return;
    };
    serde_json::to_vec(&ours).unwrap();
    let facts = ours.facts();
    let written = serde_json::to_vec(&facts).unwrap();
    assert_eq!(
        serde_json::from_slice::<PlatformFacts>(&written).unwrap(),
        facts
    );
    let _ = ENDORSEMENT.verify_report(ours.clone());
    if let Ok(theirs) = AttestationReport::from_bytes(bytes) {
        compare(&ours, &theirs);
    }
}

fn tcb(theirs: sev::firmware::host::TcbVersion) -> Option<TcbVersion> {
    Some(TcbVersion {
        fmc: theirs.fmc,
        bootloader: theirs.bootloader?,
        tee: theirs.tee,
        snp: theirs.snp,
        microcode: theirs.microcode?,
    })
}

fn compare(ours: &Report, theirs: &AttestationReport) {
    assert_eq!(ours.version(), theirs.version);
    assert_eq!(ours.guest_svn(), theirs.guest_svn);
    assert_eq!(ours.guest_policy(), u64::from(theirs.policy));
    assert_eq!(ours.vmpl(), theirs.vmpl);
    assert_eq!(ours.platform_info(), u64::from(theirs.plat_info));
    assert_eq!(ours.report_data(), &theirs.report_data);
    assert_eq!(ours.measurement(), &theirs.measurement);
    assert_eq!(ours.chip_id(), &theirs.chip_id);
    assert_eq!(ours.report_id_ma(), &theirs.report_id_ma);
    assert_eq!(ours.current_mitigations(), theirs.current_mit_vector);
    let version = ours.current_version();
    assert_eq!(
        (version.major, version.minor, version.build),
        (
            theirs.current.major,
            theirs.current.minor,
            theirs.current.build
        )
    );
    // The `sev` crate guesses a version 2 report's TCB layout from its chip ID, but only Milan
    // and Genoa firmware wrote version 2.
    if ours.version() >= 3 {
        assert_eq!(Some(ours.current_tcb()), tcb(theirs.current_tcb));
        assert_eq!(Some(ours.reported_tcb()), tcb(theirs.reported_tcb));
        assert_eq!(Some(ours.committed_tcb()), tcb(theirs.committed_tcb));
        assert_eq!(Some(ours.launch_tcb()), tcb(theirs.launch_tcb));
        let cpuid = [theirs.cpuid_fam_id, theirs.cpuid_mod_id, theirs.cpuid_step];
        assert_eq!(ours.cpuid().map(|cpuid| cpuid.map(Some)), Some(cpuid));
    }
}

fn table(bytes: &[u8]) {
    let Ok(table) = CertificateTable::parse(bytes) else {
        return;
    };
    for key in [SigningKey::Vcek, SigningKey::Vlek] {
        if let Ok(endorsements) = table.endorsements(key) {
            let _ = Endorsement::verify(endorsements.leaf, endorsements.intermediate);
        }
    }
}

fn crl(bytes: &[u8]) {
    if let Ok(crl) = Crl::verify(bytes) {
        let _ = crl.is_revoked(ENDORSEMENT.intermediate_serial());
    }
}

fn policy(json: &[u8]) {
    if let Ok(policy) = serde_json::from_slice::<Policy>(json) {
        let _ = policy.check(&VERIFIED);
        let written = serde_json::to_vec(&policy).unwrap();
        assert_eq!(serde_json::from_slice::<Policy>(&written).unwrap(), policy);
    }
    if let Ok(rules) = serde_json::from_slice::<Vec<PlatformRule>>(json) {
        let report = VERIFIED.report();
        let _ = PlatformRule::find(
            &rules,
            VERIFIED.product(),
            report.chip_id(),
            &report.facts(),
        );
    }
}

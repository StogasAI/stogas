//! Deterministic, networkless verification for Stogas confidential bundles.

pub(crate) use stogas_offline_sigstore::strict_json;
mod kem;
mod types;

pub mod approvals;
pub mod attestation;
pub mod channel;
pub mod evidence;
#[cfg(feature = "gateway")]
pub mod gateway;
#[cfg(feature = "snp")]
pub mod receipt;
pub mod sdk_release;
pub mod secret_release;
pub mod signing;
pub use types::*;

use base64::{
    Engine as _,
    engine::general_purpose::{STANDARD, URL_SAFE_NO_PAD},
};
#[cfg(any(feature = "snp", all(test, feature = "staging")))]
use chrono::{DateTime, Utc};
#[cfg(feature = "snp")]
use p256::ecdsa::{
    Signature as P256Signature, VerifyingKey as P256VerifyingKey, signature::Verifier as _,
};
#[cfg(feature = "staging")]
use serde::Deserialize;
use serde_json::Value;
use sha2::{Digest, Sha256};
#[cfg(any(feature = "snp", feature = "staging"))]
use std::collections::BTreeMap;
#[cfg(feature = "snp")]
use std::collections::BTreeSet;
use stogas_offline_sigstore::{GithubPolicy, Subject, TrustedRoot, verify_github_attestation};
use thiserror::Error;
#[cfg(feature = "snp")]
use x509_parser::{
    cri_attributes::ParsedCriAttribute,
    oid_registry::{OID_EC_P256, OID_KEY_TYPE_EC_PUBLIC_KEY, OID_SIG_ECDSA_WITH_SHA256},
    prelude::{
        FromDer as _, GeneralName, ParsedExtension, X509CertificationRequest,
        X509CertificationRequestInfo, X509Version,
    },
};

/// Maximum serialized evidence accepted by public adapters.
pub const MAX_INPUT_BYTES: usize = 16 * 1024 * 1024;
const MAX_NODES: usize = 1_024;
/// Release sequences stay exact in every JSON consumer.
const MAX_SAFE_INTEGER: u64 = 9_007_199_254_740_991;
#[cfg(feature = "snp")]
const MAX_VENDOR_COLLATERAL: usize = 4_096;
#[cfg(feature = "snp")]
const MAX_CLOCK_SKEW_MS: i64 = 60_000;
const SNP_POLICY_PAGE_SWAP_DISABLE: u64 = 1 << 25;
const SNP_POLICY_MEM_AES_256_XTS: u64 = 1 << 22;
const SNP_POLICY_CXL_ALLOW: u64 = 1 << 21;
const SNP_POLICY_SINGLE_SOCKET: u64 = 1 << 20;
const SNP_POLICY_DEBUG: u64 = 1 << 19;
const SNP_POLICY_MIGRATE_MA: u64 = 1 << 18;
const SNP_POLICY_RESERVED_MUST_BE_ONE: u64 = 1 << 17;
const SNP_POLICY_COMMON_REQUIRED: u64 =
    SNP_POLICY_PAGE_SWAP_DISABLE | SNP_POLICY_SINGLE_SOCKET | SNP_POLICY_RESERVED_MUST_BE_ONE;
const SNP_POLICY_COMMON_FORBIDDEN: u64 =
    SNP_POLICY_CXL_ALLOW | SNP_POLICY_DEBUG | SNP_POLICY_MIGRATE_MA;
#[cfg(feature = "staging")]
const STAGING_PROVENANCE_TYPE: &str = "https://stogas.ai/attestations/staging-development/v1";
const STOGAS_SIGNATURE_DOMAIN: &[u8] = b"stogas signed document v1\n";
const BUNDLE_ENVELOPE_SCHEMA: &str = "stogas.confidential-bundle-envelope.v1";
const SNP_PLATFORM_INFO_KNOWN_MASK: u64 = 0xbf;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum AmdTcbLayout {
    Family19h,
    Family1ah,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct AmdProductProfile {
    product_name: &'static str,
    root_spki_sha384: &'static str,
    struct_version: u8,
    tcb_layout: AmdTcbLayout,
    minimum_policy_abi: (u8, u8),
    required_policy_bits: u64,
}

// AMD publication 57230 product policy. Future products remain fail-closed until their CPUID
// range, KDS name, certificate layout, and pinned ARK are added together here.
const AMD_PRODUCT_PROFILES: [AmdProductProfile; 4] = [
    AmdProductProfile {
        product_name: "Milan",
        root_spki_sha384: "1249f67f15cf229a4069195e1a9ce537d1765ef706a1f4a123c36be9518786515d25ecc007f366b564d2b3f31c48082e",
        struct_version: 0,
        tcb_layout: AmdTcbLayout::Family19h,
        minimum_policy_abi: (1, 58),
        required_policy_bits: 0,
    },
    AmdProductProfile {
        product_name: "Genoa",
        root_spki_sha384: "32ab53a6ce5ec14926207396e5c475ae768a6a9831b7e860b5acf2e1c1dff222bc5a8bfc43eb5e06393189c1f246d880",
        struct_version: 0,
        tcb_layout: AmdTcbLayout::Family19h,
        minimum_policy_abi: (1, 58),
        required_policy_bits: SNP_POLICY_MEM_AES_256_XTS,
    },
    AmdProductProfile {
        product_name: "Siena",
        root_spki_sha384: "32ab53a6ce5ec14926207396e5c475ae768a6a9831b7e860b5acf2e1c1dff222bc5a8bfc43eb5e06393189c1f246d880",
        struct_version: 0,
        tcb_layout: AmdTcbLayout::Family19h,
        minimum_policy_abi: (1, 58),
        required_policy_bits: SNP_POLICY_MEM_AES_256_XTS,
    },
    AmdProductProfile {
        product_name: "Turin",
        root_spki_sha384: "3475f08a9727f8ac9a1deaea5f2a2097aa59d64d05c2a678c229c873e6359d3a6926287a2a22cd5f88a385e333a2fcc5",
        struct_version: 1,
        tcb_layout: AmdTcbLayout::Family1ah,
        minimum_policy_abi: (1, 58),
        required_policy_bits: SNP_POLICY_MEM_AES_256_XTS,
    },
];

fn validate_snp_launch_policy(policy: u64, product: &AmdProductProfile) -> Result<(), Error> {
    if policy >> 26 != 0 {
        return Err(Error::Node(
            "authorized SNP launch policy sets reserved high bits".into(),
        ));
    }
    let required = SNP_POLICY_COMMON_REQUIRED | product.required_policy_bits;
    if policy & required != required {
        return Err(Error::Node(format!(
            "authorized SNP launch policy lacks required {} protections",
            product.product_name
        )));
    }
    if policy & SNP_POLICY_COMMON_FORBIDDEN != 0 {
        return Err(Error::Node(
            "authorized SNP launch policy permits CXL, debugging, or migration".into(),
        ));
    }
    let minimum_abi = product.minimum_policy_abi;
    let policy_abi = (((policy >> 8) & 0xff) as u8, (policy & 0xff) as u8);
    if policy_abi < minimum_abi {
        return Err(Error::Node(format!(
            "authorized SNP launch policy ABI {}.{} is older than required {}.{}",
            policy_abi.0, policy_abi.1, minimum_abi.0, minimum_abi.1
        )));
    }
    Ok(())
}

fn amd_product_from_cpuid(family: u8, model: u8) -> Option<&'static AmdProductProfile> {
    let extended_model = model >> 4;
    let product_name = match (family, extended_model) {
        (0x19, 0x0) => "Milan",
        (0x19, 0x1) => "Genoa",
        (0x19, 0xa) => "Siena",
        (0x1a, 0x0 | 0x1) => "Turin",
        _ => return None,
    };
    AMD_PRODUCT_PROFILES
        .iter()
        .find(|profile| profile.product_name == product_name)
}

type InspectedReportProduct = (
    Option<u8>,
    Option<u8>,
    Option<u8>,
    Option<&'static AmdProductProfile>,
);

fn inspect_report_product(
    report: &[u8],
    report_version: u32,
) -> Result<InspectedReportProduct, Error> {
    if report_version == 2 {
        if report[0x1a8..0x1e0].iter().all(|byte| *byte == 0)
            && report[0x1a0..0x1a8].iter().any(|byte| *byte != 0)
        {
            return Err(Error::Node(
                "Family 1Ah-shaped CHIP_ID requires a report with CPUID fields".into(),
            ));
        }
        return Ok((None, None, None, None));
    }

    let family = report[0x188];
    let model = report[0x189];
    let stepping = report[0x18a];
    let product = amd_product_from_cpuid(family, model)
        .ok_or_else(|| Error::Node("unsupported AMD processor family or model".into()))?;
    if product.tcb_layout == AmdTcbLayout::Family1ah && report_version < 5 {
        return Err(Error::Node(
            "Family 1Ah requires SNP attestation report version 5 or newer".into(),
        ));
    }
    Ok((Some(family), Some(model), Some(stepping), Some(product)))
}

#[cfg(feature = "staging")]
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct StagingDevelopmentProvenance {
    #[serde(rename = "_type")]
    statement_type: String,
    #[serde(rename = "predicateType")]
    predicate_type: String,
    predicate: StagingDevelopmentPredicate,
    subject: Vec<StagingDevelopmentSubject>,
}

#[cfg(feature = "staging")]
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct StagingDevelopmentPredicate {
    environment: String,
}

#[cfg(feature = "staging")]
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct StagingDevelopmentSubject {
    digest: BTreeMap<String, String>,
    name: String,
}

/// Failure to authenticate or appraise supplied evidence.
#[derive(Debug, Error)]
pub enum Error {
    #[error("bundle exceeds {MAX_INPUT_BYTES} bytes")]
    TooLarge,
    #[error("invalid bundle JSON: {0}")]
    InvalidJson(String),
    #[error("unsupported or invalid bundle: {0}")]
    InvalidBundle(String),
    #[error("bundle checksum failed: {0}")]
    BundleChecksum(String),
    #[error("release verification failed: {0}")]
    Release(String),
    #[error("node verification failed: {0}")]
    Node(String),
    #[error("response proof verification failed: {0}")]
    ResponseProof(String),
}

/// Read untrusted hardware selectors for collateral acquisition. This does not verify a report.
///
/// # Errors
/// Rejects an incorrect report length, unsupported version or invalid processor encoding.
pub fn inspect_snp_report(report: &[u8]) -> Result<InspectedSnpQuote, Error> {
    if report.len() != 0x4a0 {
        return Err(Error::Node("SNP report has the wrong size".into()));
    }
    let report_version = u32::from_le_bytes(report[0x00..0x04].try_into().unwrap_or_default());
    if !(2..=5).contains(&report_version) {
        return Err(Error::Node("unsupported SNP report version".into()));
    }
    let (cpuid_family, cpuid_model, cpuid_stepping, product_name) =
        inspect_report_product(report, report_version)?;
    Ok(InspectedSnpQuote {
        chip_id: hex::encode(&report[0x1a0..0x1e0]),
        cpuid_family,
        cpuid_model,
        cpuid_stepping,
        product_name: product_name.map(|profile| profile.product_name.into()),
        release_measurement: hex::encode(&report[0x90..0xc0]),
        report_version,
        reported_tcb: hex::encode(&report[0x180..0x188]),
    })
}
#[cfg(feature = "snp")]
fn verify_certificate_csr(
    csr_der: &[u8],
    expected_tls_spki_sha256: &str,
    expected_common_name: Option<&str>,
    expected_dns_names: Vec<String>,
) -> Result<(), Error> {
    if csr_der.is_empty() || csr_der.len() > 16 * 1024 {
        return Err(Error::Node("certificate CSR has an invalid length".into()));
    }
    let (remaining, csr) = X509CertificationRequest::from_der(csr_der)
        .map_err(|_| Error::Node("certificate CSR is not valid DER".into()))?;
    if !remaining.is_empty() || csr.as_raw().len() != csr_der.len() {
        return Err(Error::Node("certificate CSR contains trailing data".into()));
    }
    verify_certificate_csr_key_and_signature(&csr, expected_tls_spki_sha256)?;
    verify_certificate_csr_subject(&csr.certification_request_info, expected_common_name)?;
    verify_certificate_csr_dns_names(&csr, expected_dns_names)
}
#[cfg(feature = "snp")]
fn verify_certificate_csr_key_and_signature(
    csr: &X509CertificationRequest<'_>,
    expected_tls_spki_sha256: &str,
) -> Result<(), Error> {
    if csr.certification_request_info.version != X509Version::V1 {
        return Err(Error::Node(
            "certificate CSR must use PKCS #10 version 1".into(),
        ));
    }
    if csr.signature_algorithm.algorithm != OID_SIG_ECDSA_WITH_SHA256
        || csr.signature_algorithm.parameters().is_some()
        || csr.signature_value.unused_bits != 0
    {
        return Err(Error::Node(
            "certificate CSR must use canonical ECDSA with SHA-256".into(),
        ));
    }
    let spki = &csr.certification_request_info.subject_pki;
    if spki.algorithm.algorithm != OID_KEY_TYPE_EC_PUBLIC_KEY
        || spki
            .algorithm
            .parameters()
            .and_then(|parameters| parameters.as_oid().ok())
            .as_ref()
            != Some(&OID_EC_P256)
        || spki.subject_public_key.unused_bits != 0
    {
        return Err(Error::Node(
            "certificate CSR must contain a P-256 public key".into(),
        ));
    }
    let verifying_key = P256VerifyingKey::from_sec1_bytes(&spki.subject_public_key.data)
        .map_err(|_| Error::Node("certificate CSR P-256 public key is invalid".into()))?;
    let signature = P256Signature::from_der(&csr.signature_value.data)
        .map_err(|_| Error::Node("certificate CSR signature is not canonical DER".into()))?;
    verifying_key
        .verify(csr.certification_request_info.raw, &signature)
        .map_err(|_| Error::Node("certificate CSR proof of possession is invalid".into()))?;

    let derived_spki_sha256 = hex::encode(Sha256::digest(spki.raw));
    if derived_spki_sha256 != expected_tls_spki_sha256 {
        return Err(Error::Node(
            "certificate CSR SPKI does not match the attested node key".into(),
        ));
    }
    Ok(())
}
#[cfg(feature = "snp")]
fn verify_certificate_csr_subject(
    request_info: &X509CertificationRequestInfo<'_>,
    expected_common_name: Option<&str>,
) -> Result<(), Error> {
    let common_names = request_info
        .subject
        .iter_common_name()
        .map(|attribute| {
            attribute
                .as_str()
                .map(str::to_owned)
                .map_err(|_| Error::Node("certificate CSR common name is not UTF-8".into()))
        })
        .collect::<Result<Vec<_>, _>>()?;
    let expected_common_names = expected_common_name.into_iter().collect::<Vec<_>>();
    if common_names != expected_common_names {
        return Err(Error::Node(
            "certificate CSR common name differs from the certificate order".into(),
        ));
    }
    let subject_attribute_count = request_info
        .subject
        .iter()
        .flat_map(x509_parser::prelude::RelativeDistinguishedName::iter)
        .count();
    if subject_attribute_count != common_names.len() {
        return Err(Error::Node(
            "certificate CSR contains unexpected subject attributes".into(),
        ));
    }
    Ok(())
}
#[cfg(feature = "snp")]
fn verify_certificate_csr_dns_names(
    csr: &X509CertificationRequest<'_>,
    expected_dns_names: Vec<String>,
) -> Result<(), Error> {
    let mut dns_names = BTreeSet::new();
    let mut san_extensions = 0_u8;
    let [attribute] = csr.certification_request_info.attributes() else {
        return Err(Error::Node(
            "certificate CSR must contain exactly one extension-request attribute".into(),
        ));
    };
    let ParsedCriAttribute::ExtensionRequest(requested) = attribute.parsed_attribute() else {
        return Err(Error::Node(
            "certificate CSR contains an unexpected attribute".into(),
        ));
    };
    for extension in &requested.extensions {
        match extension.parsed_extension() {
            ParsedExtension::SubjectAlternativeName(san) => {
                san_extensions = san_extensions.saturating_add(1);
                for name in &san.general_names {
                    let GeneralName::DNSName(name) = name else {
                        return Err(Error::Node(
                            "certificate CSR SANs must contain only DNS names".into(),
                        ));
                    };
                    let normalized = name.trim().to_ascii_lowercase();
                    if normalized.is_empty() || !dns_names.insert(normalized) {
                        return Err(Error::Node(
                            "certificate CSR contains an empty or duplicate DNS SAN".into(),
                        ));
                    }
                }
            }
            _ => {
                return Err(Error::Node(
                    "certificate CSR contains an unexpected requested extension".into(),
                ));
            }
        }
    }
    if san_extensions != 1 {
        return Err(Error::Node(
            "certificate CSR must contain exactly one DNS SAN extension".into(),
        ));
    }
    let expected_dns_names = expected_dns_names
        .into_iter()
        .map(|name| name.trim().to_ascii_lowercase())
        .collect::<BTreeSet<_>>();
    if expected_dns_names.is_empty()
        || expected_dns_names.len() != dns_names.len()
        || expected_dns_names != dns_names
    {
        return Err(Error::Node(
            "certificate CSR DNS SANs differ from the certificate order".into(),
        ));
    }
    Ok(())
}

#[cfg(feature = "snp")]
fn verify_raw_snp_report_signature_with_vcek(
    report: &[u8],
    vcek_der: &[u8],
    node_id: &str,
) -> Result<(), Error> {
    use x509_parser::parse_x509_certificate;

    let (remaining, vcek) = parse_x509_certificate(vcek_der)
        .map_err(|error| Error::Node(format!("{node_id} AMD VCEK: {error}")))?;
    if !remaining.is_empty() {
        return Err(Error::Node(format!(
            "{node_id} AMD VCEK contains trailing data"
        )));
    }
    verify_raw_snp_report_signature(report, vcek.public_key().raw, node_id)
}

#[cfg(feature = "snp")]
fn verify_raw_snp_report_signature(
    report: &[u8],
    public_key_der: &[u8],
    label: &str,
) -> Result<(), Error> {
    use p384::{
        ecdsa::{Signature, VerifyingKey, signature::hazmat::PrehashVerifier as _},
        pkcs8::DecodePublicKey as _,
    };
    use sha2::Sha384;

    if report.len() != 0x4a0 {
        return Err(Error::Node(format!(
            "{label} SNP report has the wrong size"
        )));
    }
    let key = VerifyingKey::from_public_key_der(public_key_der)
        .map_err(|error| Error::Node(format!("{label} AMD report signing key: {error}")))?;
    let signature = &report[0x2a0..0x4a0];
    if signature[48..72].iter().any(|byte| *byte != 0)
        || signature[120..144].iter().any(|byte| *byte != 0)
        || signature[144..].iter().any(|byte| *byte != 0)
    {
        return Err(Error::Node(format!(
            "{label} SNP signature reserved bytes are nonzero"
        )));
    }
    let mut r = [0_u8; 48];
    let mut s = [0_u8; 48];
    for index in 0..48 {
        r[index] = signature[47 - index];
        s[index] = signature[72 + 47 - index];
    }
    let signature = Signature::from_scalars(r, s)
        .map_err(|error| Error::Node(format!("{label} SNP signature encoding: {error}")))?;
    let digest = Sha384::digest(&report[..0x2a0]);
    key.verify_prehash(&digest, &signature)
        .map_err(|error| Error::Node(format!("{label} SNP signature: {error}")))
}

fn verify_hardware_policy(policy: &HardwarePolicy) -> Result<VerifiedHardwarePolicy, Error> {
    let canonical = validate_hardware_policy(policy)?;
    let mut chip_ids = policy
        .policies
        .iter()
        .flat_map(|policy| policy.chip_ids.iter().cloned())
        .collect::<Vec<_>>();
    chip_ids.sort_unstable();
    chip_ids.dedup();
    Ok(VerifiedHardwarePolicy {
        chip_ids,
        policy_count: policy.policies.len(),
        sha256: hex::encode(Sha256::digest(canonical.as_bytes())),
    })
}

fn validate_hardware_policy(policy: &HardwarePolicy) -> Result<String, Error> {
    if policy.schema != "stogas.hardware-policies.v1"
        || policy.policies.is_empty()
        || policy.policies.len() > MAX_NODES
    {
        return Err(Error::InvalidBundle(
            "unsupported or invalid hardware policy".into(),
        ));
    }
    let mut previous_group: Option<String> = None;
    for profile in &policy.policies {
        if profile.chip_ids.is_empty() || profile.chip_ids.len() > MAX_NODES {
            return Err(Error::InvalidBundle(
                "hardware policy group has no chip ids or is too large".into(),
            ));
        }
        let mut previous_chip: Option<&str> = None;
        for chip_id in &profile.chip_ids {
            if !is_lower_hex(chip_id, 64)
                || previous_chip.is_some_and(|previous| previous >= chip_id.as_str())
            {
                return Err(Error::InvalidBundle(
                    "hardware policy has an invalid, unsorted, or duplicate chip id".into(),
                ));
            }
            previous_chip = Some(chip_id);
        }
        let group = canonical_json(
            &serde_json::to_value(profile)
                .map_err(|error| Error::InvalidBundle(format!("hardware policy: {error}")))?,
        )?;
        if previous_group
            .as_ref()
            .is_some_and(|previous| previous >= &group)
        {
            return Err(Error::InvalidBundle(
                "hardware policy groups are duplicated or not canonically ordered".into(),
            ));
        }
        previous_group = Some(group);
        let built_in = amd_product_from_cpuid(profile.cpuid_family, profile.cpuid_model)
            .ok_or_else(|| {
                Error::InvalidBundle("hardware policy has an unsupported CPUID".into())
            })?;
        if built_in.tcb_layout != AmdTcbLayout::Family19h {
            return Err(Error::InvalidBundle(
                "hardware policy CPUID is not supported by this policy format".into(),
            ));
        }
        let required_platform = parse_u64_hex(
            &profile.required_platform_info_mask,
            "required platform-info mask",
        )?;
        let forbidden_platform = parse_u64_hex(
            &profile.forbidden_platform_info_mask,
            "forbidden platform-info mask",
        )?;
        if required_platform & forbidden_platform != 0
            || required_platform & !SNP_PLATFORM_INFO_KNOWN_MASK != 0
            || forbidden_platform & !SNP_PLATFORM_INFO_KNOWN_MASK != 0
        {
            return Err(Error::InvalidBundle(
                "hardware policy has invalid platform-info masks".into(),
            ));
        }
        parse_u64_hex(
            &profile.required_launch_mitigation_mask,
            "required launch mitigation mask",
        )?;
        parse_u64_hex(
            &profile.required_current_mitigation_mask,
            "required current mitigation mask",
        )?;
    }
    let value = serde_json::to_value(policy)
        .map_err(|error| Error::InvalidBundle(format!("hardware policy: {error}")))?;
    canonical_json(&value)
}
#[cfg(any(feature = "snp", test))]
fn appraise_hardware(
    policy: &HardwarePolicy,
    chip_id: &str,
    appraise: impl Fn(&AmdSevSnpPolicy) -> Result<(), Error>,
) -> Result<(), Error> {
    // A chip may have several approved configurations during a transition. Each
    // must pass as a whole; never combine fields from separate configurations.
    let mut first_error = None;
    for profile in policy.policies.iter().filter(|policy| {
        policy
            .chip_ids
            .iter()
            .any(|candidate| candidate.eq_ignore_ascii_case(chip_id))
    }) {
        match appraise(profile) {
            Ok(()) => return Ok(()),
            Err(error) => {
                first_error.get_or_insert(error);
            }
        }
    }
    Err(first_error
        .unwrap_or_else(|| Error::Node("chip id is absent from the signed hardware policy".into())))
}

fn parse_u64_hex(value: &str, label: &str) -> Result<u64, Error> {
    let hex = value
        .strip_prefix("0x")
        .filter(|hex| is_lower_hex(hex, 8))
        .ok_or_else(|| Error::InvalidBundle(format!("hardware policy {label} is invalid")))?;
    u64::from_str_radix(hex, 16)
        .map_err(|_| Error::InvalidBundle(format!("hardware policy {label} is invalid")))
}

fn validate_catalog_shape(manifest: &CatalogReleaseManifest) -> Result<(), Error> {
    if manifest.schema != "stogas.catalog.release.v1"
        || manifest.minimum_gateway_sequence == 0
        || manifest.minimum_gateway_sequence > MAX_SAFE_INTEGER
        || manifest.sequence == 0
        || manifest.sequence > MAX_SAFE_INTEGER
        || manifest.source.repository != "https://github.com/StogasAI/catalog"
        || manifest.source.tag != format!("catalog-v{}", manifest.sequence)
        || !is_lower_hex(&manifest.source.commit, 20)
        || !is_lower_hex(&manifest.source.sha256, 32)
        || !valid_artifact(&manifest.artifacts.runtime, 64 * 1024 * 1024)
        || !valid_artifact(&manifest.artifacts.public, 64 * 1024 * 1024)
    {
        return Err(Error::InvalidBundle("invalid catalog release shape".into()));
    }
    Ok(())
}

fn valid_artifact(artifact: &ReleaseArtifact, maximum_bytes: u64) -> bool {
    is_lower_hex(&artifact.sha256, 32) && (1..=maximum_bytes).contains(&artifact.size_bytes)
}

fn validate_gateway_release_manifest(manifest: &GatewayReleaseManifest) -> Result<(), Error> {
    if !gateway_release_manifest_shape_is_valid(manifest) {
        return Err(Error::InvalidBundle(
            "invalid gateway release manifest shape".into(),
        ));
    }
    validate_gateway_release_build(&manifest.build)?;
    validate_gateway_launch_policies(&manifest.sev_snp.launch_policies)?;
    let launch_policies = canonical_json(
        &serde_json::to_value(&manifest.sev_snp.launch_policies).map_err(|error| {
            Error::InvalidBundle(format!("launch policy serialization: {error}"))
        })?,
    )?;
    let launch_policies_sha256 = hex::encode(Sha256::digest(launch_policies.as_bytes()));
    if manifest
        .build
        .input_sha256
        .get("stogas/release/snp-launch-policies.json")
        != Some(&launch_policies_sha256)
    {
        return Err(Error::InvalidBundle(
            "gateway launch policy artifact does not match the release manifest".into(),
        ));
    }
    Ok(())
}

fn gateway_release_manifest_shape_is_valid(manifest: &GatewayReleaseManifest) -> bool {
    let sev_snp = &manifest.sev_snp;
    let build = &manifest.build;
    manifest.schema == "stogas.gateway.release.v1"
        && manifest.source.repository == "https://github.com/StogasAI/gateway"
        && gateway_release_sequence(&manifest.source.tag) == Some(manifest.sequence)
        && manifest.minimum_catalog_sequence > 0
        && manifest.minimum_catalog_sequence <= MAX_SAFE_INTEGER
        && manifest.source.tag.len() <= 100
        && is_lower_hex(&manifest.source.commit, 20)
        && is_lower_hex(&manifest.source.sha256, 32)
        && is_lower_hex(&manifest.artifacts.gateway_igvm.sha256, 32)
        && manifest.artifacts.gateway_igvm.size_bytes > 0
        && manifest.artifacts.gateway_igvm.size_bytes <= 128 * 1024 * 1024
        && sev_snp.check_kvm
        && sev_snp.platform == "SEV_SNP"
        && sev_snp.vmm == "qemu-kvm"
        && sev_snp.measurement_command == "igvmmeasure --check-kvm gateway.igvm measure"
        && sev_snp.measurement_tool == "igvmmeasure"
        && !sev_snp.measurement_tool_version.is_empty()
        && sev_snp.measurement_tool_version.len() <= 100
        && is_lower_hex(&sev_snp.measurement_tool_sha256, 32)
        && is_lower_hex(&sev_snp.launch_measurement, 48)
        && sev_snp.vcpu_count > 0
        && sev_snp.vcpu_count <= 1024
        && build.environment.lc_all == "C"
        && build.environment.source_date_epoch == "1"
        && build.environment.tz == "UTC"
        && build.environment.umask == "022"
        && build.guest_ca_bundle_path == "/etc/ssl/certs/ca-certificates.crt"
        && is_lower_hex(&build.guix_channel_commit, 20)
        && !build.input_sha256.is_empty()
        && build.input_sha256.len() <= 256
        && !build.go_version.is_empty()
        && build.go_version.len() <= 200
        && !build.kernel_version.is_empty()
        && build.kernel_version.len() <= 100
}

fn validate_gateway_release_build(build: &GatewayReleaseBuild) -> Result<(), Error> {
    for path in [
        "core/go.mod",
        "core/go.sum",
        "transports/go.mod",
        "transports/go.sum",
        "guix/nss-certs/ca-certificates.crt",
        "stogas/release/guix/cmdline.txt",
        "stogas/release/guix/os-release",
        "stogas/release/pins.lock.json",
    ] {
        if !build.input_sha256.contains_key(path) {
            return Err(Error::InvalidBundle(format!(
                "gateway build input is absent: {path}"
            )));
        }
    }

    for digest in [
        &build.go_vendor_tree_sha256,
        &build.kernel_config_sha256,
        &build.linux_bz_image_sha256,
        &build.ovmf_sha256,
        &build.systemd_stub_sha256,
        &build.uki_sha256,
    ] {
        if !is_lower_hex(digest, 32) {
            return Err(Error::InvalidBundle(
                "gateway release build digest is invalid".into(),
            ));
        }
    }
    if build
        .input_sha256
        .iter()
        .any(|(name, digest)| name.is_empty() || name.len() > 256 || !is_lower_hex(digest, 32))
    {
        return Err(Error::InvalidBundle(
            "gateway release build input is invalid".into(),
        ));
    }
    Ok(())
}

fn validate_gateway_launch_policies(policies: &LaunchPolicies) -> Result<(), Error> {
    if policies.schema != "stogas.snp-launch-policies.v1" || policies.policies.is_empty() {
        return Err(Error::InvalidBundle(
            "invalid gateway launch policies".into(),
        ));
    }
    let mut previous_product: Option<&str> = None;
    for policy in &policies.policies {
        let product_name = policy.product_name.as_str();
        if previous_product.is_some_and(|previous| previous >= product_name) {
            return Err(Error::InvalidBundle(
                "gateway launch policies are duplicated or not sorted by product".into(),
            ));
        }
        previous_product = Some(product_name);
        let product = AMD_PRODUCT_PROFILES
            .iter()
            .find(|profile| profile.product_name == product_name)
            .ok_or_else(|| {
                Error::InvalidBundle(
                    "gateway launch policy names an unsupported AMD product".into(),
                )
            })?;
        validate_gateway_launch_policy(&policy.launch, product)?;
    }
    Ok(())
}

fn validate_gateway_launch_policy(
    launch: &LaunchValues,
    product: &AmdProductProfile,
) -> Result<(), Error> {
    if !is_lower_hex(&launch.family_id, 16)
        || !is_lower_hex(&launch.image_id, 16)
        || !is_lower_hex(&launch.host_data, 32)
        || !is_lower_hex(&launch.id_key_digest, 48)
        || !is_lower_hex(&launch.author_key_digest, 48)
        || launch.vmpl != 0
        || !is_prefixed_lower_hex(&launch.policy, 8)
    {
        return Err(Error::InvalidBundle("invalid gateway launch policy".into()));
    }
    let launch_policy = u64::from_str_radix(&launch.policy[2..], 16)
        .map_err(|_| Error::InvalidBundle("invalid SNP launch policy".into()))?;
    validate_snp_launch_policy(launch_policy, product)
        .map_err(|error| Error::InvalidBundle(format!("invalid gateway launch policy: {error}")))
}

/// Launch values depend on the processor generation, not on the individual chip, so a new host
/// of an admitted generation needs only a hardware-policy change.
#[cfg(feature = "snp")]
fn compatible_launch_policy<'a>(
    policies: &'a LaunchPolicies,
    product: &AmdProductProfile,
) -> Result<&'a LaunchValues, Error> {
    policies
        .policies
        .iter()
        .find(|policy| policy.product_name == product.product_name)
        .map(|policy| &policy.launch)
        .ok_or_else(|| {
            Error::Node(format!(
                "the release has no launch policy for AMD {}",
                product.product_name
            ))
        })
}

fn gateway_release_sequence(release_tag: &str) -> Option<u64> {
    const COMPONENT_BASE: u64 = 1_000_000;
    const MAJOR_BASE: u64 = COMPONENT_BASE * COMPONENT_BASE;

    let mut parts = release_tag.strip_prefix('v')?.split('.');
    let parse = |part: &str| {
        if part.is_empty()
            || (part.len() > 1 && part.starts_with('0'))
            || !part.bytes().all(|byte| byte.is_ascii_digit())
        {
            return None;
        }
        part.parse::<u64>().ok()
    };
    let major = parse(parts.next()?)?;
    let minor = parse(parts.next()?)?;
    let patch = parse(parts.next()?)?;
    if parts.next().is_some() || minor >= COMPONENT_BASE || patch >= COMPONENT_BASE {
        return None;
    }
    let sequence = major
        .checked_mul(MAJOR_BASE)?
        .checked_add(minor.checked_mul(COMPONENT_BASE)?)?
        .checked_add(patch)?;
    (sequence > 0 && sequence <= MAX_SAFE_INTEGER).then_some(sequence)
}

fn is_lower_hex(value: &str, bytes: usize) -> bool {
    value.len() == bytes * 2
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

fn is_prefixed_lower_hex(value: &str, bytes: usize) -> bool {
    value
        .strip_prefix("0x")
        .is_some_and(|hex| is_lower_hex(hex, bytes))
}

/// The release document's own file digest, which the build proof names.
fn release_manifest_sha256(manifest: &impl serde::Serialize) -> Result<String, Error> {
    let value =
        serde_json::to_value(manifest).map_err(|error| Error::Release(error.to_string()))?;
    Ok(hex::encode(Sha256::digest(
        canonical_json(&value)?.as_bytes(),
    )))
}

fn verify_catalog_release(
    catalog: &AllowedCatalog,
    trust: &TrustedRoot,
    now_unix_ms: i64,
) -> Result<VerifiedCatalogRelease, Error> {
    let manifest = &catalog.document;
    validate_catalog_shape(manifest)?;
    let manifest_digest = release_manifest_sha256(manifest)?;
    let attestation_bytes = serde_json::to_vec(&catalog.provenance)
        .map_err(|error| Error::Release(error.to_string()))?;
    let (github_integrated_time_unix_ms, provenance) = verify_catalog_provenance(
        &attestation_bytes,
        manifest,
        &manifest_digest,
        trust,
        now_unix_ms,
    )?;

    Ok(VerifiedCatalogRelease {
        github_integrated_time_unix_ms,
        minimum_gateway_sequence: manifest.minimum_gateway_sequence,
        provenance,
        public_digest: format!("sha256:{}", manifest.artifacts.public.sha256),
        public_size_bytes: manifest.artifacts.public.size_bytes,
        runtime_digest: format!("sha256:{}", manifest.artifacts.runtime.sha256),
        runtime_size_bytes: manifest.artifacts.runtime.size_bytes,
        sequence: manifest.sequence,
        source_commit: manifest.source.commit.clone(),
        source_repository: manifest.source.repository.clone(),
        source_sha256: manifest.source.sha256.clone(),
        source_tag: manifest.source.tag.clone(),
    })
}

fn verify_catalog_provenance(
    attestation_bytes: &[u8],
    manifest: &CatalogReleaseManifest,
    manifest_digest: &str,
    trust: &TrustedRoot,
    now_unix_ms: i64,
) -> Result<(Option<i64>, ReleaseProvenance), Error> {
    #[cfg(feature = "staging")]
    if is_staging_development_provenance(
        attestation_bytes,
        &[
            ("catalog-release.json", manifest_digest),
            ("catalog.runtime.json", &manifest.artifacts.runtime.sha256),
            ("catalog.public.json", &manifest.artifacts.public.sha256),
        ],
    )? {
        return Ok((None, ReleaseProvenance::Staging));
    }

    let workflow_identity = format!(
        "https://github.com/StogasAI/catalog/.github/workflows/catalog-release.yml@refs/tags/{}",
        manifest.source.tag
    );
    verify_github_provenance(
        trust,
        attestation_bytes,
        &[
            Subject {
                name: "catalog-release.json",
                sha256: manifest_digest,
            },
            Subject {
                name: "catalog.runtime.json",
                sha256: &manifest.artifacts.runtime.sha256,
            },
            Subject {
                name: "catalog.public.json",
                sha256: &manifest.artifacts.public.sha256,
            },
        ],
        &GithubPolicy {
            repository: manifest.source.repository.clone(),
            workflow_identity,
            source_ref: format!("refs/tags/{}", manifest.source.tag),
            source_commit: manifest.source.commit.clone(),
            predicate_type: "https://slsa.dev/provenance/v1".into(),
            require_github_hosted: true,
        },
        now_unix_ms,
        "catalog provenance",
    )
}

fn verify_gateway_release(
    release: &AllowedIgvm,
    trust: &TrustedRoot,
    now_unix_ms: i64,
) -> Result<VerifiedRelease, Error> {
    let manifest = &release.document;
    validate_gateway_release_manifest(manifest)?;
    let manifest_digest = release_manifest_sha256(manifest)?;
    let attestation_bytes = serde_json::to_vec(&release.provenance)
        .map_err(|error| Error::Release(error.to_string()))?;
    let (github_integrated_time_unix_ms, provenance) = verify_release_provenance(
        &attestation_bytes,
        manifest,
        &manifest_digest,
        trust,
        now_unix_ms,
    )?;

    Ok(VerifiedRelease {
        github_integrated_time_unix_ms,
        igvm_sha256: manifest.artifacts.gateway_igvm.sha256.clone(),
        launch_policies: manifest.sev_snp.launch_policies.clone(),
        measurement: manifest.sev_snp.launch_measurement.clone(),
        minimum_catalog_sequence: manifest.minimum_catalog_sequence,
        provenance,
        release_manifest_sha256: manifest_digest,
        release_tag: manifest.source.tag.clone(),
        sequence: manifest.sequence,
        source_commit: manifest.source.commit.clone(),
        source_repository: manifest.source.repository.clone(),
        source_sha256: manifest.source.sha256.clone(),
        vcpu_count: manifest.sev_snp.vcpu_count,
    })
}

fn verify_release_provenance(
    attestation_bytes: &[u8],
    manifest: &GatewayReleaseManifest,
    manifest_digest: &str,
    trust: &TrustedRoot,
    now_unix_ms: i64,
) -> Result<(Option<i64>, ReleaseProvenance), Error> {
    #[cfg(feature = "staging")]
    if is_staging_development_provenance(
        attestation_bytes,
        &[
            ("release-manifest.json", manifest_digest),
            ("gateway.igvm", &manifest.artifacts.gateway_igvm.sha256),
        ],
    )? {
        return Ok((None, ReleaseProvenance::Staging));
    }

    let workflow_identity = format!(
        "https://github.com/StogasAI/gateway/.github/workflows/gateway-igvm-release.yml@refs/tags/{}",
        manifest.source.tag
    );
    verify_github_provenance(
        trust,
        attestation_bytes,
        &[
            Subject {
                name: "release-manifest.json",
                sha256: manifest_digest,
            },
            Subject {
                name: "gateway.igvm",
                sha256: &manifest.artifacts.gateway_igvm.sha256,
            },
        ],
        &GithubPolicy {
            repository: manifest.source.repository.clone(),
            workflow_identity,
            source_ref: format!("refs/tags/{}", manifest.source.tag),
            source_commit: manifest.source.commit.clone(),
            predicate_type: "https://slsa.dev/provenance/v1".into(),
            require_github_hosted: true,
        },
        now_unix_ms,
        "gateway provenance",
    )
}

fn verify_github_provenance(
    trust: &TrustedRoot,
    attestation_bytes: &[u8],
    expected_subjects: &[Subject<'_>],
    policy: &GithubPolicy,
    now_unix_ms: i64,
    context: &str,
) -> Result<(Option<i64>, ReleaseProvenance), Error> {
    let verified = verify_github_attestation(
        trust,
        attestation_bytes,
        expected_subjects,
        policy,
        now_unix_ms,
    )
    .map_err(|error| Error::Release(format!("{context}: {error}")))?;
    let integrated_time = verified
        .integrated_time
        .checked_mul(1000)
        .ok_or_else(|| Error::Release(format!("{context} GitHub integration time overflows")))?;
    Ok((Some(integrated_time), ReleaseProvenance::Github))
}

#[cfg(feature = "staging")]
fn is_staging_development_provenance(
    bytes: &[u8],
    expected_subjects: &[(&str, &str)],
) -> Result<bool, Error> {
    let value: Value = serde_json::from_slice(bytes)
        .map_err(|error| Error::Release(format!("invalid provenance JSON: {error}")))?;
    if value.get("predicateType").and_then(Value::as_str) != Some(STAGING_PROVENANCE_TYPE) {
        return Ok(false);
    }
    let statement: StagingDevelopmentProvenance =
        serde_json::from_value(value).map_err(|error| {
            Error::Release(format!("invalid staging development provenance: {error}"))
        })?;
    if statement.statement_type != "https://in-toto.io/Statement/v1"
        || statement.predicate_type != STAGING_PROVENANCE_TYPE
        || statement.predicate.environment != "staging"
        || statement.subject.len() != expected_subjects.len()
    {
        return Err(Error::Release(
            "invalid staging development provenance policy".into(),
        ));
    }
    let expected = expected_subjects
        .iter()
        .map(|(name, digest)| ((*name).to_owned(), (*digest).to_owned()))
        .collect::<BTreeMap<_, _>>();
    let mut actual = BTreeMap::new();
    for subject in statement.subject {
        if subject.digest.len() != 1 {
            return Err(Error::Release(
                "staging development provenance subject digest is invalid".into(),
            ));
        }
        let Some(digest) = subject.digest.get("sha256") else {
            return Err(Error::Release(
                "staging development provenance requires SHA-256 subjects".into(),
            ));
        };
        if actual.insert(subject.name, digest.clone()).is_some() {
            return Err(Error::Release(
                "staging development provenance has duplicate subjects".into(),
            ));
        }
    }
    if actual != expected {
        return Err(Error::Release(
            "staging development provenance subjects differ".into(),
        ));
    }
    Ok(true)
}
#[cfg(feature = "snp")]
#[derive(Clone, Debug)]
struct AmdCollateralEntry {
    ca_product_name: String,
    collateral_type: String,
    der: Vec<u8>,
    sha256: String,
    chip_id: Option<String>,
    reported_tcb: Option<String>,
}

#[derive(Clone, Debug)]
#[cfg_attr(
    not(feature = "snp"),
    allow(
        dead_code,
        reason = "parsed AMD collateral is consumed only by the optional SNP verifier"
    )
)]
struct AmdCollateralStack {
    ark: Vec<u8>,
    ask: Vec<u8>,
    vek: Vec<u8>,
}
#[cfg(feature = "snp")]
#[derive(serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct AmdKdsPayload {
    ca_product_name: String,
    #[serde(default)]
    chip_id: Option<String>,
    collateral_type: String,
    der_base64url: String,
    fetched_at: String,
    #[serde(default)]
    hwid: Option<String>,
    product_name: String,
    #[serde(default)]
    reported_tcb: Option<String>,
    schema: String,
    sha256: String,
    source: String,
    source_url: String,
    #[serde(default)]
    tcb: Option<Value>,
}
#[cfg(feature = "snp")]
fn expand_bundle_vendor_collateral(
    rows: &[BTreeMap<String, Value>],
) -> Result<Vec<VendorCollateral>, Error> {
    rows.iter()
        .map(|payload| {
            let parsed: AmdKdsPayload =
                serde_json::from_value(Value::Object(payload.clone().into_iter().collect()))
                    .map_err(|error| {
                        Error::InvalidBundle(format!("invalid AMD collateral: {error}"))
                    })?;
            Ok(VendorCollateral {
                chip_id: parsed.chip_id,
                collateral_type: parsed.collateral_type,
                fetched_at: parsed.fetched_at,
                payload: payload.clone(),
                sha256: parsed.sha256,
                source_url: parsed.source_url,
            })
        })
        .collect()
}
#[cfg(feature = "snp")]
type AmdCommonCollateral = BTreeMap<(String, String), AmdCollateralEntry>;
#[cfg(feature = "snp")]
type AmdVcekCollateral = BTreeMap<String, AmdCollateralEntry>;
#[cfg(feature = "snp")]
// Fetch times describe delivery. Vendor signatures and validity are checked separately.
fn parse_amd_collateral_entries(
    rows: &[VendorCollateral],
) -> Result<(AmdCommonCollateral, AmdVcekCollateral), Error> {
    let mut common = BTreeMap::<(String, String), AmdCollateralEntry>::new();
    let mut vceks = BTreeMap::<String, AmdCollateralEntry>::new();
    let mut hashes = BTreeSet::new();

    for row in rows {
        let payload: AmdKdsPayload = serde_json::from_value(
            serde_json::to_value(&row.payload)
                .map_err(|error| Error::InvalidBundle(error.to_string()))?,
        )
        .map_err(|error| Error::InvalidBundle(format!("invalid AMD collateral: {error}")))?;
        let _ = (&payload.hwid, &payload.product_name, &payload.tcb);
        if payload.schema != "stogas.amd-kds-collateral.v1"
            || payload.source != "amd-kds"
            || payload.collateral_type != row.collateral_type
            || payload.fetched_at != row.fetched_at
            || payload.sha256 != row.sha256
            || payload.source_url != row.source_url
            || payload.chip_id.as_deref() != row.chip_id.as_deref()
        {
            return Err(Error::InvalidBundle(
                "AMD collateral envelope and payload differ".into(),
            ));
        }
        if !matches!(row.collateral_type.as_str(), "ark" | "ask" | "crl" | "vcek") {
            return Err(Error::InvalidBundle(
                "unsupported AMD collateral type".into(),
            ));
        }
        parse_time(&row.fetched_at)?;
        let der = URL_SAFE_NO_PAD
            .decode(&payload.der_base64url)
            .map_err(|_| Error::InvalidBundle("AMD collateral DER is not base64url".into()))?;
        if hex::encode(Sha256::digest(&der)) != row.sha256 || !hashes.insert(row.sha256.clone()) {
            return Err(Error::InvalidBundle(
                "AMD collateral digest differs or is duplicated".into(),
            ));
        }
        let entry = AmdCollateralEntry {
            ca_product_name: payload.ca_product_name,
            collateral_type: row.collateral_type.clone(),
            der,
            sha256: row.sha256.clone(),
            chip_id: row.chip_id.clone(),
            reported_tcb: payload.reported_tcb.map(|value| value.to_lowercase()),
        };
        if entry.collateral_type == "vcek" {
            let chip_id = entry
                .chip_id
                .as_deref()
                .ok_or_else(|| Error::InvalidBundle("AMD VCEK has no chip id".into()))?;
            let reported_tcb = entry
                .reported_tcb
                .as_deref()
                .ok_or_else(|| Error::InvalidBundle("AMD VCEK has no reported TCB".into()))?;
            if vceks
                .insert(amd_platform_key(chip_id, reported_tcb), entry)
                .is_some()
            {
                return Err(Error::InvalidBundle(
                    "duplicate AMD VCEK platform evidence".into(),
                ));
            }
        } else {
            if entry.chip_id.is_some() || entry.reported_tcb.is_some() {
                return Err(Error::InvalidBundle(
                    "product-scoped AMD evidence has node identity".into(),
                ));
            }
            let key = (entry.ca_product_name.clone(), entry.collateral_type.clone());
            if common.insert(key, entry).is_some() {
                return Err(Error::InvalidBundle(
                    "duplicate product-scoped AMD evidence".into(),
                ));
            }
        }
    }

    Ok((common, vceks))
}
#[cfg(feature = "snp")]
fn amd_platform_key(chip_id: &str, reported_tcb: &str) -> String {
    format!(
        "{}:{}",
        chip_id.trim().to_lowercase(),
        reported_tcb.trim().to_lowercase()
    )
}

#[cfg(feature = "snp")]
#[derive(Clone, Copy)]
struct ExpectedSnpReport<'a> {
    node_id: &'a str,
    chip_id: &'a str,
    reported_tcb: &'a str,
    report_data_sha512: &'a str,
}

#[cfg(feature = "snp")]
fn check_raw_report_bindings(
    node: ExpectedSnpReport<'_>,
    measurement: &str,
    launch: &LaunchValues,
    report: &[u8],
    hardware_policy: Option<&HardwarePolicy>,
) -> Result<(), Error> {
    fn bytes<const N: usize>(value: &str, label: &str) -> Result<[u8; N], Error> {
        let decoded = hex::decode(value).map_err(|_| Error::Node(format!("invalid {label}")))?;
        decoded
            .try_into()
            .map_err(|_| Error::Node(format!("invalid {label} length")))
    }
    if report.len() != 0x4a0 {
        return Err(Error::Node("SNP report has the wrong size".into()));
    }
    let u32_at = |offset: usize| {
        u32::from_le_bytes(report[offset..offset + 4].try_into().unwrap_or_default())
    };
    let u64_at = |offset: usize| {
        u64::from_le_bytes(report[offset..offset + 8].try_into().unwrap_or_default())
    };
    // Release verification checked these values against the rules of their AMD product.
    let expected_policy = u64::from_str_radix(launch.policy.trim_start_matches("0x"), 16)
        .map_err(|_| Error::Node("invalid launch policy value".into()))?;
    let report_version = u32_at(0x00);
    if !(2..=5).contains(&report_version) {
        return Err(Error::Node(format!(
            "{} SNP report version differs",
            node.node_id
        )));
    }
    let (_, _, _, report_product) = inspect_report_product(report, report_version)?;
    validate_raw_snp_report_encoding(report, report_version, report_product, node.node_id)?;
    let report_info = u32_at(0x48);
    let author_key_present = launch.author_key_digest.bytes().any(|byte| byte != b'0');
    let checks = [
        (
            report[0x10..0x20] == bytes::<16>(&launch.family_id, "family id")?,
            "family id",
        ),
        (
            report[0x20..0x30] == bytes::<16>(&launch.image_id, "image id")?,
            "image id",
        ),
        (
            report[0x50..0x90] == bytes::<64>(node.report_data_sha512, "report data")?,
            "report data",
        ),
        (
            report[0x90..0xc0] == bytes::<48>(measurement, "measurement")?,
            "measurement",
        ),
        (
            report[0xc0..0xe0] == bytes::<32>(&launch.host_data, "host data")?,
            "host data",
        ),
        (
            report[0xe0..0x110] == bytes::<48>(&launch.id_key_digest, "id key digest")?,
            "id key digest",
        ),
        (
            report[0x110..0x140] == bytes::<48>(&launch.author_key_digest, "author key digest")?,
            "author key digest",
        ),
        (
            report[0x180..0x188] == bytes::<8>(node.reported_tcb, "reported TCB")?,
            "reported TCB",
        ),
        (
            report[0x1a0..0x1e0] == bytes::<64>(node.chip_id, "chip id")?,
            "chip id",
        ),
        (u32_at(0x30) == u32::from(launch.vmpl), "VMPL"),
        (u64_at(0x08) == expected_policy, "guest policy"),
        (u32_at(0x34) == 1, "signature algorithm"),
        ((report_info & !1) == 0, "VCEK signing key information"),
        (
            (report_info & 1 != 0) == author_key_present,
            "author key flag",
        ),
        (
            expected_policy & SNP_POLICY_MIGRATE_MA != 0
                || is_absent_snp_migration_agent_id(&report[0x160..0x180]),
            "migration-agent report id",
        ),
    ];
    for (valid, label) in checks {
        if !valid {
            return Err(Error::Node(format!("{} SNP {label} differs", node.node_id)));
        }
    }
    if let Some(hardware_policy) = hardware_policy {
        appraise_hardware(hardware_policy, node.chip_id, |profile| {
            appraise_snp_report(report, report_product, profile, node.node_id)
        })?;
    }
    Ok(())
}

#[cfg(feature = "snp")]
fn is_absent_snp_migration_agent_id(value: &[u8]) -> bool {
    // The ABI specifies zero at launch. Milan firmware 1.58 uses all ones as its
    // absent-agent report sentinel. The signed policy bit remains authoritative.
    value.iter().all(|byte| *byte == 0) || value.iter().all(|byte| *byte == 0xff)
}

#[cfg(feature = "snp")]
fn validate_raw_snp_report_encoding(
    report: &[u8],
    report_version: u32,
    product: Option<&AmdProductProfile>,
    node_id: &str,
) -> Result<(), Error> {
    let zero_ranges: &[(usize, usize)] = if report_version == 5 {
        &[(0x4c, 0x50), (0x18b, 0x1a0), (0x208, 0x2a0)]
    } else {
        &[(0x4c, 0x50), (0x188, 0x1a0), (0x1f8, 0x2a0)]
    };
    if zero_ranges
        .iter()
        .any(|(start, end)| report[*start..*end].iter().any(|byte| *byte != 0))
        || report[0x1eb] != 0
        || report[0x1ef] != 0
    {
        return Err(Error::Node(format!(
            "{node_id} SNP report reserved bytes are nonzero"
        )));
    }
    let platform_info = u64::from_le_bytes(report[0x40..0x48].try_into().unwrap_or_default());
    if platform_info & !SNP_PLATFORM_INFO_KNOWN_MASK != 0 {
        return Err(Error::Node(format!(
            "{node_id} SNP platform information sets reserved bits"
        )));
    }
    if product.is_some_and(|profile| profile.tcb_layout == AmdTcbLayout::Family19h) {
        for (offset, label) in [
            (0x38, "current"),
            (0x180, "reported"),
            (0x1e0, "committed"),
            (0x1f0, "launch"),
        ] {
            if report[offset + 2..offset + 6].iter().any(|byte| *byte != 0) {
                return Err(Error::Node(format!(
                    "{node_id} SNP {label} TCB reserved bytes are nonzero"
                )));
            }
        }
    }
    Ok(())
}

#[cfg(feature = "snp")]
fn appraise_snp_report(
    report: &[u8],
    product: Option<&AmdProductProfile>,
    profile: &AmdSevSnpPolicy,
    node_id: &str,
) -> Result<(), Error> {
    let policy_product = amd_product_from_cpuid(profile.cpuid_family, profile.cpuid_model);
    if policy_product != product {
        return Err(Error::Node(format!(
            "{node_id} SNP processor identity differs from hardware policy"
        )));
    }
    evidence::SnpHardwareFacts::from_report(report).appraise(profile, node_id)
}

#[cfg(feature = "snp")]
fn family19h_tcb(bytes: &[u8]) -> AmdTcb {
    AmdTcb {
        bootloader: bytes[0],
        tee: bytes[1],
        snp: bytes[6],
        microcode: bytes[7],
    }
}

#[cfg(feature = "snp")]
const fn tcb_at_least(actual: AmdTcb, minimum: AmdTcb) -> bool {
    actual.bootloader >= minimum.bootloader
        && actual.tee >= minimum.tee
        && actual.snp >= minimum.snp
        && actual.microcode >= minimum.microcode
}

#[cfg(feature = "snp")]
#[allow(clippy::similar_names)]
fn verify_amd_certificates(
    collateral: &AmdCollateralStack,
    chip_id: &str,
    reported_tcb: &str,
    bundle_created_at: i64,
    bundle_expires_at: i64,
) -> Result<(), Error> {
    use sev::certs::snp::{Chain, Verifiable};
    use sha2::Sha384;
    use x509_parser::parse_x509_certificate;
    let (ark_remaining, ark) = parse_x509_certificate(&collateral.ark)
        .map_err(|error| Error::Node(format!("AMD ARK: {error}")))?;
    let (ask_remaining, ask) = parse_x509_certificate(&collateral.ask)
        .map_err(|error| Error::Node(format!("AMD ASK: {error}")))?;
    let (vek_remaining, vek) = parse_x509_certificate(&collateral.vek)
        .map_err(|error| Error::Node(format!("AMD VEK: {error}")))?;
    if !ark_remaining.is_empty() || !ask_remaining.is_empty() || !vek_remaining.is_empty() {
        return Err(Error::Node(
            "AMD certificate collateral contains trailing data".into(),
        ));
    }
    for (label, cert) in [("ARK", &ark), ("ASK", &ask), ("VEK", &vek)] {
        if cert.validity().not_before.timestamp() * 1000 > bundle_created_at
            || cert.validity().not_after.timestamp() * 1000 < bundle_expires_at
        {
            return Err(Error::Node(format!(
                "AMD {label} is not valid for the complete bundle interval"
            )));
        }
    }
    let product = validate_vcek_extensions(&vek, chip_id, reported_tcb)?;
    let root_hash = hex::encode(Sha384::digest(ark.public_key().raw));
    if root_hash != product.root_spki_sha384
        || ark.subject() != ark.issuer()
        || ask.issuer() != ark.subject()
        || vek.issuer() != ask.subject()
    {
        return Err(Error::Node("AMD certificate identity chain differs".into()));
    }
    let chain = Chain::from_der(&collateral.ark, &collateral.ask, &collateral.vek)
        .map_err(|error| Error::Node(format!("AMD chain: {error}")))?;
    (&chain)
        .verify()
        .map_err(|error| Error::Node(format!("AMD chain signature: {error}")))?;
    Ok(())
}

#[cfg(feature = "snp")]
fn verify_amd_crl_signature(
    crl: &x509_parser::revocation_list::CertificateRevocationList<'_>,
    signer: &x509_parser::certificate::X509Certificate<'_>,
) -> Result<(), Error> {
    use rsa::{RsaPublicKey, pkcs8::DecodePublicKey as _, pss};
    use signature::Verifier as _;
    use x509_parser::signature_algorithm::SignatureAlgorithm;

    const RSA_PSS_OID: &str = "1.2.840.113549.1.1.10";
    const MGF1_OID: &str = "1.2.840.113549.1.1.8";
    const SHA384_OID: &str = "2.16.840.1.101.3.4.2.2";
    const SHA384_BYTES: u32 = 48;
    if crl.signature_algorithm != crl.tbs_cert_list.signature
        || crl.signature_algorithm.algorithm.to_id_string() != RSA_PSS_OID
    {
        return Err(Error::Node(
            "AMD CRL must use one matching RSA-PSS signature algorithm".into(),
        ));
    }
    let SignatureAlgorithm::RSASSA_PSS(parameters) =
        SignatureAlgorithm::try_from(&crl.signature_algorithm)
            .map_err(|_| Error::Node("AMD CRL has invalid RSA-PSS signature parameters".into()))?
    else {
        return Err(Error::Node("AMD CRL must use RSA-PSS with SHA-384".into()));
    };
    let mask = parameters
        .mask_gen_algorithm()
        .map_err(|_| Error::Node("AMD CRL has invalid RSA-PSS mask parameters".into()))?;
    if parameters.hash_algorithm_oid().to_id_string() != SHA384_OID
        || mask.mgf.to_id_string() != MGF1_OID
        || mask.hash.to_id_string() != SHA384_OID
        || parameters.salt_length() != SHA384_BYTES
        || parameters.trailer_field() != 1
    {
        return Err(Error::Node(
            "AMD CRL must use RSA-PSS with SHA-384, MGF1-SHA-384, and a 48-byte salt".into(),
        ));
    }
    let public_key = RsaPublicKey::from_public_key_der(signer.public_key().raw)
        .map_err(|error| Error::Node(format!("AMD CRL signer key: {error}")))?;
    let signature = pss::Signature::try_from(crl.signature_value.data.as_ref())
        .map_err(|error| Error::Node(format!("AMD CRL signature encoding: {error}")))?;
    pss::VerifyingKey::<sha2::Sha384>::new(public_key)
        .verify(crl.tbs_cert_list.as_ref(), &signature)
        .map_err(|error| Error::Node(format!("AMD CRL signature: {error}")))
}

#[cfg(feature = "snp")]
fn validate_vcek_extensions(
    vek: &x509_parser::certificate::X509Certificate<'_>,
    chip_id: &str,
    reported_tcb: &str,
) -> Result<&'static AmdProductProfile, Error> {
    let expected_tcb =
        hex::decode(reported_tcb).map_err(|_| Error::Node("reported TCB is invalid".into()))?;
    if expected_tcb.len() != 8 {
        return Err(Error::Node("reported TCB has the wrong length".into()));
    }

    let mut extensions = BTreeMap::new();
    for extension in vek.extensions().iter().filter(|extension| {
        extension
            .oid
            .to_id_string()
            .starts_with("1.3.6.1.4.1.3704.1.")
    }) {
        let oid = extension.oid.to_id_string();
        if extensions.insert(oid.clone(), extension.value).is_some() {
            return Err(Error::Node(format!(
                "AMD VCEK extension {oid} is duplicated"
            )));
        }
    }
    let required = |oid: &str| {
        extensions
            .get(oid)
            .copied()
            .ok_or_else(|| Error::Node(format!("AMD VCEK extension {oid} is absent")))
    };

    let struct_version_oid = "1.3.6.1.4.1.3704.1.1";
    let struct_version = parse_der_u8(required(struct_version_oid)?)
        .ok_or_else(|| Error::Node("AMD VCEK structVersion is malformed".into()))?;
    let product_name = parse_der_ia5_string(required("1.3.6.1.4.1.3704.1.2")?)
        .ok_or_else(|| Error::Node("AMD VCEK productName is malformed".into()))?;
    let profile = amd_product_from_vcek_name(product_name)
        .ok_or_else(|| Error::Node("AMD VCEK productName is unsupported".into()))?;
    if struct_version != profile.struct_version {
        return Err(Error::Node(format!(
            "AMD VCEK structVersion differs for {}",
            profile.product_name
        )));
    }

    let tcb_extensions: &[(&str, usize)] = match profile.tcb_layout {
        AmdTcbLayout::Family19h => &[
            ("1.3.6.1.4.1.3704.1.3.1", 0),
            ("1.3.6.1.4.1.3704.1.3.2", 1),
            ("1.3.6.1.4.1.3704.1.3.4", 2),
            ("1.3.6.1.4.1.3704.1.3.5", 3),
            ("1.3.6.1.4.1.3704.1.3.6", 4),
            ("1.3.6.1.4.1.3704.1.3.7", 5),
            ("1.3.6.1.4.1.3704.1.3.3", 6),
            ("1.3.6.1.4.1.3704.1.3.8", 7),
        ],
        AmdTcbLayout::Family1ah => &[
            ("1.3.6.1.4.1.3704.1.3.9", 0),
            ("1.3.6.1.4.1.3704.1.3.1", 1),
            ("1.3.6.1.4.1.3704.1.3.2", 2),
            ("1.3.6.1.4.1.3704.1.3.3", 3),
            ("1.3.6.1.4.1.3704.1.3.5", 4),
            ("1.3.6.1.4.1.3704.1.3.6", 5),
            ("1.3.6.1.4.1.3704.1.3.7", 6),
            ("1.3.6.1.4.1.3704.1.3.8", 7),
        ],
    };
    for &(oid, tcb_index) in tcb_extensions {
        let expected_value = expected_tcb[tcb_index];
        if tcb_index != 7 && expected_value > 127 {
            return Err(Error::Node(format!(
                "reported TCB byte {tcb_index} exceeds AMD KDS policy"
            )));
        }
        let value = parse_der_u8(required(oid)?)
            .ok_or_else(|| Error::Node(format!("AMD VCEK extension {oid} is malformed")))?;
        if value != expected_value {
            return Err(Error::Node(format!(
                "AMD VCEK extension {oid} differs: certificate={value:#04x}, report={expected_value:#04x}"
            )));
        }
    }
    let chip = hex::decode(chip_id).map_err(|_| Error::Node("chip id is invalid".into()))?;
    if chip.len() != 64 {
        return Err(Error::Node("chip id has the wrong length".into()));
    }
    let hwid = required("1.3.6.1.4.1.3704.1.4")?;
    let certificate_chip = parse_der_octet_string(hwid)
        .ok_or_else(|| Error::Node(format!("AMD VCEK chip id is malformed ({})", hwid.len())))?;
    let expected_hwid = match profile.tcb_layout {
        AmdTcbLayout::Family19h => chip.as_slice(),
        AmdTcbLayout::Family1ah => {
            if chip[8..].iter().any(|byte| *byte != 0) || chip[..8].iter().all(|byte| *byte == 0) {
                return Err(Error::Node(
                    "Family 1Ah report CHIP_ID is not an 8-byte PSN followed by zeros".into(),
                ));
            }
            &chip[..8]
        }
    };
    if certificate_chip != expected_hwid {
        return Err(Error::Node("AMD VCEK chip id differs".into()));
    }
    Ok(profile)
}

#[cfg(feature = "snp")]
fn amd_product_from_vcek_name(value: &str) -> Option<&'static AmdProductProfile> {
    AMD_PRODUCT_PROFILES.iter().find(|profile| {
        value == profile.product_name
            || value
                .strip_prefix(profile.product_name)
                .and_then(|suffix| suffix.strip_prefix('-'))
                .is_some_and(|stepping| {
                    !stepping.is_empty()
                        && stepping.len() <= 8
                        && stepping.bytes().all(|byte| byte.is_ascii_alphanumeric())
                })
    })
}

#[cfg(feature = "snp")]
fn validate_report_product_binding(
    vek_der: &[u8],
    report: &[u8],
) -> Result<&'static AmdProductProfile, Error> {
    use x509_parser::parse_x509_certificate;

    let (remaining, vek) = parse_x509_certificate(vek_der)
        .map_err(|error| Error::Node(format!("AMD VEK: {error}")))?;
    if !remaining.is_empty() {
        return Err(Error::Node("AMD VEK contains trailing data".into()));
    }
    let product_name = vek
        .extensions()
        .iter()
        .find(|extension| extension.oid.to_id_string() == "1.3.6.1.4.1.3704.1.2")
        .and_then(|extension| parse_der_ia5_string(extension.value))
        .ok_or_else(|| Error::Node("AMD VCEK productName is malformed".into()))?;
    let certificate_product = amd_product_from_vcek_name(product_name)
        .ok_or_else(|| Error::Node("AMD VCEK productName is unsupported".into()))?;
    let report_version = u32::from_le_bytes(
        report[0x00..0x04]
            .try_into()
            .map_err(|_| Error::Node("SNP report version is absent".into()))?,
    );
    if !(2..=5).contains(&report_version) {
        return Err(Error::Node("unsupported SNP report version".into()));
    }
    let (_, _, _, report_product) = inspect_report_product(report, report_version)?;
    match report_product {
        Some(report_product) if report_product == certificate_product => Ok(certificate_product),
        Some(_) => Err(Error::Node(
            "AMD VCEK product differs from the report CPUID".into(),
        )),
        None if certificate_product.tcb_layout == AmdTcbLayout::Family19h => {
            Ok(certificate_product)
        }
        None => Err(Error::Node(
            "Family 1Ah VCEK requires report CPUID fields".into(),
        )),
    }
}

#[cfg(feature = "snp")]
fn parse_der_u8(value: &[u8]) -> Option<u8> {
    match value {
        [0x02, 0x01, byte] if *byte < 0x80 => Some(*byte),
        [0x02, 0x02, 0x00, byte] if *byte >= 0x80 => Some(*byte),
        _ => None,
    }
}

#[cfg(feature = "snp")]
fn parse_der_ia5_string(value: &[u8]) -> Option<&str> {
    let [0x16, length, bytes @ ..] = value else {
        return None;
    };
    if usize::from(*length) != bytes.len() || *length >= 0x80 || !bytes.is_ascii() {
        return None;
    }
    std::str::from_utf8(bytes).ok()
}

#[cfg(feature = "snp")]
fn parse_der_octet_string(value: &[u8]) -> Option<&[u8]> {
    if matches!(value.len(), 8 | 64) {
        return Some(value);
    }
    match value {
        [0x04, length, bytes @ ..] if usize::from(*length) == bytes.len() && *length < 0x80 => {
            Some(bytes)
        }
        _ => None,
    }
}
#[cfg(any(feature = "snp", all(test, feature = "staging")))]
fn parse_time(value: &str) -> Result<i64, Error> {
    DateTime::parse_from_rfc3339(value)
        .map(|value| value.with_timezone(&Utc).timestamp_millis())
        .map_err(|_| Error::InvalidBundle(format!("invalid timestamp: {value}")))
}

fn verify_stogas_signature(
    public_der_b64: &str,
    payload: &[u8],
    signature_b64url: &str,
) -> Result<(), String> {
    let der = STANDARD
        .decode(public_der_b64)
        .map_err(|error| error.to_string())?;
    if STANDARD.encode(&der) != public_der_b64 {
        return Err("non-canonical Stogas public key".into());
    }
    let key = signing::public_key_from_spki(&der).map_err(|error| error.to_string())?;
    let signature = URL_SAFE_NO_PAD
        .decode(signature_b64url)
        .map_err(|error| error.to_string())?;
    if signature.len() != signing::SIGNATURE_BYTES
        || URL_SAFE_NO_PAD.encode(&signature) != signature_b64url
    {
        return Err("invalid Stogas signature encoding".into());
    }
    signing::verify(key, payload, &signature).map_err(|error| error.to_string())
}

fn canonical_json(value: &Value) -> Result<String, Error> {
    let mut output = serde_json_canonicalizer::to_string(value)
        .map_err(|error| Error::InvalidBundle(format!("canonical JSON: {error}")))?;
    output.push('\n');
    Ok(output)
}

#[cfg(test)]
mod tests {

    use super::*;

    fn embedded() -> &'static TrustedRoot {
        TrustedRoot::embedded().unwrap()
    }

    #[test]
    fn groups_exact_chip_ids_under_shared_hardware_requirements() {
        let policy: HardwarePolicy =
            serde_json::from_str(include_str!("../tests/fixtures/milan-hardware-policy.json"))
                .unwrap();
        validate_hardware_policy(&policy).unwrap();
        let chip_id = &policy.policies[0].chip_ids[0];
        appraise_hardware(&policy, chip_id, |profile| {
            assert_eq!(profile.chip_ids, vec![chip_id.clone()]);
            Ok(())
        })
        .unwrap();
        assert!(appraise_hardware(&policy, &"00".repeat(64), |_| Ok(())).is_err());
    }

    #[test]
    fn hardware_policy_alternatives_are_unique_canonical_and_individually_valid() {
        let mut policy: HardwarePolicy =
            serde_json::from_str(include_str!("../tests/fixtures/milan-hardware-policy.json"))
                .unwrap();
        let mut alternative = policy.policies[0].clone();
        alternative.forbidden_platform_info_mask = "0x0000000000000001".into();
        policy.policies.push(alternative);
        let summary = verify_hardware_policy(&policy).unwrap();
        assert_eq!(summary.chip_ids, policy.policies[0].chip_ids);
        assert_eq!(summary.policy_count, 2);

        let mut invalid = policy.clone();
        invalid.policies.reverse();
        assert!(validate_hardware_policy(&invalid).is_err());
        invalid = policy.clone();
        invalid.policies[1] = invalid.policies[0].clone();
        assert!(validate_hardware_policy(&invalid).is_err());
        invalid = policy.clone();
        let repeated_chip = invalid.policies[0].chip_ids[0].clone();
        invalid.policies[1].chip_ids.push(repeated_chip);
        assert!(validate_hardware_policy(&invalid).is_err());
        invalid = policy.clone();
        invalid.policies[1].required_platform_info_mask = "0x0000000000000025".into();
        assert!(validate_hardware_policy(&invalid).is_err());
        invalid = policy;
        invalid.policies[1].cpuid_family = 0;
        assert!(validate_hardware_policy(&invalid).is_err());
    }

    #[cfg(feature = "snp")]
    #[test]
    fn hardware_transitions_match_one_complete_configuration() {
        let (report, profile, product) = appraisable_milan_report();
        let chip = profile.chip_ids[0].clone();
        let mut smt_on = profile.clone();
        smt_on.required_platform_info_mask = "0x0000000000000025".into();
        smt_on.minimum_tcb.microcode = 223;
        let mut smt_off = profile;
        smt_off.forbidden_platform_info_mask = "0x0000000000000001".into();
        let transition = HardwarePolicy {
            policies: vec![smt_on.clone(), smt_off.clone()],
            schema: "stogas.hardware-policies.v1".into(),
        };
        let only_on = HardwarePolicy {
            policies: vec![smt_on],
            ..transition.clone()
        };
        let only_off = HardwarePolicy {
            policies: vec![smt_off],
            ..transition.clone()
        };
        for (policy, platform, microcode, allowed) in [
            (&transition, 0x25_u64, 223, true),
            (&transition, 0x24, 222, true), // The first configuration fails, the second passes.
            (&transition, 0x25, 222, false), // Cannot borrow the SMT-off TCB minimum.
            (&transition, 0x24, 221, false),
            (&only_off, 0x25, 223, false),
            (&only_off, 0x24, 222, true),
            (&only_on, 0x24, 223, false),
            (&only_on, 0x25, 223, true),
        ] {
            validate_hardware_policy(policy).unwrap();
            let mut quote = report.clone();
            quote[0x40..0x48].copy_from_slice(&platform.to_le_bytes());
            for offset in [0x3f, 0x187, 0x1e7, 0x1f7] {
                quote[offset] = microcode;
            }
            let raw = appraise_hardware(policy, &chip, |rule| {
                appraise_snp_report(&quote, Some(product), rule, "node")
            });
            let facts = evidence::SnpHardwareFacts::from_report(&quote);
            let retained = appraise_hardware(policy, &chip, |rule| facts.appraise(rule, "node"));
            assert_eq!(
                raw.is_ok(),
                allowed,
                "platform={platform:#x} microcode={microcode}"
            );
            assert_eq!(
                retained.is_ok(),
                allowed,
                "retained platform={platform:#x} microcode={microcode}"
            );
        }
    }

    #[cfg(feature = "snp")]
    fn appraisable_milan_report() -> (Vec<u8>, AmdSevSnpPolicy, &'static AmdProductProfile) {
        let policy: HardwarePolicy =
            serde_json::from_str(include_str!("../tests/fixtures/milan-hardware-policy.json"))
                .unwrap();
        let profile = amd_product_from_cpuid(0x19, 0x01).unwrap();
        let mut report = vec![0_u8; 0x4a0];
        report[0x00..0x04].copy_from_slice(&5_u32.to_le_bytes());
        let tcb = [4, 0, 0, 0, 0, 0, 29, 222];
        for offset in [0x38, 0x180, 0x1e0, 0x1f0] {
            report[offset..offset + 8].copy_from_slice(&tcb);
        }
        report[0x40..0x48].copy_from_slice(&0x24_u64.to_le_bytes());
        report[0x188..0x18b].copy_from_slice(&[0x19, 0x01, 0x01]);
        report[0x1f8..0x200].copy_from_slice(&0x0b_u64.to_le_bytes());
        report[0x200..0x208].copy_from_slice(&0x0b_u64.to_le_bytes());
        (report, policy.policies[0].clone(), profile)
    }

    #[cfg(feature = "snp")]
    #[test]
    fn report_v5_appraisal_enforces_every_dynamic_amd_security_field() {
        let (report, policy, product) = appraisable_milan_report();
        appraise_snp_report(&report, Some(product), &policy, "node").unwrap();

        for (label, offset, value) in [
            ("current TCB", 0x3e, 28_u8),
            ("reported TCB", 0x186, 28),
            ("committed TCB", 0x1e6, 28),
            ("launch TCB", 0x1f6, 28),
        ] {
            let mut invalid = report.clone();
            invalid[offset] = value;
            let error = appraise_snp_report(&invalid, Some(product), &policy, "node")
                .unwrap_err()
                .to_string();
            assert!(error.contains("below hardware policy"), "{label}: {error}");
        }

        for (label, offset) in [("launch", 0x1f8), ("current", 0x200)] {
            let mut invalid = report.clone();
            invalid[offset..offset + 8].copy_from_slice(&0x12_u64.to_le_bytes());
            let error = appraise_snp_report(&invalid, Some(product), &policy, "node")
                .unwrap_err()
                .to_string();
            assert!(error.contains(&format!("{label} mitigations")), "{error}");
        }

        let mut missing_alias_check = report.clone();
        missing_alias_check[0x40..0x48].copy_from_slice(&0_u64.to_le_bytes());
        assert!(
            appraise_snp_report(&missing_alias_check, Some(product), &policy, "node")
                .unwrap_err()
                .to_string()
                .contains("platform information")
        );

        let mut smt_enabled = report.clone();
        smt_enabled[0x40..0x48].copy_from_slice(&0x25_u64.to_le_bytes());
        appraise_snp_report(&smt_enabled, Some(product), &policy, "node").unwrap();

        let mut old_report = report;
        old_report[0..4].copy_from_slice(&4_u32.to_le_bytes());
        assert!(
            appraise_snp_report(&old_report, Some(product), &policy, "node")
                .unwrap_err()
                .to_string()
                .contains("report version")
        );
    }

    #[cfg(feature = "snp")]
    #[test]
    fn report_v5_appraisal_rejects_tcb_and_firmware_downgrade_inconsistency() {
        let (mut report, mut policy, product) = appraisable_milan_report();
        policy.minimum_tcb = AmdTcb {
            bootloader: 0,
            microcode: 0,
            snp: 0,
            tee: 0,
        };
        report[0x187] = 3;
        report[0x1e7] = 2;
        let error = appraise_snp_report(&report, Some(product), &policy, "node")
            .unwrap_err()
            .to_string();
        assert!(error.contains("invalid downgrade order"));

        let (mut report, policy, product) = appraisable_milan_report();
        report[0x1e8..0x1eb].copy_from_slice(&[1, 0, 1]);
        report[0x1ec..0x1ef].copy_from_slice(&[2, 0, 1]);
        let error = appraise_snp_report(&report, Some(product), &policy, "node")
            .unwrap_err()
            .to_string();
        assert!(error.contains("committed firmware version exceeds current"));
    }

    pub fn release_fixture() -> AllowedIgvm {
        let launch = serde_json::json!({
            "author_key_digest": "00".repeat(48),
            "family_id": "00".repeat(16),
            "host_data": "00".repeat(32),
            "id_key_digest": "00".repeat(48),
            "image_id": "00".repeat(16),
            "policy": "0x000000000213013a",
            "vmpl": 0
        });
        let launch_policies = serde_json::json!({
            "policies": [{
                "launch": launch,
                "product_name": "Milan"
            }],
            "schema": "stogas.snp-launch-policies.v1"
        });
        let launch_policies_bytes = canonical_json(&launch_policies).unwrap();
        let launch_policies_sha256 = hex::encode(Sha256::digest(launch_policies_bytes.as_bytes()));
        serde_json::from_value(serde_json::json!({
            "provenance": {},
            "document": {
                "artifacts": {
                    "gateway.igvm": { "sha256": "11".repeat(32), "size_bytes": 1 },
                },
                "build": {
                    "environment": { "lc_all": "C", "source_date_epoch": "1", "tz": "UTC", "umask": "022" },
                    "go_vendor_tree_sha256": "17".repeat(32),
                    "go_version": "go1.25.0",
                    "guest_ca_bundle_path": "/etc/ssl/certs/ca-certificates.crt",
                    "guix_channel_commit": "19".repeat(20),
                    "input_sha256": {
                        "stogas/release/guix/cmdline.txt": "12".repeat(32),
                        "core/go.mod": "13".repeat(32),
                        "core/go.sum": "14".repeat(32),
                        "transports/go.mod": "15".repeat(32),
                        "transports/go.sum": "16".repeat(32),
                        "guix/nss-certs/ca-certificates.crt": "18".repeat(32),
                        "stogas/release/guix/os-release": "23".repeat(32),
                        "stogas/release/pins.lock.json": "25".repeat(32),
                        "source": "20".repeat(32),
                        "stogas/release/snp-launch-policies.json": launch_policies_sha256
                    },
                    "kernel_config_sha256": "21".repeat(32),
                    "kernel_version": "6.12.0",
                    "linux_bz_image_sha256": "22".repeat(32),
                    "ovmf_sha256": "24".repeat(32),
                    "systemd_stub_sha256": "26".repeat(32),
                    "uki_sha256": "27".repeat(32)
                },
                "source": {
                    "commit": "33".repeat(20),
                    "repository": "https://github.com/StogasAI/gateway",
                    "sha256": "44".repeat(32),
                    "tag": "v0.0.1"
                },
                "minimum_catalog_sequence": 1,
                "schema": "stogas.gateway.release.v1",
                "sequence": 1,
                "sev_snp": {
                    "check_kvm": true,
                    "launch_measurement": "55".repeat(48),
                    "launch_policies": launch_policies,
                    "measurement_command": "igvmmeasure --check-kvm gateway.igvm measure",
                    "measurement_tool": "igvmmeasure",
                    "measurement_tool_sha256": "66".repeat(32),
                    "measurement_tool_version": "0.3.1",
                    "platform": "SEV_SNP",
                    "vcpu_count": 4,
                    "vmm": "qemu-kvm"
                }
            }
        }))
        .unwrap()
    }

    pub fn catalog_fixture() -> AllowedCatalog {
        serde_json::from_value(serde_json::json!({
            "provenance": {},
            "document": {
                "minimum_gateway_sequence": 1,
                "artifacts": {
                    "catalog.public.json": { "sha256": "11".repeat(32), "size_bytes": 1 },
                    "catalog.runtime.json": { "sha256": "22".repeat(32), "size_bytes": 1 }
                },
                "schema": "stogas.catalog.release.v1",
                "sequence": 1,
                "source": {
                    "commit": "33".repeat(20),
                    "repository": "https://github.com/StogasAI/catalog",
                    "sha256": "44".repeat(32),
                    "tag": "catalog-v1"
                }
            }
        }))
        .unwrap()
    }

    #[cfg(feature = "snp")]
    #[test]
    fn validates_turin_vcek_structure_tcb_and_psn_extensions() {
        use x509_parser::parse_x509_certificate;

        let der = STANDARD
            .decode(include_str!("../tests/fixtures/vcek-turin.der.base64").trim())
            .unwrap();
        let (_, vcek) = parse_x509_certificate(&der).unwrap();
        let chip_id = format!("{}{}", "1e550a8ee5cf9f4d", "00".repeat(56));
        let profile = validate_vcek_extensions(&vcek, &chip_id, "0000000000000009").unwrap();
        assert_eq!(profile.product_name, "Turin");
        assert_eq!(profile.struct_version, 1);
        assert_eq!(profile.tcb_layout, AmdTcbLayout::Family1ah);
        assert!(validate_vcek_extensions(&vcek, &chip_id, "0000000000000008").is_err());
        assert!(validate_vcek_extensions(&vcek, &"11".repeat(64), "0000000000000009").is_err());
    }

    #[cfg(feature = "snp")]
    #[test]
    fn raw_snp_binding_accepts_only_absent_migration_agent_ids() {
        assert!(is_absent_snp_migration_agent_id(&[0; 32]));
        assert!(is_absent_snp_migration_agent_id(&[0xff; 32]));

        let mut migration_agent_id = [0; 32];
        migration_agent_id[31] = 1;
        assert!(!is_absent_snp_migration_agent_id(&migration_agent_id));
    }

    #[test]
    fn rejects_duplicate_keys() {
        let error = strict_json::from_slice(br#"{"body":1,"body":2}"#).unwrap_err();
        assert!(error.to_string().contains("duplicate JSON key"));
    }

    #[test]
    fn release_launch_policies_follow_the_rules_of_their_amd_product() {
        let manifest = release_fixture().document;
        let milan = manifest.sev_snp.launch_policies.policies[0].clone();
        let with = |policies: Vec<AmdSevSnpLaunchPolicy>| {
            validate_gateway_launch_policies(&LaunchPolicies {
                policies,
                schema: manifest.sev_snp.launch_policies.schema.clone(),
            })
        };
        let product = |name: &str, policy: &str| {
            let mut entry = milan.clone();
            entry.product_name = name.into();
            entry.launch.policy = policy.into();
            entry
        };

        with(vec![
            product("Genoa", "0x000000000253013a"),
            product("Milan", "0x000000000213013a"),
        ])
        .unwrap();
        for (policies, message) in [
            (vec![], "invalid gateway launch policies"),
            (
                vec![product("Milan", "0x000000000013013a")],
                "required Milan protections",
            ),
            (
                vec![product("Genoa", "0x000000000213013a")],
                "required Genoa protections",
            ),
            (
                vec![product("Milan", "0x000000000213012f")],
                "ABI 1.47 is older",
            ),
            (
                vec![product("Venice", "0x000000000253013a")],
                "unsupported AMD product",
            ),
            (
                vec![
                    product("Milan", "0x000000000213013a"),
                    product("Genoa", "0x000000000253013a"),
                ],
                "not sorted by product",
            ),
            (
                vec![
                    product("Milan", "0x000000000213013a"),
                    product("Milan", "0x000000000213013a"),
                ],
                "duplicated",
            ),
        ] {
            let error = with(policies).unwrap_err().to_string();
            assert!(error.contains(message), "{error}");
        }
    }

    #[test]
    fn release_manifest_rejects_nonzero_vmpl() {
        let mut release = release_fixture();
        release.document.sev_snp.launch_policies.policies[0]
            .launch
            .vmpl = 1;
        let error = validate_gateway_release_manifest(&release.document).unwrap_err();
        assert!(error.to_string().contains("invalid gateway launch policy"));
    }

    #[test]
    fn release_evidence_rejects_ambiguous_envelopes_and_unsupported_documents() {
        for (document, gateway) in [
            (serde_json::to_value(release_fixture()).unwrap(), true),
            (serde_json::to_value(catalog_fixture()).unwrap(), false),
        ] {
            let valid = |value: Value| {
                if gateway {
                    serde_json::from_value::<AllowedIgvm>(value).is_ok_and(|release| {
                        validate_gateway_release_manifest(&release.document).is_ok()
                    })
                } else {
                    serde_json::from_value::<AllowedCatalog>(value)
                        .is_ok_and(|release| validate_catalog_shape(&release.document).is_ok())
                }
            };
            assert!(valid(document.clone()));
            let mut extended = document.clone();
            extended["signature"] = Value::Null;
            assert!(!valid(extended));
            for schema in [Value::Null, 1.into(), "".into(), "unsupported".into()] {
                let mut changed = document.clone();
                changed["document"]["schema"] = schema;
                assert!(!valid(changed));
            }
        }
    }

    #[test]
    fn staging_release_policy_is_fixed_by_the_compiled_artifact() {
        let mut release = release_fixture();
        let canonical = canonical_json(&serde_json::to_value(&release.document).unwrap()).unwrap();
        let manifest_digest = hex::encode(Sha256::digest(canonical.as_bytes()));
        release.provenance = serde_json::json!({
            "_type": "https://in-toto.io/Statement/v1",
            "predicateType": "https://stogas.ai/attestations/staging-development/v1",
            "predicate": { "environment": "staging" },
            "subject": [
                { "name": "release-manifest.json", "digest": { "sha256": manifest_digest } },
                { "name": "gateway.igvm", "digest": { "sha256": release.document.artifacts.gateway_igvm.sha256 } }
            ]
        });

        #[cfg(feature = "staging")]
        {
            let verified = verify_gateway_release(&release, embedded(), 1_784_246_400_000).unwrap();
            assert!(verified.github_integrated_time_unix_ms.is_none());
            assert!(matches!(verified.provenance, ReleaseProvenance::Staging));

            for subject in 0..2 {
                let mut changed = release.clone();
                changed.provenance["subject"][subject]["digest"]["sha256"] =
                    Value::String("00".repeat(32));
                assert!(verify_gateway_release(&changed, embedded(), 1_784_246_400_000).is_err());
            }
            let mut missing = release;
            missing.provenance["subject"].as_array_mut().unwrap().pop();
            assert!(verify_gateway_release(&missing, embedded(), 1_784_246_400_000).is_err());
        }
        #[cfg(not(feature = "staging"))]
        assert!(verify_gateway_release(&release, embedded(), 1_784_246_400_000).is_err());
    }

    #[test]
    fn staging_catalog_policy_is_fixed_by_the_compiled_artifact() {
        let mut catalog = catalog_fixture();
        let canonical = canonical_json(&serde_json::to_value(&catalog.document).unwrap()).unwrap();
        let manifest_digest = hex::encode(Sha256::digest(canonical.as_bytes()));
        catalog.provenance = serde_json::json!({
            "_type": "https://in-toto.io/Statement/v1",
            "predicateType": "https://stogas.ai/attestations/staging-development/v1",
            "predicate": { "environment": "staging" },
            "subject": [
                { "name": "catalog-release.json", "digest": { "sha256": manifest_digest } },
                { "name": "catalog.runtime.json", "digest": { "sha256": &catalog.document.artifacts.runtime.sha256 } },
                { "name": "catalog.public.json", "digest": { "sha256": &catalog.document.artifacts.public.sha256 } }
            ]
        });

        #[cfg(feature = "staging")]
        {
            let verified = verify_catalog_release(&catalog, embedded(), 1_784_246_400_000).unwrap();
            assert!(verified.github_integrated_time_unix_ms.is_none());
            assert!(matches!(verified.provenance, ReleaseProvenance::Staging));

            for subject in 0..3 {
                let mut changed = catalog.clone();
                changed.provenance["subject"][subject]["digest"]["sha256"] =
                    Value::String("00".repeat(32));
                assert!(verify_catalog_release(&changed, embedded(), 1_784_246_400_000).is_err());
            }
            let mut missing = catalog;
            missing.provenance["subject"].as_array_mut().unwrap().pop();
            assert!(verify_catalog_release(&missing, embedded(), 1_784_246_400_000).is_err());
        }
        #[cfg(not(feature = "staging"))]
        assert!(verify_catalog_release(&catalog, embedded(), 1_784_246_400_000).is_err());
    }

    #[test]
    fn canonical_documents_follow_rfc8785_and_add_one_file_newline() {
        let vectors: Vec<Value> = serde_json::from_str(include_str!(
            "../../../tests/fixtures/canonical-json-v1.json"
        ))
        .unwrap();
        for vector in vectors {
            assert_eq!(
                canonical_json(&vector["input"]).unwrap(),
                format!("{}\n", vector["canonical"].as_str().unwrap()),
                "{}",
                vector["name"]
            );
        }
    }
    #[test]
    fn raw_report_inspection_rejects_unknown_products_versions_and_sizes() {
        let mut report = vec![0_u8; 0x4a0];
        report[..4].copy_from_slice(&2_u32.to_le_bytes());
        report[0x90..0xc0].fill(0x22);
        report[0x180..0x188].fill(0x33);
        report[0x1a0..0x1e0].fill(0x11);
        let identity = inspect_snp_report(&report).unwrap();
        assert_eq!(identity.chip_id, "11".repeat(64));
        assert_eq!(identity.release_measurement, "22".repeat(48));
        assert_eq!(identity.reported_tcb, "33".repeat(8));
        assert_eq!(identity.product_name, None);
        for length in [0, 0x49f, 0x4a1] {
            assert!(inspect_snp_report(&vec![0; length]).is_err());
        }
        for version in [0_u32, 1, 6, u32::MAX] {
            report[..4].copy_from_slice(&version.to_le_bytes());
            assert!(inspect_snp_report(&report).is_err());
        }
        report[..4].copy_from_slice(&5_u32.to_le_bytes());
        for (family, model, expected) in [
            (0x19, 0x0f, "Milan"),
            (0x19, 0x11, "Genoa"),
            (0x19, 0xa0, "Siena"),
        ] {
            report[0x188..0x18b].copy_from_slice(&[family, model, 2]);
            let identity = inspect_snp_report(&report).unwrap();
            assert_eq!(identity.product_name.as_deref(), Some(expected));
            assert_eq!(identity.cpuid_stepping, Some(2));
        }
        report[0x1a8..0x1e0].fill(0);
        report[0x188..0x18b].copy_from_slice(&[0x1a, 0x11, 0]);
        assert_eq!(
            inspect_snp_report(&report).unwrap().product_name.as_deref(),
            Some("Turin")
        );
        report[0x189] = 0x50;
        assert!(inspect_snp_report(&report).is_err());
        report[..4].copy_from_slice(&2_u32.to_le_bytes());
        assert!(inspect_snp_report(&report).is_err());
    }

    #[cfg(feature = "snp")]
    #[test]
    fn amd_crl_signature_requires_the_correct_key_and_matching_pss_parameters() {
        use x509_parser::{parse_x509_certificate, parse_x509_crl};
        let fixture: Value =
            serde_json::from_str(include_str!("../tests/fixtures/amd-crl-test-vectors.json"))
                .unwrap();
        let decode = |field: &str| STANDARD.decode(fixture[field].as_str().unwrap()).unwrap();
        let root = decode("ark_der_base64");
        let (_, ark) = parse_x509_certificate(&root).unwrap();
        let clean = decode("clean_crl_der_base64");
        let (_, crl) = parse_x509_crl(&clean).unwrap();
        verify_amd_crl_signature(&crl, &ark).unwrap();
        for field in [
            "ask_signed_crl_der_base64",
            "wrong_ark_signed_crl_der_base64",
        ] {
            let bytes = decode(field);
            let (_, forged) = parse_x509_crl(&bytes).unwrap();
            assert!(verify_amd_crl_signature(&forged, &ark).is_err());
        }
        let mut mismatch = crl.clone();
        mismatch.tbs_cert_list.signature.parameters = None;
        assert!(
            verify_amd_crl_signature(&mismatch, &ark)
                .unwrap_err()
                .to_string()
                .contains("one matching RSA-PSS")
        );
        mismatch.signature_algorithm.parameters = None;
        assert!(
            verify_amd_crl_signature(&mismatch, &ark)
                .unwrap_err()
                .to_string()
                .contains("invalid RSA-PSS")
        );
    }
}

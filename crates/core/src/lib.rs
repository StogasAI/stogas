#![doc = include_str!("../README.md")]

pub(crate) use stogas_sigstore::{rfc3339, strict_json};
mod kem;
mod types;

pub mod attestation;
pub mod authority;
pub mod channel;
mod csr;
pub mod evidence;
pub mod format;
#[cfg(feature = "gateway")]
pub mod gateway;
pub mod log_batch;
pub mod receipt;
pub mod sdk_release;
pub mod secret_release;
pub mod signing;
pub use types::*;

use base64::{
    Engine as _,
    engine::general_purpose::{STANDARD, URL_SAFE_NO_PAD},
};
#[cfg(feature = "staging")]
use serde::Deserialize;
use serde_json::Value;
use sha2::{Digest, Sha256};
#[cfg(feature = "staging")]
use std::collections::BTreeMap;
use stogas_sev_snp::{PlatformRule, Product, guest_policy};
use stogas_sigstore::{GithubPolicy, Subject, TrustedRoot, verify_github_attestation};
use thiserror::Error;

/// Maximum serialized evidence accepted by public adapters.
pub const MAX_INPUT_BYTES: usize = 16 * 1024 * 1024;
// The formats of the release documents that evidence lists.
pub const GATEWAY_RELEASE_SCHEMA: &str = "stogas.gateway.release.v1";
pub const CATALOG_RELEASE_SCHEMA: &str = "stogas.catalog.release.v2";
pub const LAUNCH_POLICIES_SCHEMA: &str = "stogas.snp-launch-policies.v1";
const MAX_NODES: usize = 1_024;
/// Release sequences stay exact in every JSON consumer.
const MAX_SAFE_INTEGER: u64 = 9_007_199_254_740_991;
const MAX_VENDOR_COLLATERAL: usize = 4_096;
const MAX_CLOCK_SKEW_MS: i64 = 60_000;
/// Guest policy flags that every gateway launch sets: no page swapping, one socket and the
/// reserved bit.
const LAUNCH_REQUIRED: u64 =
    guest_policy::PAGE_SWAP_DISABLE | guest_policy::SINGLE_SOCKET | guest_policy::RESERVED_ONE;
/// Flags that no gateway launch sets: CXL, debugging and a migration agent.
const LAUNCH_FORBIDDEN: u64 =
    guest_policy::CXL_ALLOW | guest_policy::DEBUG | guest_policy::MIGRATE_MA;
/// The oldest firmware ABI that gateways launch on.
const LAUNCH_MINIMUM_ABI: (u8, u8) = (1, 58);
#[cfg(feature = "staging")]
const STAGING_PROVENANCE_TYPE: &str = "https://stogas.ai/attestations/staging-development/v1";
const STOGAS_SIGNATURE_DOMAIN: &[u8] = b"stogas signed document v1\n";

/// The flags that a product's gateway launches set. Genoa and later encrypt memory with
/// AES-256-XTS, which Milan cannot.
const fn launch_required(product: Product) -> u64 {
    match product {
        Product::Milan => LAUNCH_REQUIRED,
        Product::Genoa | Product::Turin => LAUNCH_REQUIRED | guest_policy::MEM_AES_256_XTS,
    }
}

fn validate_snp_launch_policy(policy: u64, product: Product) -> Result<(), Error> {
    if policy >> 26 != 0 {
        return Err(Error::Node(
            "authorized SNP launch policy sets reserved high bits".into(),
        ));
    }
    let required = launch_required(product);
    if policy & required != required {
        return Err(Error::Node(format!(
            "authorized SNP launch policy lacks required {product} protections"
        )));
    }
    if policy & LAUNCH_FORBIDDEN != 0 {
        return Err(Error::Node(
            "authorized SNP launch policy permits CXL, debugging, or migration".into(),
        ));
    }
    let (major, minor) = guest_policy::abi(policy);
    let (minimum_major, minimum_minor) = LAUNCH_MINIMUM_ABI;
    if (major, minor) < LAUNCH_MINIMUM_ABI {
        return Err(Error::Node(format!(
            "authorized SNP launch policy ABI {major}.{minor} is older than required {minimum_major}.{minimum_minor}"
        )));
    }
    Ok(())
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
    #[error("input exceeds {MAX_INPUT_BYTES} bytes")]
    TooLarge,
    #[error("invalid JSON: {0}")]
    InvalidJson(String),
    #[error("unsupported or invalid evidence: {0}")]
    InvalidEvidence(String),
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
/// Rejects a report that breaks AMD's encoding or comes from an unsupported processor.
pub fn inspect_snp_report(report: &[u8]) -> Result<InspectedSnpQuote, Error> {
    let report =
        stogas_sev_snp::Report::parse(report).map_err(|error| Error::Node(error.to_string()))?;
    let cpuid = report.cpuid();
    Ok(InspectedSnpQuote {
        chip_id: hex::encode(report.chip_id()),
        cpuid_family: cpuid.map(|cpuid| cpuid[0]),
        cpuid_model: cpuid.map(|cpuid| cpuid[1]),
        cpuid_stepping: cpuid.map(|cpuid| cpuid[2]),
        product_name: report.product().map(|product| product.name().into()),
        release_measurement: hex::encode(report.measurement()),
        report_version: report.version(),
        reported_tcb: hex::encode(report.reported_tcb().to_bytes()),
    })
}

/// The path on AMD's Key Distribution Service of a chip's VCEK at a reported TCB, from the
/// product, chip ID and reported TCB that a report inspection or a VCEK collateral row gives.
///
/// # Errors
/// Rejects an unsupported product, noncanonical hexadecimal and a chip or TCB that KDS does not
/// serve.
pub fn amd_vcek_path(
    product_name: &str,
    chip_id: &str,
    reported_tcb: &str,
) -> Result<String, Error> {
    fn bytes<const N: usize>(value: &str, label: &str) -> Result<[u8; N], Error> {
        is_lower_hex(value, N)
            .then(|| hex::decode(value).ok()?.try_into().ok())
            .flatten()
            .ok_or_else(|| {
                Error::Node(format!("{label} is not {N} bytes of lowercase hexadecimal"))
            })
    }
    let node = |error: stogas_sev_snp::Error| Error::Node(error.to_string());
    let product: Product = product_name.parse().map_err(node)?;
    let tcb = stogas_sev_snp::TcbVersion::from_bytes(bytes(reported_tcb, "reported TCB")?, product)
        .map_err(node)?;
    stogas_sev_snp::kds::vcek_path(product, &bytes(chip_id, "chip ID")?, tcb).map_err(node)
}

/// Check the signed hardware policy and turn its groups into platform rules. Every group lists
/// its chips and names their processor and minimum TCB, and groups are unique and sorted.
fn validate_hardware_policies(policies: &[AmdSevSnpPolicy]) -> Result<Vec<PlatformRule>, Error> {
    if policies.is_empty() || policies.len() > MAX_NODES {
        return Err(Error::InvalidEvidence(
            "hardware policy is empty or too large".into(),
        ));
    }
    let mut previous_group: Option<String> = None;
    let mut rules = Vec::with_capacity(policies.len());
    for policy in policies {
        if policy.chip_ids.is_empty() || policy.chip_ids.len() > MAX_NODES {
            return Err(Error::InvalidEvidence(
                "hardware policy group has no chip ids or is too large".into(),
            ));
        }
        if policy.chip_ids.iter().enumerate().any(|(index, chip_id)| {
            !is_lower_hex(chip_id, 64) || index > 0 && policy.chip_ids[index - 1] >= *chip_id
        }) {
            return Err(Error::InvalidEvidence(
                "hardware policy has an invalid, unsorted, or duplicate chip id".into(),
            ));
        }
        let group = canonical_json(
            &serde_json::to_value(policy)
                .map_err(|error| Error::InvalidEvidence(format!("hardware policy: {error}")))?,
        )?;
        if previous_group
            .as_ref()
            .is_some_and(|previous| previous >= &group)
        {
            return Err(Error::InvalidEvidence(
                "hardware policy groups are duplicated or not canonically ordered".into(),
            ));
        }
        previous_group = Some(group);
        let rule = platform_rule(policy)?;
        rule.validate()
            .map_err(|error| Error::InvalidEvidence(format!("hardware policy: {error}")))?;
        rules.push(rule);
    }
    Ok(rules)
}

/// The rule of one hardware policy group. Gateways accept firmware that a host updated but has
/// not committed, as long as the committed firmware meets the same minimums, so that a host can
/// apply an AMD fix without its gateways failing verification. The TCB minimum also applies to
/// the TCB that a gateway launched with.
fn platform_rule(policy: &AmdSevSnpPolicy) -> Result<PlatformRule, Error> {
    Ok(PlatformRule {
        product: None,
        cpuid_family: Some(policy.cpuid_family),
        cpuid_model: Some(policy.cpuid_model),
        cpuid_stepping: Some(policy.cpuid_stepping),
        chip_ids: policy
            .chip_ids
            .iter()
            .map(|chip_id| {
                hex::decode(chip_id)
                    .ok()
                    .and_then(|chip_id| chip_id.try_into().ok())
                    .ok_or_else(|| {
                        Error::InvalidEvidence("hardware policy chip id is invalid".into())
                    })
            })
            .collect::<Result<_, _>>()?,
        minimum_tcb: Some(policy.minimum_tcb),
        minimum_launch_tcb: None,
        minimum_firmware_version: None,
        permit_provisional_firmware: true,
        required_platform_info_mask: parse_u64_hex(
            &policy.required_platform_info_mask,
            "required platform-info mask",
        )?,
        forbidden_platform_info_mask: parse_u64_hex(
            &policy.forbidden_platform_info_mask,
            "forbidden platform-info mask",
        )?,
        required_launch_mitigation_mask: parse_u64_hex(
            &policy.required_launch_mitigation_mask,
            "required launch mitigation mask",
        )?,
        required_current_mitigation_mask: parse_u64_hex(
            &policy.required_current_mitigation_mask,
            "required current mitigation mask",
        )?,
    })
}

fn parse_u64_hex(value: &str, label: &str) -> Result<u64, Error> {
    let hex = value
        .strip_prefix("0x")
        .filter(|hex| is_lower_hex(hex, 8))
        .ok_or_else(|| Error::InvalidEvidence(format!("hardware policy {label} is invalid")))?;
    u64::from_str_radix(hex, 16)
        .map_err(|_| Error::InvalidEvidence(format!("hardware policy {label} is invalid")))
}

/// Gateways and Web reject a larger catalog root, and the catalog build refuses one.
const CATALOG_ROOT_MAX_BYTES: u64 = 16 * 1024 * 1024;

fn validate_catalog_shape(manifest: &CatalogReleaseManifest) -> Result<(), Error> {
    if manifest.schema != CATALOG_RELEASE_SCHEMA
        || manifest.minimum_gateway_sequence == 0
        || manifest.minimum_gateway_sequence > MAX_SAFE_INTEGER
        || manifest.sequence == 0
        || manifest.sequence > MAX_SAFE_INTEGER
        || manifest.source.repository != "https://github.com/StogasAI/catalog"
        || manifest.source.tag != format!("catalog-v{}", manifest.sequence)
        || !is_lower_hex(&manifest.source.commit, 20)
        || !is_lower_hex(&manifest.source.sha256, 32)
        || !valid_artifact(&manifest.artifacts.root, CATALOG_ROOT_MAX_BYTES)
    {
        return Err(Error::InvalidEvidence(
            "invalid catalog release shape".into(),
        ));
    }
    Ok(())
}

fn valid_artifact(artifact: &ReleaseArtifact, maximum_bytes: u64) -> bool {
    is_lower_hex(&artifact.sha256, 32) && (1..=maximum_bytes).contains(&artifact.size_bytes)
}

fn validate_gateway_release_manifest(manifest: &GatewayReleaseManifest) -> Result<(), Error> {
    if !gateway_release_manifest_shape_is_valid(manifest) {
        return Err(Error::InvalidEvidence(
            "invalid gateway release manifest shape".into(),
        ));
    }
    validate_gateway_release_build(&manifest.build)?;
    validate_gateway_launch_policies(&manifest.sev_snp.launch_policies)?;
    let launch_policies = canonical_json(
        &serde_json::to_value(&manifest.sev_snp.launch_policies).map_err(|error| {
            Error::InvalidEvidence(format!("launch policy serialization: {error}"))
        })?,
    )?;
    let launch_policies_sha256 = hex::encode(Sha256::digest(launch_policies.as_bytes()));
    if manifest
        .build
        .input_sha256
        .get("stogas/release/snp-launch-policies.json")
        != Some(&launch_policies_sha256)
    {
        return Err(Error::InvalidEvidence(
            "gateway launch policy artifact does not match the release manifest".into(),
        ));
    }
    Ok(())
}

fn gateway_release_manifest_shape_is_valid(manifest: &GatewayReleaseManifest) -> bool {
    let sev_snp = &manifest.sev_snp;
    let build = &manifest.build;
    manifest.schema == GATEWAY_RELEASE_SCHEMA
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
        "stogas/release/guix/cmdline.txt",
        "stogas/release/guix/os-release",
        "stogas/release/pins.lock.json",
    ] {
        if !build.input_sha256.contains_key(path) {
            return Err(Error::InvalidEvidence(format!(
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
            return Err(Error::InvalidEvidence(
                "gateway release build digest is invalid".into(),
            ));
        }
    }
    if build
        .input_sha256
        .iter()
        .any(|(name, digest)| name.is_empty() || name.len() > 256 || !is_lower_hex(digest, 32))
    {
        return Err(Error::InvalidEvidence(
            "gateway release build input is invalid".into(),
        ));
    }
    Ok(())
}

fn validate_gateway_launch_policies(policies: &LaunchPolicies) -> Result<(), Error> {
    if policies.schema != LAUNCH_POLICIES_SCHEMA || policies.policies.is_empty() {
        return Err(Error::InvalidEvidence(
            "invalid gateway launch policies".into(),
        ));
    }
    let mut previous_product: Option<&str> = None;
    for policy in &policies.policies {
        let product_name = policy.product_name.as_str();
        if previous_product.is_some_and(|previous| previous >= product_name) {
            return Err(Error::InvalidEvidence(
                "gateway launch policies are duplicated or not sorted by product".into(),
            ));
        }
        previous_product = Some(product_name);
        let product = product_name.parse::<Product>().map_err(|_| {
            Error::InvalidEvidence("gateway launch policy names an unsupported AMD product".into())
        })?;
        validate_gateway_launch_policy(&policy.launch, product)?;
    }
    Ok(())
}

fn validate_gateway_launch_policy(launch: &LaunchValues, product: Product) -> Result<(), Error> {
    if !is_lower_hex(&launch.family_id, 16)
        || !is_lower_hex(&launch.image_id, 16)
        || !is_lower_hex(&launch.host_data, 32)
        || !is_lower_hex(&launch.id_key_digest, 48)
        || !is_lower_hex(&launch.author_key_digest, 48)
        || launch.vmpl != 0
        || !is_prefixed_lower_hex(&launch.policy, 8)
    {
        return Err(Error::InvalidEvidence(
            "invalid gateway launch policy".into(),
        ));
    }
    let launch_policy = u64::from_str_radix(&launch.policy[2..], 16)
        .map_err(|_| Error::InvalidEvidence("invalid SNP launch policy".into()))?;
    validate_snp_launch_policy(launch_policy, product)
        .map_err(|error| Error::InvalidEvidence(format!("invalid gateway launch policy: {error}")))
}

/// Launch values depend on the processor generation, not on the individual chip, so a new host
/// of an admitted generation needs only a hardware-policy change.
fn compatible_launch_policy(
    policies: &LaunchPolicies,
    product: Product,
) -> Result<&LaunchValues, Error> {
    policies
        .policies
        .iter()
        .find(|policy| policy.product_name == product.name())
        .map(|policy| &policy.launch)
        .ok_or_else(|| {
            Error::Node(format!(
                "the release has no launch policy for AMD {product}"
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
) -> Result<VerifiedCatalogRelease, Error> {
    let manifest = &catalog.document;
    validate_catalog_shape(manifest)?;
    let manifest_digest = release_manifest_sha256(manifest)?;
    let attestation_bytes = serde_json::to_vec(&catalog.provenance)
        .map_err(|error| Error::Release(error.to_string()))?;
    let (github_integrated_time_unix_ms, provenance) =
        verify_catalog_provenance(&attestation_bytes, manifest, &manifest_digest, trust)?;

    Ok(VerifiedCatalogRelease {
        github_integrated_time_unix_ms,
        minimum_gateway_sequence: manifest.minimum_gateway_sequence,
        provenance,
        root_digest: format!("sha256:{}", manifest.artifacts.root.sha256),
        root_size_bytes: manifest.artifacts.root.size_bytes,
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
) -> Result<(Option<i64>, ReleaseProvenance), Error> {
    #[cfg(feature = "staging")]
    if is_staging_development_provenance(
        attestation_bytes,
        &[
            ("catalog-release.json", manifest_digest),
            ("catalog.json", &manifest.artifacts.root.sha256),
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
                name: "catalog.json",
                sha256: &manifest.artifacts.root.sha256,
            },
        ],
        &GithubPolicy {
            repository: manifest.source.repository.clone(),
            workflow_identity,
            source_ref: format!("refs/tags/{}", manifest.source.tag),
            source_commit: manifest.source.commit.clone(),
            predicate_type: "https://slsa.dev/provenance/v1".into(),
        },
        "catalog provenance",
    )
}

fn verify_gateway_release(
    release: &AllowedIgvm,
    trust: &TrustedRoot,
) -> Result<VerifiedRelease, Error> {
    let manifest = &release.document;
    validate_gateway_release_manifest(manifest)?;
    let manifest_digest = release_manifest_sha256(manifest)?;
    let attestation_bytes = serde_json::to_vec(&release.provenance)
        .map_err(|error| Error::Release(error.to_string()))?;
    let (github_integrated_time_unix_ms, provenance) =
        verify_release_provenance(&attestation_bytes, manifest, &manifest_digest, trust)?;

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
        },
        "gateway provenance",
    )
}

fn verify_github_provenance(
    trust: &TrustedRoot,
    attestation_bytes: &[u8],
    expected_subjects: &[Subject<'_>],
    policy: &GithubPolicy,
    context: &str,
) -> Result<(Option<i64>, ReleaseProvenance), Error> {
    let verified = verify_github_attestation(trust, attestation_bytes, expected_subjects, policy)
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
        .map_err(|error| Error::InvalidEvidence(format!("canonical JSON: {error}")))?;
    output.push('\n');
    Ok(output)
}

#[cfg(test)]
mod tests {

    use super::*;
    use stogas_sev_snp::PlatformFacts;

    fn production() -> &'static TrustedRoot {
        authority::sigstore_fixture().1.trusted_root()
    }

    fn milan_policies() -> Vec<AmdSevSnpPolicy> {
        serde_json::from_str(include_str!("../tests/fixtures/milan-hardware-policy.json")).unwrap()
    }

    /// The firmware state of the staging Milan host, which its policy admits.
    fn milan_facts() -> PlatformFacts {
        let registration: Value = serde_json::from_str(include_str!(
            "../../../tests/fixtures/hardware-registration-v1.json"
        ))
        .unwrap();
        let report = URL_SAFE_NO_PAD
            .decode(registration["boot"]["report"].as_str().unwrap())
            .unwrap();
        stogas_sev_snp::Report::parse(&report).unwrap().facts()
    }

    fn appraise(policies: &[AmdSevSnpPolicy], facts: &PlatformFacts) -> bool {
        let rules = validate_hardware_policies(policies).unwrap();
        let chip: [u8; 64] = hex::decode(&policies[0].chip_ids[0])
            .unwrap()
            .try_into()
            .unwrap();
        PlatformRule::find(&rules, Product::Milan, &chip, facts).is_ok()
    }

    #[test]
    fn groups_exact_chip_ids_under_shared_hardware_requirements() {
        let policies = milan_policies();
        let rules = validate_hardware_policies(&policies).unwrap();
        assert_eq!(
            hex::encode(rules[0].chip_ids.concat()),
            policies[0].chip_ids[0]
        );
        assert!(appraise(&policies, &milan_facts()));
        assert!(PlatformRule::find(&rules, Product::Milan, &[0; 64], &milan_facts()).is_err());
    }

    #[test]
    fn hardware_policy_alternatives_are_unique_canonical_and_individually_valid() {
        let mut policies = milan_policies();
        let mut alternative = policies[0].clone();
        alternative.forbidden_platform_info_mask = "0x0000000000000001".into();
        policies.push(alternative);
        validate_hardware_policies(&policies).unwrap();

        let mut invalid = policies.clone();
        invalid.reverse();
        assert!(validate_hardware_policies(&invalid).is_err());
        invalid = policies.clone();
        invalid[1] = invalid[0].clone();
        assert!(validate_hardware_policies(&invalid).is_err());
        invalid = policies.clone();
        let repeated_chip = invalid[0].chip_ids[0].clone();
        invalid[1].chip_ids.push(repeated_chip);
        assert!(validate_hardware_policies(&invalid).is_err());
        invalid = policies.clone();
        invalid[1].chip_ids[0] = invalid[1].chip_ids[0].to_uppercase();
        assert!(validate_hardware_policies(&invalid).is_err());
        invalid = policies.clone();
        invalid[1].required_platform_info_mask = "0x0000000000000025".into();
        assert!(validate_hardware_policies(&invalid).is_err());
        invalid = policies.clone();
        invalid[1].cpuid_family = 0;
        assert!(validate_hardware_policies(&invalid).is_err());
        // A Milan minimum has no FMC SPL, which only Turin's TCB carries.
        invalid = policies;
        invalid[1].minimum_tcb.fmc = Some(0);
        assert!(validate_hardware_policies(&invalid).is_err());
        assert!(validate_hardware_policies(&[]).is_err());
    }

    #[test]
    fn hardware_transitions_match_one_complete_configuration() {
        let policy = milan_policies().remove(0);
        let mut smt_on = policy.clone();
        smt_on.required_platform_info_mask = "0x0000000000000025".into();
        smt_on.minimum_tcb.microcode = 223;
        let mut smt_off = policy;
        smt_off.forbidden_platform_info_mask = "0x0000000000000001".into();
        let transition = [smt_on.clone(), smt_off.clone()];
        let only_on = [smt_on];
        let only_off = [smt_off];
        for (policies, platform_info, microcode, allowed) in [
            (&transition[..], 0x25_u64, 223, true),
            (&transition, 0x24, 222, true), // The first configuration fails, the second passes.
            (&transition, 0x25, 222, false), // Cannot borrow the SMT-off TCB minimum.
            (&transition, 0x24, 221, false),
            (&only_off, 0x25, 223, false),
            (&only_off, 0x24, 222, true),
            (&only_on, 0x24, 223, false),
            (&only_on, 0x25, 223, true),
        ] {
            let mut facts = milan_facts();
            facts.platform_info = platform_info;
            for tcb in [
                &mut facts.current_tcb,
                &mut facts.reported_tcb,
                &mut facts.committed_tcb,
                &mut facts.launch_tcb,
            ] {
                tcb.microcode = microcode;
            }
            assert_eq!(
                appraise(policies, &facts),
                allowed,
                "platform={platform_info:#x} microcode={microcode}"
            );
        }
    }

    #[test]
    fn hosts_may_run_uncommitted_firmware_whose_committed_version_meets_the_minimum() {
        let policies = milan_policies();
        let mut facts = milan_facts();
        facts.current_tcb.microcode = 223;
        facts.current_version.build = 22;
        assert!(appraise(&policies, &facts));
        // The host could roll back to committed firmware below the minimum.
        facts.committed_tcb.microcode = 221;
        assert!(!appraise(&policies, &facts));
        // Committed firmware is never newer than the firmware that runs.
        let mut facts = milan_facts();
        facts.committed_version.build = 22;
        assert!(!appraise(&policies, &facts));
        // A gateway launched before the host met the minimum stays rejected.
        let mut facts = milan_facts();
        facts.launch_tcb.snp = 28;
        assert!(!appraise(&policies, &facts));
    }

    /// The onion address of an Ed25519 key, with the checksum computed for `version`.
    pub fn onion_address(key: [u8; 32], version: u8) -> String {
        let mut input = b".onion checksum".to_vec();
        input.extend_from_slice(&key);
        input.push(version);
        let mut raw = key.to_vec();
        raw.extend_from_slice(&libcrux_sha3::sha256(&input)[..2]);
        raw.push(version);
        let alphabet = b"abcdefghijklmnopqrstuvwxyz234567";
        let mut label = String::new();
        for chunk in raw.chunks(5) {
            let bits = chunk
                .iter()
                .fold(0_u64, |bits, byte| bits << 8 | u64::from(*byte));
            for shift in (0..8).rev() {
                label.push(char::from(
                    alphabet[usize::try_from(bits >> (shift * 5) & 31).unwrap()],
                ));
            }
        }
        format!("{label}.onion")
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
                    "guix_channel_commit": "19".repeat(20),
                    "input_sha256": {
                        "stogas/release/guix/cmdline.txt": "12".repeat(32),
                        "core/go.mod": "13".repeat(32),
                        "core/go.sum": "14".repeat(32),
                        "transports/go.mod": "15".repeat(32),
                        "transports/go.sum": "16".repeat(32),
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
                    "catalog.json": { "sha256": "11".repeat(32), "size_bytes": 1 }
                },
                "schema": "stogas.catalog.release.v2",
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
            // Siena takes Genoa's certificates and launch values.
            (
                vec![product("Siena", "0x000000000253013a")],
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
    fn catalog_root_stays_within_the_size_that_gateways_and_web_accept() {
        for (size, valid) in [
            (0, false),
            (1, true),
            (16 * 1024 * 1024, true),
            (16 * 1024 * 1024 + 1, false),
        ] {
            let mut catalog = catalog_fixture();
            catalog.document.artifacts.root.size_bytes = size;
            assert_eq!(validate_catalog_shape(&catalog.document).is_ok(), valid);
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
            let verified = verify_gateway_release(&release, production()).unwrap();
            assert!(verified.github_integrated_time_unix_ms.is_none());
            assert!(matches!(verified.provenance, ReleaseProvenance::Staging));

            for subject in 0..2 {
                let mut changed = release.clone();
                changed.provenance["subject"][subject]["digest"]["sha256"] =
                    Value::String("00".repeat(32));
                assert!(verify_gateway_release(&changed, production()).is_err());
            }
            let mut missing = release;
            missing.provenance["subject"].as_array_mut().unwrap().pop();
            assert!(verify_gateway_release(&missing, production()).is_err());
        }
        #[cfg(not(feature = "staging"))]
        assert!(verify_gateway_release(&release, production()).is_err());
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
                { "name": "catalog.json", "digest": { "sha256": &catalog.document.artifacts.root.sha256 } }
            ]
        });

        #[cfg(feature = "staging")]
        {
            let verified = verify_catalog_release(&catalog, production()).unwrap();
            assert!(verified.github_integrated_time_unix_ms.is_none());
            assert!(matches!(verified.provenance, ReleaseProvenance::Staging));

            for subject in 0..2 {
                let mut changed = catalog.clone();
                changed.provenance["subject"][subject]["digest"]["sha256"] =
                    Value::String("00".repeat(32));
                assert!(verify_catalog_release(&changed, production()).is_err());
            }
            let mut missing = catalog;
            missing.provenance["subject"].as_array_mut().unwrap().pop();
            assert!(verify_catalog_release(&missing, production()).is_err());
        }
        #[cfg(not(feature = "staging"))]
        assert!(verify_catalog_release(&catalog, production()).is_err());
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
    fn report_inspection_reads_selectors_from_reports_that_amd_defines() {
        let fixture = |name: &str| {
            std::fs::read(format!(
                "{}/../../tests/fixtures/sev-snp/{name}",
                env!("CARGO_MANIFEST_DIR")
            ))
            .unwrap()
        };
        let report = fixture("gcp-milan/report-vmpl0.bin");
        let identity = inspect_snp_report(&report).unwrap();
        assert_eq!(identity.chip_id, hex::encode(&report[0x1a0..0x1e0]));
        assert_eq!(
            identity.release_measurement,
            hex::encode(&report[0x90..0xc0])
        );
        assert_eq!(identity.reported_tcb, "0400000000001fe1");
        assert_eq!(identity.report_version, 5);
        assert_eq!(identity.product_name.as_deref(), Some("Milan"));
        assert_eq!(
            (
                identity.cpuid_family,
                identity.cpuid_model,
                identity.cpuid_stepping
            ),
            (Some(0x19), Some(0x01), Some(0x01))
        );
        // KDS serves Siena's certificates as Genoa's.
        let siena = inspect_snp_report(&fixture("attestation-rs/siena-report.bin")).unwrap();
        assert_eq!(siena.product_name.as_deref(), Some("Genoa"));
        assert_eq!(siena.cpuid_model, Some(0xa0));
        // Version 2 reports carry no CPUID.
        let old = inspect_snp_report(&fixture("go-sev-guest/report.bin")).unwrap();
        assert_eq!(
            (old.report_version, old.product_name, old.cpuid_family),
            (2, None, None)
        );

        for length in [0, 0x49f, 0x4a1] {
            assert!(inspect_snp_report(&vec![0; length]).is_err());
        }
        for (offset, value) in [(0x00, 7), (0x189, 0x50), (0x4c, 1)] {
            let mut changed = report.clone();
            changed[offset] = value;
            assert!(inspect_snp_report(&changed).is_err(), "{offset:#x}");
        }
    }

    #[test]
    fn vcek_paths_follow_each_products_chip_and_tcb_layout() {
        let milan = "ab".repeat(64);
        assert_eq!(
            amd_vcek_path("Milan", &milan, "0400000000001fe1").unwrap(),
            format!("/vcek/v1/Milan/{milan}?blSPL=4&teeSPL=0&snpSPL=31&ucodeSPL=225")
        );
        let turin = format!("1e550a8ee5cf9f4d{}", "00".repeat(56));
        assert_eq!(
            amd_vcek_path("Turin", &turin, "0102030400000009").unwrap(),
            "/vcek/v1/Turin/1e550a8ee5cf9f4d?fmcSPL=1&blSPL=2&teeSPL=3&snpSPL=4&ucodeSPL=9"
        );
        for (product, chip, tcb) in [
            ("Siena", milan.as_str(), "0400000000001fe1"),
            ("Milan", &milan.to_uppercase(), "0400000000001fe1"),
            ("Turin", &milan, "0102030400000009"),
            // Milan reserves bytes 2 to 5, and KDS serves SPLs up to 127.
            ("Milan", &milan, "0400010000001fe1"),
            ("Milan", &milan, "8000000000001fe1"),
        ] {
            assert!(
                amd_vcek_path(product, chip, tcb).is_err(),
                "{product} {tcb}"
            );
        }
    }
}

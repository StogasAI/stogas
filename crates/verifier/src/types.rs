use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::collections::BTreeMap;

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct LoggedDocument<T> {
    pub document: T,
    pub signature: StogasSignature,
    pub inclusion: Value,
}

/// A release manifest and the build proof that names its files. The signed approval
/// manifest that lists it is the only Stogas signature over it.
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ReleaseEvidence<T> {
    pub document: T,
    pub provenance: Value,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct HardwarePolicy {
    pub policies: Vec<AmdSevSnpPolicy>,
    pub schema: String,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct AmdSevSnpPolicy {
    pub chip_ids: Vec<String>,
    pub cpuid_family: u8,
    pub cpuid_model: u8,
    pub cpuid_stepping: u8,
    pub forbidden_platform_info_mask: String,
    pub minimum_tcb: AmdTcb,
    pub required_current_mitigation_mask: String,
    pub required_launch_mitigation_mask: String,
    pub required_platform_info_mask: String,
}

#[derive(Clone, Copy, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct AmdTcb {
    pub bootloader: u8,
    pub microcode: u8,
    pub snp: u8,
    pub tee: u8,
}

pub type AllowedCatalog = ReleaseEvidence<CatalogReleaseManifest>;

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct CatalogReleaseManifest {
    pub minimum_gateway_sequence: u64,
    pub artifacts: CatalogReleaseArtifacts,
    pub schema: String,
    pub sequence: u64,
    pub source: ReleaseSource,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct CatalogReleaseArtifacts {
    #[serde(rename = "catalog.public.json")]
    pub public: ReleaseArtifact,
    #[serde(rename = "catalog.runtime.json")]
    pub runtime: ReleaseArtifact,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ReleaseSource {
    pub commit: String,
    pub repository: String,
    /// SHA-256 of the canonical JSON list of every source file's path, mode and SHA-256.
    pub sha256: String,
    pub tag: String,
}

pub type AllowedIgvm = ReleaseEvidence<GatewayReleaseManifest>;

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct GatewayReleaseManifest {
    pub artifacts: GatewayReleaseArtifacts,
    pub build: GatewayReleaseBuild,
    pub source: ReleaseSource,
    pub schema: String,
    pub sequence: u64,
    pub sev_snp: GatewayReleaseSevSnp,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct GatewayReleaseArtifacts {
    #[serde(rename = "gateway.igvm")]
    pub gateway_igvm: ReleaseArtifact,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ReleaseArtifact {
    pub sha256: String,
    pub size_bytes: u64,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct GatewayReleaseBuild {
    pub environment: GatewayReleaseBuildEnvironment,
    pub go_vendor_tree_sha256: String,
    pub go_version: String,
    pub guest_ca_bundle_path: String,
    pub guix_channel_commit: String,
    pub input_sha256: BTreeMap<String, String>,
    pub kernel_config_sha256: String,
    pub kernel_version: String,
    pub linux_bz_image_sha256: String,
    pub ovmf_sha256: String,
    pub systemd_stub_sha256: String,
    pub uki_sha256: String,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct GatewayReleaseBuildEnvironment {
    pub lc_all: String,
    pub source_date_epoch: String,
    pub tz: String,
    pub umask: String,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct GatewayReleaseSevSnp {
    pub check_kvm: bool,
    pub launch_measurement: String,
    pub launch_policies: LaunchPolicies,
    pub measurement_command: String,
    pub measurement_tool: String,
    pub measurement_tool_sha256: String,
    pub measurement_tool_version: String,
    pub platform: String,
    pub vcpu_count: u16,
    pub vmm: String,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct LaunchValues {
    pub author_key_digest: String,
    pub family_id: String,
    pub host_data: String,
    pub id_key_digest: String,
    pub image_id: String,
    pub policy: String,
    pub vmpl: u8,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct LaunchPolicies {
    pub policies: Vec<AmdSevSnpLaunchPolicy>,
    pub schema: String,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct AmdSevSnpLaunchPolicy {
    pub launch: LaunchValues,
    pub product_name: String,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct StogasSignature {
    pub key_id: String,
    pub signature: String,
}

/// Identity fields extracted from an untrusted raw report for collateral lookup only.
#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct InspectedSnpQuote {
    pub chip_id: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub cpuid_family: Option<u8>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub cpuid_model: Option<u8>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub cpuid_stepping: Option<u8>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub product_name: Option<String>,
    pub release_measurement: String,
    pub report_version: u32,
    pub reported_tcb: String,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct VendorCollateral {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub chip_id: Option<String>,
    pub collateral_type: String,
    pub fetched_at: String,
    pub payload: BTreeMap<String, Value>,
    pub sha256: String,
    pub source_url: String,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ReleaseProvenance {
    Github,
    #[cfg(feature = "staging")]
    Staging,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct VerifiedRelease {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub github_integrated_time_unix_ms: Option<i64>,
    pub igvm_sha256: String,
    pub launch_policies: LaunchPolicies,
    pub measurement: String,
    pub provenance: ReleaseProvenance,
    pub release_tag: String,
    pub release_manifest_sha256: String,
    pub sequence: u64,
    pub source_commit: String,
    pub source_repository: String,
    pub source_sha256: String,
    pub vcpu_count: u16,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct VerifiedCatalogRelease {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub github_integrated_time_unix_ms: Option<i64>,
    pub minimum_gateway_sequence: u64,
    pub provenance: ReleaseProvenance,
    pub public_digest: String,
    pub public_size_bytes: u64,
    pub runtime_digest: String,
    pub runtime_size_bytes: u64,
    pub sequence: u64,
    pub source_commit: String,
    pub source_repository: String,
    pub source_sha256: String,
    pub source_tag: String,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct VerifiedHardwarePolicy {
    pub chip_ids: Vec<String>,
    pub policy_count: usize,
    pub sha256: String,
}

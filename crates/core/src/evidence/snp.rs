use stogas_sev_snp::{GuestPolicyRule, PlatformFacts, PlatformRule, Policy, Report, SigningKey};

use super::{Error, Snapshot, Validity};

/// An SNP report appraised against this snapshot's approved release, hardware policy and
/// current vendor revocation state. This result does not itself establish session freshness.
#[derive(Debug)]
pub struct VerifiedSnpReport {
    node_id: String,
    report_id: [u8; 32],
    chip_id: String,
    reported_tcb: String,
    facts: PlatformFacts,
    validity: Validity,
}

impl VerifiedSnpReport {
    /// The platform's firmware state, which an authority keeps to appraise the boot again.
    #[must_use]
    pub const fn facts(&self) -> &PlatformFacts {
        &self.facts
    }

    #[must_use]
    pub fn node_id(&self) -> &str {
        &self.node_id
    }

    #[must_use]
    pub const fn report_id(&self) -> &[u8; 32] {
        &self.report_id
    }

    #[must_use]
    pub fn chip_id(&self) -> &str {
        &self.chip_id
    }

    #[must_use]
    pub fn reported_tcb(&self) -> &str {
        &self.reported_tcb
    }

    #[must_use]
    pub const fn validity(&self) -> Validity {
        self.validity
    }
}

impl Snapshot {
    /// Verify a complete raw report against the caller's expected report-data commitment.
    /// Boot and session protocols supply their own commitments; neither accepts an arbitrary
    /// report's embedded report data as the expected binding.
    ///
    /// # Errors
    /// Rejects unapproved releases/platforms, wrong bindings, host/other-VMPL reports, weak
    /// launch policies, bad signatures and missing, revoked or expired vendor material.
    pub fn verify_snp_report(
        &self,
        report: &[u8],
        expected_report_data: &[u8; 64],
        release_id: &str,
        now_unix_ms: i64,
    ) -> Result<VerifiedSnpReport, Error> {
        self.require_current_keys()?;
        let release = self.gateway(release_id).ok_or(Error::Authority(
            crate::authority::Error::NotApproved("gateway"),
        ))?;
        let report = Report::parse(report).map_err(attestation_error)?;
        let report_id = *report.report_id();
        let node_id = crate::attestation::snp_node_id(&report_id);
        let rejected =
            |error: stogas_sev_snp::Error| attestation_error(format!("{node_id} {error}"));
        let chip_id = hex::encode(report.chip_id());
        let reported_tcb = hex::encode(report.reported_tcb().to_bytes());
        let verified = self
            .collateral
            .endorsement(&chip_id, &reported_tcb)?
            .verify_report(report)
            .map_err(rejected)?;
        let launch = crate::compatible_launch_policy(&release.launch_policies, verified.product())
            .map_err(attestation_error)?;
        launch_policy(&release.measurement, launch, expected_report_data)?
            .check(&verified)
            .map_err(rejected)?;
        let facts = verified.facts();
        PlatformRule::find(
            &self.platforms,
            verified.product(),
            verified.report().chip_id(),
            &facts,
        )
        .map_err(rejected)?;
        // Consult shared CRL state after crypto work. An old retained snapshot cannot hide
        // a revocation learned while another evidence candidate was being installed.
        let validity = self.collateral_validity(&chip_id, &reported_tcb, now_unix_ms)?;
        Ok(VerifiedSnpReport {
            node_id,
            report_id,
            chip_id,
            reported_tcb,
            facts,
            validity,
        })
    }
}

/// What a gateway's report must show: the release's measurement and launch values at VMPL 0,
/// signed with a VCEK, and the report data that the protocol expects. The platform rules apply
/// separately, so that a check does not copy them.
fn launch_policy(
    measurement: &str,
    launch: &crate::LaunchValues,
    report_data: &[u8; 64],
) -> Result<Policy, Error> {
    fn bytes<const N: usize>(value: &str, label: &str) -> Result<[u8; N], Error> {
        hex::decode(value)
            .ok()
            .and_then(|bytes| bytes.try_into().ok())
            .ok_or_else(|| attestation_error(format!("invalid {label}")))
    }
    let guest_policy = launch
        .policy
        .strip_prefix("0x")
        .and_then(|policy| u64::from_str_radix(policy, 16).ok())
        .ok_or_else(|| attestation_error("invalid launch policy value"))?;
    Ok(Policy {
        report_data: Some(*report_data),
        measurements: vec![bytes(measurement, "measurement")?],
        host_data: Some(bytes(&launch.host_data, "host data")?),
        family_id: Some(bytes(&launch.family_id, "family id")?),
        image_id: Some(bytes(&launch.image_id, "image id")?),
        id_key_digests: vec![bytes(&launch.id_key_digest, "id key digest")?],
        author_key_digests: vec![bytes(&launch.author_key_digest, "author key digest")?],
        report_id: None,
        report_id_ma: None,
        vmpl: Some(u32::from(launch.vmpl)),
        minimum_guest_svn: None,
        guest_policy: GuestPolicyRule {
            exact: Some(guest_policy),
            ..GuestPolicyRule::default()
        },
        platforms: Vec::new(),
        signers: vec![SigningKey::Vcek],
        csp_ids: Vec::new(),
        require_crl: false,
    })
}

fn attestation_error(error: impl std::fmt::Display) -> Error {
    Error::Attestation(error.to_string())
}

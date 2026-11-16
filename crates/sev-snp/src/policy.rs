use alloc::{format, string::String, vec::Vec};

use crate::error::{Error, invalid_policy, policy as rejected};
use crate::product::Product;
use crate::report::{SigningKey, guest_policy};
use crate::tcb::{FirmwareVersion, TcbVersion};
use crate::verify::Verified;

/// What a verifier requires of a verified report: the workload it must run, the guest policy it
/// launched with and the platforms it may run on.
///
/// An empty list or an absent value requires nothing. JSON gives byte fields in lowercase
/// hexadecimal and masks as `0x` followed by 16 lowercase hexadecimal digits.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
#[cfg_attr(
    feature = "serde",
    derive(serde::Deserialize, serde::Serialize),
    serde(deny_unknown_fields)
)]
pub struct Policy {
    /// The data the guest bound to the report, such as a nonce or a key digest.
    #[cfg_attr(
        feature = "serde",
        serde(
            default,
            skip_serializing_if = "Option::is_none",
            with = "crate::hex::serde::option"
        )
    )]
    pub report_data: Option<[u8; 64]>,
    /// Launch measurements, any of which the report may carry.
    #[cfg_attr(
        feature = "serde",
        serde(
            default,
            skip_serializing_if = "Vec::is_empty",
            with = "crate::hex::serde::vec"
        )
    )]
    pub measurements: Vec<[u8; 48]>,
    #[cfg_attr(
        feature = "serde",
        serde(
            default,
            skip_serializing_if = "Option::is_none",
            with = "crate::hex::serde::option"
        )
    )]
    pub host_data: Option<[u8; 32]>,
    #[cfg_attr(
        feature = "serde",
        serde(
            default,
            skip_serializing_if = "Option::is_none",
            with = "crate::hex::serde::option"
        )
    )]
    pub family_id: Option<[u8; 16]>,
    #[cfg_attr(
        feature = "serde",
        serde(
            default,
            skip_serializing_if = "Option::is_none",
            with = "crate::hex::serde::option"
        )
    )]
    pub image_id: Option<[u8; 16]>,
    /// Digests of keys that may sign the ID block. All zeros admits a guest without one.
    #[cfg_attr(
        feature = "serde",
        serde(
            default,
            skip_serializing_if = "Vec::is_empty",
            with = "crate::hex::serde::vec"
        )
    )]
    pub id_key_digests: Vec<[u8; 48]>,
    /// Digests of author keys that may sign the ID key. All zeros admits a guest without one.
    #[cfg_attr(
        feature = "serde",
        serde(
            default,
            skip_serializing_if = "Vec::is_empty",
            with = "crate::hex::serde::vec"
        )
    )]
    pub author_key_digests: Vec<[u8; 48]>,
    #[cfg_attr(
        feature = "serde",
        serde(
            default,
            skip_serializing_if = "Option::is_none",
            with = "crate::hex::serde::option"
        )
    )]
    pub report_id: Option<[u8; 32]>,
    #[cfg_attr(
        feature = "serde",
        serde(
            default,
            skip_serializing_if = "Option::is_none",
            with = "crate::hex::serde::option"
        )
    )]
    pub report_id_ma: Option<[u8; 32]>,
    /// The privilege level that must request the report. Level 0 is the most privileged.
    #[cfg_attr(
        feature = "serde",
        serde(default, skip_serializing_if = "Option::is_none")
    )]
    pub vmpl: Option<u32>,
    #[cfg_attr(
        feature = "serde",
        serde(default, skip_serializing_if = "Option::is_none")
    )]
    pub minimum_guest_svn: Option<u32>,
    #[cfg_attr(feature = "serde", serde(default))]
    pub guest_policy: GuestPolicyRule,
    /// Platforms the report may come from. A report must meet one rule entirely.
    #[cfg_attr(
        feature = "serde",
        serde(default, skip_serializing_if = "Vec::is_empty")
    )]
    pub platforms: Vec<PlatformRule>,
    /// Keys that may sign the report: VCEK, VLEK or both when empty.
    #[cfg_attr(
        feature = "serde",
        serde(default, skip_serializing_if = "Vec::is_empty")
    )]
    pub signers: Vec<SigningKey>,
    /// Cloud providers whose VLEK may sign the report, by the CSP ID in the VLEK.
    #[cfg_attr(
        feature = "serde",
        serde(default, skip_serializing_if = "Vec::is_empty")
    )]
    pub csp_ids: Vec<String>,
    /// Require a CRL that shows the intermediate certificate is not revoked.
    #[cfg_attr(feature = "serde", serde(default))]
    pub require_crl: bool,
}

/// What the guest policy must allow and forbid.
#[derive(Clone, Debug, Eq, PartialEq)]
#[cfg_attr(
    feature = "serde",
    derive(serde::Deserialize, serde::Serialize),
    serde(deny_unknown_fields)
)]
pub struct GuestPolicyRule {
    /// The exact policy, when the verifier knows the one its launcher sets.
    #[cfg_attr(
        feature = "serde",
        serde(
            default,
            skip_serializing_if = "Option::is_none",
            with = "crate::hex::serde::mask_option"
        )
    )]
    pub exact: Option<u64>,
    /// The oldest firmware ABI, as `[major, minor]`, that the policy may accept.
    #[cfg_attr(
        feature = "serde",
        serde(default, skip_serializing_if = "Option::is_none")
    )]
    pub minimum_abi: Option<(u8, u8)>,
    /// Flags the policy must set.
    #[cfg_attr(feature = "serde", serde(default, with = "crate::hex::serde::mask"))]
    pub require: u64,
    /// Flags the policy must not set: by default debugging and a migration agent.
    #[cfg_attr(
        feature = "serde",
        serde(default = "default_forbid", with = "crate::hex::serde::mask")
    )]
    pub forbid: u64,
}

const fn default_forbid() -> u64 {
    guest_policy::DEBUG | guest_policy::MIGRATE_MA
}

impl Default for GuestPolicyRule {
    fn default() -> Self {
        Self {
            exact: None,
            minimum_abi: None,
            require: 0,
            forbid: default_forbid(),
        }
    }
}

/// What a platform must be: its processor, chips and firmware state.
///
/// TCB minimums apply to the reported, committed and current TCB, and the launch minimum, which
/// defaults to the TCB minimum, to the launch TCB. SPL numbering is specific to a product line,
/// so a rule with a TCB minimum names its product, directly or by CPUID.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
#[cfg_attr(
    feature = "serde",
    derive(serde::Deserialize, serde::Serialize),
    serde(deny_unknown_fields)
)]
pub struct PlatformRule {
    #[cfg_attr(
        feature = "serde",
        serde(default, skip_serializing_if = "Option::is_none")
    )]
    pub product: Option<Product>,
    #[cfg_attr(
        feature = "serde",
        serde(default, skip_serializing_if = "Option::is_none")
    )]
    pub cpuid_family: Option<u8>,
    #[cfg_attr(
        feature = "serde",
        serde(default, skip_serializing_if = "Option::is_none")
    )]
    pub cpuid_model: Option<u8>,
    #[cfg_attr(
        feature = "serde",
        serde(default, skip_serializing_if = "Option::is_none")
    )]
    pub cpuid_stepping: Option<u8>,
    /// Chips, by the `CHIP_ID` in their reports.
    #[cfg_attr(
        feature = "serde",
        serde(
            default,
            skip_serializing_if = "Vec::is_empty",
            with = "crate::hex::serde::vec"
        )
    )]
    pub chip_ids: Vec<[u8; 64]>,
    #[cfg_attr(
        feature = "serde",
        serde(default, skip_serializing_if = "Option::is_none")
    )]
    pub minimum_tcb: Option<TcbVersion>,
    #[cfg_attr(
        feature = "serde",
        serde(default, skip_serializing_if = "Option::is_none")
    )]
    pub minimum_launch_tcb: Option<TcbVersion>,
    /// The oldest committed firmware version.
    #[cfg_attr(
        feature = "serde",
        serde(default, skip_serializing_if = "Option::is_none")
    )]
    pub minimum_firmware_version: Option<FirmwareVersion>,
    /// Accept firmware that the host updated but did not commit, so that it may roll back to
    /// the committed version. Minimums still apply to the committed TCB and version.
    #[cfg_attr(feature = "serde", serde(default, skip_serializing_if = "is_false"))]
    pub permit_provisional_firmware: bool,
    /// Platform information bits that must be set. [`platform_info`](crate::platform_info) names
    /// them.
    #[cfg_attr(feature = "serde", serde(default, with = "crate::hex::serde::mask"))]
    pub required_platform_info_mask: u64,
    /// Platform information bits that must be clear. Add `!platform_info::KNOWN` to refuse the
    /// bits that this crate does not name.
    #[cfg_attr(feature = "serde", serde(default, with = "crate::hex::serde::mask"))]
    pub forbidden_platform_info_mask: u64,
    /// Mitigations that the platform applied when the guest launched. Requiring any needs a
    /// report of version 5 or later.
    #[cfg_attr(feature = "serde", serde(default, with = "crate::hex::serde::mask"))]
    pub required_launch_mitigation_mask: u64,
    /// Mitigations that the platform applies now.
    #[cfg_attr(feature = "serde", serde(default, with = "crate::hex::serde::mask"))]
    pub required_current_mitigation_mask: u64,
}

#[cfg(feature = "serde")]
#[allow(
    clippy::trivially_copy_pass_by_ref,
    reason = "Serde passes a reference to the field to skip_serializing_if."
)]
const fn is_false(value: &bool) -> bool {
    !*value
}

/// The firmware state of the platform that produced a report, which a [`PlatformRule`]
/// appraises. Mitigation masks are zero in reports older than version 5.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[cfg_attr(
    feature = "serde",
    derive(serde::Deserialize, serde::Serialize),
    serde(deny_unknown_fields)
)]
pub struct PlatformFacts {
    pub report_version: u32,
    /// CPUID family, model and stepping, which reports carry from version 3.
    #[cfg_attr(
        feature = "serde",
        serde(default, skip_serializing_if = "Option::is_none")
    )]
    pub cpuid: Option<[u8; 3]>,
    pub current_tcb: TcbVersion,
    pub reported_tcb: TcbVersion,
    pub committed_tcb: TcbVersion,
    pub launch_tcb: TcbVersion,
    pub current_version: FirmwareVersion,
    pub committed_version: FirmwareVersion,
    #[cfg_attr(feature = "serde", serde(with = "crate::hex::serde::mask"))]
    pub platform_info: u64,
    #[cfg_attr(feature = "serde", serde(with = "crate::hex::serde::mask"))]
    pub launch_mitigations: u64,
    #[cfg_attr(feature = "serde", serde(with = "crate::hex::serde::mask"))]
    pub current_mitigations: u64,
}

impl Policy {
    /// Check that the policy is coherent.
    ///
    /// # Errors
    /// Rejects unknown or contradictory guest policy bits, an unsigned signer and invalid
    /// platform rules.
    pub fn validate(&self) -> Result<(), Error> {
        self.guest_policy.validate()?;
        if self.signers.contains(&SigningKey::None) {
            return Err(invalid_policy("an unsigned report cannot satisfy a policy"));
        }
        self.platforms.iter().try_for_each(PlatformRule::validate)
    }

    /// Check a verified report against the policy. [`crate::verify`] calls this.
    ///
    /// # Errors
    /// Names the first requirement that the report fails.
    pub fn check(&self, verified: &Verified) -> Result<(), Error> {
        self.validate()?;
        let report = verified.report();
        if !self.signers.is_empty() && !self.signers.contains(&verified.signing_key()) {
            return Err(rejected("the report's signing key is not allowed"));
        }
        if let Some(csp_id) = verified.csp_id()
            && !self.csp_ids.is_empty()
            && !self.csp_ids.iter().any(|allowed| allowed == csp_id)
        {
            return Err(rejected(format!("cloud provider {csp_id} is not allowed")));
        }
        if self.require_crl && !verified.revocation_checked() {
            return Err(crate::error::missing("the policy requires a CRL"));
        }
        let differs = |label: &str| Err(rejected(format!("{label} differs from the policy")));
        if self
            .report_data
            .is_some_and(|data| &data != report.report_data())
        {
            return differs("report data");
        }
        if !admits(&self.measurements, report.measurement()) {
            return differs("measurement");
        }
        if self
            .host_data
            .is_some_and(|data| &data != report.host_data())
        {
            return differs("host data");
        }
        if self.family_id.is_some_and(|id| &id != report.family_id()) {
            return differs("family ID");
        }
        if self.image_id.is_some_and(|id| &id != report.image_id()) {
            return differs("image ID");
        }
        if !admits(&self.id_key_digests, report.id_key_digest()) {
            return differs("ID key digest");
        }
        let author_key = report.author_key_digest();
        if !admits(&self.author_key_digests, author_key)
            || (!self.author_key_digests.is_empty()
                && report.author_key_enabled() == author_key.iter().all(|byte| *byte == 0))
        {
            return differs("author key");
        }
        if self.report_id.is_some_and(|id| &id != report.report_id()) {
            return differs("report ID");
        }
        if self
            .report_id_ma
            .is_some_and(|id| &id != report.report_id_ma())
        {
            return differs("migration agent's report ID");
        }
        if self.vmpl.is_some_and(|vmpl| vmpl != report.vmpl()) {
            return differs("VMPL");
        }
        if self
            .minimum_guest_svn
            .is_some_and(|minimum| report.guest_svn() < minimum)
        {
            return Err(rejected("guest SVN is below the policy's minimum"));
        }
        self.guest_policy.check(report.guest_policy())?;
        // Without the policy bit, no migration agent can be bound to the guest.
        let report_id_ma = report.report_id_ma();
        if report.guest_policy() & guest_policy::MIGRATE_MA == 0
            && !report_id_ma.iter().all(|byte| *byte == 0)
            && !report_id_ma.iter().all(|byte| *byte == 0xff)
        {
            return Err(rejected(
                "the report names a migration agent that the guest policy forbids",
            ));
        }
        if self.platforms.is_empty() {
            return Ok(());
        }
        PlatformRule::find(
            &self.platforms,
            verified.product(),
            report.chip_id(),
            &report.facts(),
        )
        .map(|_| ())
    }
}

fn admits<const N: usize>(allowed: &[[u8; N]], actual: &[u8; N]) -> bool {
    allowed.is_empty() || allowed.contains(actual)
}

impl GuestPolicyRule {
    fn validate(&self) -> Result<(), Error> {
        let flags = self.require | self.forbid;
        if flags & !guest_policy::FLAGS != 0 || self.require & self.forbid != 0 {
            return Err(invalid_policy(
                "guest policy rule names unknown, ABI or contradictory bits",
            ));
        }
        if let Some(exact) = self.exact
            && (exact & guest_policy::RESERVED_ONE == 0
                || exact & !guest_policy::KNOWN != 0
                || self.check(exact).is_err())
        {
            return Err(invalid_policy(
                "the exact guest policy is invalid or breaks the rule's other requirements",
            ));
        }
        Ok(())
    }

    fn check(&self, policy: u64) -> Result<(), Error> {
        if self.exact.is_some_and(|exact| exact != policy) {
            return Err(rejected(format!(
                "guest policy {policy:#018x} differs from the policy"
            )));
        }
        if policy & self.require != self.require || policy & self.forbid != 0 {
            return Err(rejected(format!(
                "guest policy {policy:#018x} sets or lacks bits that the policy forbids or requires"
            )));
        }
        if let Some((major, minor)) = self.minimum_abi
            && guest_policy::abi(policy) < (major, minor)
        {
            return Err(rejected(format!(
                "guest policy ABI is below {major}.{minor}"
            )));
        }
        Ok(())
    }
}

impl PlatformRule {
    /// The product this rule names, directly or by CPUID.
    ///
    /// # Errors
    /// Rejects an unsupported CPUID and a CPUID of another product than the rule names.
    pub fn named_product(&self) -> Result<Option<Product>, Error> {
        let by_cpuid = match (self.cpuid_family, self.cpuid_model) {
            (Some(family), Some(model)) => Some(
                Product::from_cpuid(family, model)
                    .map_err(|error| invalid_policy(format!("platform rule: {error}")))?,
            ),
            _ => None,
        };
        match (self.product, by_cpuid) {
            (Some(product), Some(by_cpuid)) if product != by_cpuid => Err(invalid_policy(format!(
                "platform rule names {product} and a CPUID of {by_cpuid}"
            ))),
            (product, by_cpuid) => Ok(product.or(by_cpuid)),
        }
    }

    /// Check that the rule is coherent.
    ///
    /// # Errors
    /// Rejects a TCB minimum without a product or in another product's layout, platform
    /// information bits that the rule both requires and forbids, and an incomplete CPUID.
    pub fn validate(&self) -> Result<(), Error> {
        if (self.cpuid_stepping.is_some() && self.cpuid_model.is_none())
            || (self.cpuid_model.is_some() && self.cpuid_family.is_none())
        {
            return Err(invalid_policy(
                "platform rule names a CPUID model or stepping without its family or model",
            ));
        }
        let product = self.named_product()?;
        for tcb in [self.minimum_tcb, self.minimum_launch_tcb]
            .into_iter()
            .flatten()
        {
            let Some(product) = product else {
                return Err(invalid_policy(
                    "a TCB minimum needs the rule to name its product",
                ));
            };
            if !tcb.fits(product.tcb_layout()) {
                return Err(invalid_policy(format!(
                    "a {product} TCB minimum {} an FMC SPL",
                    if tcb.fmc.is_some() {
                        "cannot have"
                    } else {
                        "needs"
                    }
                )));
            }
        }
        if self.required_platform_info_mask & self.forbidden_platform_info_mask != 0 {
            return Err(invalid_policy(
                "platform rule requires and forbids the same platform information bits",
            ));
        }
        Ok(())
    }

    /// The first rule that admits the platform, or why none does. Rules that do not name the
    /// platform's product, CPUID or chip do not count toward the reason.
    ///
    /// # Errors
    /// Rejects an invalid rule, and names the first requirement that the platform fails, or
    /// that no rule names it.
    pub fn find<'a>(
        rules: &'a [Self],
        product: Product,
        chip_id: &[u8; 64],
        facts: &PlatformFacts,
    ) -> Result<&'a Self, Error> {
        rules.iter().try_for_each(Self::validate)?;
        let mut failure = None;
        for rule in rules {
            if !rule.names(product, chip_id, facts)? {
                continue;
            }
            match rule.check(facts) {
                Ok(()) => return Ok(rule),
                Err(error) => {
                    failure.get_or_insert(error);
                }
            }
        }
        Err(failure.unwrap_or_else(|| rejected("no platform rule names this platform")))
    }

    fn names(
        &self,
        product: Product,
        chip_id: &[u8; 64],
        facts: &PlatformFacts,
    ) -> Result<bool, Error> {
        if self.named_product()?.is_some_and(|named| named != product) {
            return Ok(false);
        }
        let cpuid = facts.cpuid;
        let matches = |expected: Option<u8>, index: usize| {
            expected.is_none_or(|expected| cpuid.is_some_and(|cpuid| cpuid[index] == expected))
        };
        Ok(matches(self.cpuid_family, 0)
            && matches(self.cpuid_model, 1)
            && matches(self.cpuid_stepping, 2)
            && (self.chip_ids.is_empty() || self.chip_ids.contains(chip_id)))
    }

    fn check(&self, facts: &PlatformFacts) -> Result<(), Error> {
        let below = |label: &str| Err(rejected(format!("{label} is below the platform rule")));
        if !facts.current_tcb.at_least(facts.reported_tcb) {
            return Err(rejected("the reported TCB is above the current TCB"));
        }
        let provisional = facts.committed_tcb != facts.current_tcb
            || facts.committed_version != facts.current_version;
        if provisional
            && (!self.permit_provisional_firmware
                || !facts.current_tcb.at_least(facts.committed_tcb)
                || facts.committed_version > facts.current_version)
        {
            return Err(rejected("the platform runs uncommitted firmware"));
        }
        if let Some(minimum) = self.minimum_tcb {
            for (label, tcb) in [
                ("reported TCB", facts.reported_tcb),
                ("committed TCB", facts.committed_tcb),
                ("current TCB", facts.current_tcb),
            ] {
                if !tcb.at_least(minimum) {
                    return below(label);
                }
            }
        }
        if self
            .minimum_launch_tcb
            .or(self.minimum_tcb)
            .is_some_and(|minimum| !facts.launch_tcb.at_least(minimum))
        {
            return below("launch TCB");
        }
        if self
            .minimum_firmware_version
            .is_some_and(|minimum| facts.committed_version < minimum)
        {
            return below("committed firmware version");
        }
        let platform = facts.platform_info;
        if platform & self.required_platform_info_mask != self.required_platform_info_mask
            || platform & self.forbidden_platform_info_mask != 0
        {
            return Err(rejected(format!(
                "platform information {platform:#018x} breaks the platform rule"
            )));
        }
        for (label, applied, required) in [
            (
                "launch",
                facts.launch_mitigations,
                self.required_launch_mitigation_mask,
            ),
            (
                "current",
                facts.current_mitigations,
                self.required_current_mitigation_mask,
            ),
        ] {
            if applied & required != required {
                return Err(rejected(format!(
                    "{label} mitigations {applied:#018x} lack ones the platform rule requires"
                )));
            }
        }
        Ok(())
    }
}

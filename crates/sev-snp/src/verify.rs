use alloc::{format, string::String, vec::Vec};

use p384::ecdsa::signature::hazmat::PrehashVerifier as _;
use sha2::{Digest as _, Sha384};

use crate::certificate::{AmdCertificate, ID_CE_BASIC_CONSTRAINTS, ID_CE_KEY_USAGE};
use crate::crl::Crl;
use crate::error::{
    Error, binding, certificate as malformed, expired, missing, revoked,
    signature as bad_signature, unsigned, unsupported,
};
use crate::policy::{PlatformFacts, Policy};
use crate::product::Product;
use crate::report::{Report, SigningKey};
use crate::tcb::{TcbLayout, TcbVersion};

/// A time interval in seconds since the UNIX epoch, which includes both ends.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
#[cfg_attr(feature = "serde", derive(serde::Deserialize, serde::Serialize))]
pub struct Validity {
    pub not_before: u64,
    pub not_after: u64,
}

impl Validity {
    #[must_use]
    pub const fn contains(self, time: u64) -> bool {
        self.not_before <= time && time <= self.not_after
    }

    #[must_use]
    pub fn intersect(self, other: Self) -> Self {
        Self {
            not_before: self.not_before.max(other.not_before),
            not_after: self.not_after.min(other.not_after),
        }
    }
}

/// The certificates that endorse a report, in DER.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct Endorsements<'a> {
    /// The VCEK or VLEK certificate.
    pub leaf: &'a [u8],
    /// The ASK of a VCEK or the ASVK of a VLEK. The built-in one applies when it is absent.
    pub intermediate: Option<&'a [u8]>,
    /// AMD's CRL for the product, which [`Policy::require_crl`] can require.
    pub crl: Option<&'a [u8]>,
}

/// A VCEK or VLEK certificate whose chain to AMD's pinned root for its product this crate
/// verified. A verifier can keep it to check many reports from one platform.
#[derive(Clone, Debug)]
pub struct Endorsement {
    product: Product,
    signing_key: SigningKey,
    csp_id: Option<String>,
    chip_id: Option<[u8; 64]>,
    tcb: TcbVersion,
    key: p384::ecdsa::VerifyingKey,
    validity: Validity,
    intermediate_serial: Vec<u8>,
}

impl Endorsement {
    /// Verify a VCEK or VLEK certificate and its intermediate, which defaults to the built-in
    /// ASK or ASVK. Validity in time is left to the caller: see [`Self::validity`].
    ///
    /// # Errors
    /// Rejects certificates outside AMD's profile, an intermediate that the product's pinned
    /// root did not sign and an invalid signature.
    pub fn verify(leaf: &[u8], intermediate: Option<&[u8]>) -> Result<Self, Error> {
        let leaf = AmdCertificate::parse(leaf, "VCEK or VLEK")?;
        leaf.check_critical(&[])?;
        let extensions = leaf.endorsement_extensions()?;
        let signing_key = extensions.signing_key().ok_or_else(|| {
            malformed("the certificate carries neither a chip ID nor a CSP ID, or both")
        })?;
        let (name, intermediate_name) = match signing_key {
            SigningKey::Vcek => ("SEV-VCEK", "SEV-"),
            _ => ("SEV-VLEK", "SEV-VLEK-"),
        };
        if leaf.common_name()? != name {
            return Err(malformed(format!(
                "a certificate with a {} is named {name}",
                if signing_key == SigningKey::Vcek {
                    "chip ID"
                } else {
                    "CSP ID"
                }
            )));
        }
        let product = Product::from_certificate_name(extensions.product_name).ok_or_else(|| {
            unsupported(format!(
                "certificate product {} is not supported",
                extensions.product_name
            ))
        })?;
        if extensions.struct_version != product.struct_version() {
            return Err(malformed(format!(
                "{product} certificate has structVersion {}",
                extensions.struct_version
            )));
        }
        let [bl, tee, snp, spl4, spl5, spl6, spl7, microcode, fmc] = extensions.spl;
        let (Some(bl), Some(tee), Some(snp), Some(spl5), Some(spl6), Some(spl7), Some(microcode)) =
            (bl, tee, snp, spl5, spl6, spl7, microcode)
        else {
            return Err(malformed("certificate lacks an SPL"));
        };
        let layout = product.tcb_layout();
        let tcb = match (layout, spl4, fmc) {
            (TcbLayout::Family19h, Some(spl4), None) => {
                [bl, tee, spl4, spl5, spl6, spl7, snp, microcode]
            }
            (TcbLayout::Family1ah, None, Some(fmc)) => {
                [fmc, bl, tee, snp, spl5, spl6, spl7, microcode]
            }
            _ => {
                return Err(malformed(format!(
                    "{product} certificate has another product's SPLs"
                )));
            }
        };
        let tcb = TcbVersion::decode(tcb, layout)
            .ok_or_else(|| malformed(format!("{product} certificate sets a reserved SPL")))?;
        let chip_id = extensions
            .hwid
            .map(|value| {
                chip_id(value, product.hwid_len())
                    .ok_or_else(|| malformed(format!("{product} certificate chip ID is malformed")))
            })
            .transpose()?;
        let key = p384::ecdsa::VerifyingKey::from_sec1_bytes(leaf.p384_point()?)
            .map_err(|_| malformed("certificate P-384 key is invalid"))?;

        let roots = product.roots();
        let ark = AmdCertificate::parse(roots.ark, "ARK")?;
        let built_in = match signing_key {
            SigningKey::Vcek => roots.ask,
            _ => roots.asvk,
        };
        let label = match signing_key {
            SigningKey::Vcek => "ASK",
            _ => "ASVK",
        };
        let intermediate_der = intermediate.unwrap_or(built_in);
        let intermediate = AmdCertificate::parse(intermediate_der, label)?;
        // Tests verify the built-in intermediates. Another one must be AMD's for this product.
        if intermediate_der != built_in {
            if intermediate.common_name()? != format!("{intermediate_name}{product}") {
                return Err(binding(format!("the {label} is not the {product} {label}")));
            }
            intermediate.check_critical(&[ID_CE_BASIC_CONSTRAINTS, ID_CE_KEY_USAGE])?;
            intermediate.verify_issued_by(&ark, &ark.rsa_key()?)?;
        }
        leaf.verify_issued_by(&intermediate, &intermediate.rsa_key()?)?;
        Ok(Self {
            product,
            signing_key,
            csp_id: extensions.csp_id,
            chip_id,
            tcb,
            key,
            validity: ark
                .validity()
                .intersect(intermediate.validity())
                .intersect(leaf.validity()),
            intermediate_serial: intermediate.serial().to_vec(),
        })
    }

    #[must_use]
    pub const fn product(&self) -> Product {
        self.product
    }

    /// [`SigningKey::Vcek`] or [`SigningKey::Vlek`].
    #[must_use]
    pub const fn signing_key(&self) -> SigningKey {
        self.signing_key
    }

    /// The cloud provider that a VLEK names.
    #[must_use]
    pub fn csp_id(&self) -> Option<&str> {
        self.csp_id.as_deref()
    }

    /// The `CHIP_ID` of the reports that a VCEK signs. A VCEK names its chip by the full ID, or
    /// for Turin by an 8-byte serial number that the report's `CHIP_ID` follows with zeros. A
    /// VLEK names no chip.
    #[must_use]
    pub const fn chip_id(&self) -> Option<&[u8; 64]> {
        self.chip_id.as_ref()
    }

    /// The TCB that the certificate is for, which must be a report's reported TCB.
    #[must_use]
    pub const fn tcb(&self) -> TcbVersion {
        self.tcb
    }

    /// When the certificate, its intermediate and the root are all valid.
    #[must_use]
    pub const fn validity(&self) -> Validity {
        self.validity
    }

    /// The serial number of the intermediate, as the content of its DER INTEGER, which AMD's
    /// CRL lists when it is revoked.
    #[must_use]
    pub fn intermediate_serial(&self) -> &[u8] {
        &self.intermediate_serial
    }

    /// Check that the certificate names the report's processor, chip and reported TCB, and that
    /// its key signed the report. The result is not yet checked for time or revocation.
    ///
    /// # Errors
    /// Rejects an unsigned report, one the certificate does not describe and a bad signature.
    pub fn verify_report(&self, report: Report) -> Result<Verified, Error> {
        match report.signing_key() {
            SigningKey::None => return Err(unsigned("the report is not signed")),
            key if key != self.signing_key => {
                return Err(binding("the report names another kind of signing key"));
            }
            _ => {}
        }
        match report.product() {
            Some(product) if product != self.product => {
                return Err(binding(format!(
                    "a {} certificate cannot sign a {product} report",
                    self.product
                )));
            }
            None if self.product.tcb_layout() != TcbLayout::Family19h => {
                return Err(binding(format!(
                    "a {} report carries CPUID fields",
                    self.product
                )));
            }
            _ => {}
        }
        if report.reported_tcb() != self.tcb {
            return Err(binding(
                "the certificate is for another TCB than the reported one",
            ));
        }
        if self
            .chip_id
            .is_some_and(|chip_id| &chip_id != report.chip_id())
        {
            return Err(binding("the certificate is for another chip"));
        }
        let (r, s) = report.signature_scalars();
        let signature = p384::ecdsa::Signature::from_scalars(r, s)
            .map_err(|_| bad_signature("the report signature is malformed"))?;
        self.key
            .verify_prehash(&Sha384::digest(report.signed_bytes()), &signature)
            .map_err(|_| bad_signature("the report signature is invalid"))?;
        Ok(Verified {
            report,
            product: self.product,
            signing_key: self.signing_key,
            csp_id: self.csp_id.clone(),
            validity: self.validity,
            revocation_checked: false,
        })
    }
}

/// The `CHIP_ID` of a certificate's chip, whose ID it holds as raw bytes, or in an OCTET STRING
/// in case AMD adds the header that KDS omits.
fn chip_id(value: &[u8], length: usize) -> Option<[u8; 64]> {
    let bytes = if value.len() == length {
        value
    } else {
        <&der::asn1::OctetStringRef as der::Decode<'_>>::from_der(value)
            .ok()?
            .as_bytes()
    };
    let mut chip_id = [0; 64];
    chip_id
        .get_mut(..bytes.len())
        .filter(|_| bytes.len() == length && bytes.iter().any(|byte| *byte != 0))?
        .copy_from_slice(bytes);
    Some(chip_id)
}

/// A report whose signature chains to AMD's pinned root for its product.
#[derive(Clone, Debug)]
pub struct Verified {
    report: Report,
    product: Product,
    signing_key: SigningKey,
    csp_id: Option<String>,
    validity: Validity,
    revocation_checked: bool,
}

impl Verified {
    #[must_use]
    pub const fn report(&self) -> &Report {
        &self.report
    }

    #[must_use]
    pub const fn product(&self) -> Product {
        self.product
    }

    #[must_use]
    pub const fn signing_key(&self) -> SigningKey {
        self.signing_key
    }

    /// The cloud provider that a VLEK names.
    #[must_use]
    pub fn csp_id(&self) -> Option<&str> {
        self.csp_id.as_deref()
    }

    /// The platform's firmware state.
    #[must_use]
    pub fn facts(&self) -> PlatformFacts {
        self.report.facts()
    }

    /// When the certificates, and any CRL that was checked, are all valid.
    #[must_use]
    pub const fn validity(&self) -> Validity {
        self.validity
    }

    /// Whether a CRL showed that the intermediate is not revoked.
    #[must_use]
    pub const fn revocation_checked(&self) -> bool {
        self.revocation_checked
    }
}

/// Verify a report at `now`, in seconds since the UNIX epoch, and check it against a policy.
///
/// # Errors
/// Names the first check that fails, with an [`crate::ErrorKind`] for programs.
pub fn verify(
    report: &[u8],
    endorsements: &Endorsements<'_>,
    policy: &Policy,
    now: u64,
) -> Result<Verified, Error> {
    policy.validate()?;
    let report = Report::parse(report)?;
    let endorsement = Endorsement::verify(endorsements.leaf, endorsements.intermediate)?;
    let mut verified = endorsement.verify_report(report)?;
    match endorsements.crl {
        Some(crl) => {
            let crl = Crl::verify(crl)?;
            if crl.product() != endorsement.product() {
                return Err(binding(format!(
                    "the CRL is for {}, not {}",
                    crl.product(),
                    endorsement.product()
                )));
            }
            if crl.is_revoked(endorsement.intermediate_serial()) {
                return Err(revoked("AMD revoked the intermediate certificate"));
            }
            verified.validity = verified.validity.intersect(crl.validity());
            verified.revocation_checked = true;
        }
        None if policy.require_crl => return Err(missing("the policy requires a CRL")),
        None => {}
    }
    if !verified.validity.contains(now) {
        return Err(expired(
            "a certificate or the CRL is not valid at the time given",
        ));
    }
    policy.check(&verified)?;
    Ok(verified)
}

//! AMD's certificate profile: the ARK signs itself, the ASK and the ASVK, the ASK signs VCEKs and
//! the ASVK signs VLEKs. Every certificate and CRL uses RSASSA-PSS with SHA-384.

use alloc::{format, string::String, vec::Vec};

use const_oid::{
    ObjectIdentifier,
    db::{rfc4519, rfc5280, rfc5912},
};
use der::{Decode as _, Encode as _, Reader as _, SliceReader, Tagged as _};
use rsa::{PublicKey, pkcs1::DecodeRsaPublicKey as _, signature::Verifier as _};
use x509_cert::{Certificate, ext::Extension, name::Name, time::Time};

use crate::error::{Error, certificate as malformed, signature as bad_signature};
use crate::report::SigningKey;
use crate::verify::Validity;

/// RSASSA-PSS with SHA-384, MGF1 with SHA-384 and a 48-byte salt, exactly as AMD encodes it: with
/// the trailer field written out, as in its roots and older VCEKs, and without it, as DER requires
/// and as in its CRLs, VLEKs and newer VCEKs.
const AMD_SIGNATURE_ALGORITHMS: [&[u8]; 2] = [
    &[
        0x30, 0x46, 0x06, 0x09, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x0a, 0x30, 0x39,
        0xa0, 0x0f, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x02,
        0x05, 0x00, 0xa1, 0x1c, 0x30, 0x1a, 0x06, 0x09, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01,
        0x01, 0x08, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x02,
        0x05, 0x00, 0xa2, 0x03, 0x02, 0x01, 0x30, 0xa3, 0x03, 0x02, 0x01, 0x01,
    ],
    &[
        0x30, 0x41, 0x06, 0x09, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x0a, 0x30, 0x34,
        0xa0, 0x0f, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x02,
        0x05, 0x00, 0xa1, 0x1c, 0x30, 0x1a, 0x06, 0x09, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01,
        0x01, 0x08, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x02,
        0x05, 0x00, 0xa2, 0x03, 0x02, 0x01, 0x30,
    ],
];

/// AMD's extensions in VCEK and VLEK certificates sit under this arc.
const AMD_ARC: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.3.6.1.4.1.3704.1");

/// The parts of a signed X.509 structure: the exact bytes the signature covers, the outer
/// algorithm and the signature.
pub struct Signed<'a> {
    pub message: &'a [u8],
    algorithm: &'a [u8],
    signature: &'a [u8],
}

impl<'a> Signed<'a> {
    /// Split DER without re-encoding: AMD writes the PSS trailer field, which DER would omit.
    pub fn split(der: &'a [u8], label: &str) -> Result<Self, Error> {
        let parts = (|| {
            let mut reader = SliceReader::new(der)?;
            let parts = reader.sequence(|outer| {
                Ok::<_, der::Error>((outer.tlv_bytes()?, outer.tlv_bytes()?, outer.tlv_bytes()?))
            })?;
            reader.finish()?;
            Ok::<_, der::Error>(parts)
        })()
        .map_err(|error| malformed(format!("{label} is not DER: {error}")))?;
        let (message, algorithm, signature) = parts;
        let signature = der::asn1::BitStringRef::from_der(signature)
            .ok()
            .and_then(|bits| bits.as_bytes())
            .ok_or_else(|| {
                malformed(format!("{label} signature is not a whole number of bytes"))
            })?;
        Ok(Self {
            message,
            algorithm,
            signature,
        })
    }

    /// Check AMD's algorithm in both places it appears, then the signature.
    pub fn verify(
        &self,
        signed_algorithm: &[u8],
        issuer: &PublicKey,
        label: &str,
    ) -> Result<(), Error> {
        if self.algorithm != signed_algorithm || !AMD_SIGNATURE_ALGORITHMS.contains(&self.algorithm)
        {
            return Err(malformed(format!(
                "{label} is not signed with AMD's RSASSA-PSS SHA-384 profile"
            )));
        }
        let signature = rsa::pss::Signature::try_from(self.signature)
            .map_err(|_| bad_signature(format!("{label} signature is malformed")))?;
        rsa::pss::VerifyingKey::<sha2::Sha384>::new(issuer.clone())
            .verify(self.message, &signature)
            .map_err(|_| bad_signature(format!("{label} signature is invalid")))
    }
}

/// One of AMD's certificates, with the bytes its issuer signed.
pub struct AmdCertificate<'a> {
    signed: Signed<'a>,
    certificate: Certificate,
    label: &'static str,
}

impl<'a> AmdCertificate<'a> {
    pub fn parse(der: &'a [u8], label: &'static str) -> Result<Self, Error> {
        let signed = Signed::split(der, label)?;
        let certificate = Certificate::from_der(der)
            .map_err(|error| malformed(format!("{label} is not an X.509 certificate: {error}")))?;
        if certificate.tbs_certificate().version() != x509_cert::Version::V3 {
            return Err(malformed(format!(
                "{label} is not an X.509 version 3 certificate"
            )));
        }
        Ok(Self {
            signed,
            certificate,
            label,
        })
    }

    pub fn subject(&self) -> &Name {
        self.certificate.tbs_certificate().subject()
    }

    pub fn issuer(&self) -> &Name {
        self.certificate.tbs_certificate().issuer()
    }

    pub fn serial(&self) -> &[u8] {
        self.certificate
            .tbs_certificate()
            .serial_number()
            .as_bytes()
    }

    pub fn common_name(&self) -> Result<&str, Error> {
        common_name(self.subject())
            .ok_or_else(|| malformed(format!("{} has no single common name", self.label)))
    }

    pub fn validity(&self) -> Validity {
        let validity = self.certificate.tbs_certificate().validity();
        Validity {
            not_before: unix_seconds(validity.not_before),
            not_after: unix_seconds(validity.not_after),
        }
    }

    /// The issuer's key of an ARK, ASK or ASVK.
    pub fn rsa_key(&self) -> Result<PublicKey, Error> {
        let key = self.certificate.tbs_certificate().subject_public_key_info();
        if key.algorithm.oid != rfc5912::RSA_ENCRYPTION {
            return Err(malformed(format!("{} key is not an RSA key", self.label)));
        }
        let key = key
            .subject_public_key
            .as_bytes()
            .and_then(|bytes| PublicKey::from_pkcs1_der(bytes).ok())
            .ok_or_else(|| malformed(format!("{} RSA key is malformed", self.label)))?;
        if rsa::traits::PublicKeyParts::size(&key) != 512 {
            return Err(malformed(format!(
                "{} key is not a 4096-bit RSA key",
                self.label
            )));
        }
        Ok(key)
    }

    /// The SEC1 point of a VCEK or VLEK, whose curve parameters name P-384.
    pub fn p384_point(&self) -> Result<&[u8], Error> {
        let key = self.certificate.tbs_certificate().subject_public_key_info();
        let curve = key
            .algorithm
            .parameters
            .as_ref()
            .and_then(|parameters| parameters.decode_as::<ObjectIdentifier>().ok());
        if key.algorithm.oid != rfc5912::ID_EC_PUBLIC_KEY || curve != Some(rfc5912::SECP_384_R_1) {
            return Err(malformed(format!("{} key is not a P-384 key", self.label)));
        }
        key.subject_public_key
            .as_bytes()
            .ok_or_else(|| malformed(format!("{} key is malformed", self.label)))
    }

    /// Check that `issuer` named, and signed, this certificate.
    pub fn verify_issued_by(&self, issuer: &Self, key: &PublicKey) -> Result<(), Error> {
        if self.issuer() != issuer.subject() {
            return Err(malformed(format!(
                "{} names another issuer than the {}",
                self.label, issuer.label
            )));
        }
        let signed_algorithm = self
            .certificate
            .tbs_certificate()
            .signature()
            .to_der()
            .map_err(|error| malformed(format!("{}: {error}", self.label)))?;
        self.signed.verify(&signed_algorithm, key, self.label)
    }

    /// Reject a critical extension other than those AMD's intermediates mark critical.
    pub fn check_critical(&self, allowed: &[ObjectIdentifier]) -> Result<(), Error> {
        self.extensions()
            .iter()
            .find(|extension| extension.critical && !allowed.contains(&extension.extn_id))
            .map_or(Ok(()), |extension| {
                Err(malformed(format!(
                    "{} has the unsupported critical extension {}",
                    self.label, extension.extn_id
                )))
            })
    }

    fn extension(&self, oid: ObjectIdentifier) -> Option<&[u8]> {
        self.extensions()
            .iter()
            .find(|extension| extension.extn_id == oid)
            .map(|extension| extension.extn_value.as_bytes())
    }

    pub fn subject_key_identifier(&self) -> Option<&[u8]> {
        self.extension(rfc5280::ID_CE_SUBJECT_KEY_IDENTIFIER)
            .and_then(|value| <&der::asn1::OctetStringRef>::from_der(value).ok())
            .map(der::asn1::OctetStringRef::as_bytes)
    }

    fn extensions(&self) -> &[Extension] {
        self.certificate
            .tbs_certificate()
            .extensions()
            .map_or(&[], Vec::as_slice)
    }

    /// AMD's extensions of a VCEK or VLEK.
    pub fn endorsement_extensions(&self) -> Result<EndorsementExtensions<'_>, Error> {
        let mut found: Vec<(Vec<u32>, &[u8])> = Vec::new();
        for extension in self.extensions() {
            let Some(arc) = amd_arc(&extension.extn_id) else {
                continue;
            };
            if found.iter().any(|(seen, _)| *seen == arc) {
                return Err(malformed(format!(
                    "{} repeats extension {}",
                    self.label, extension.extn_id
                )));
            }
            found.push((arc, extension.extn_value.as_bytes()));
        }
        let find = |suffix: &[u32]| {
            found
                .iter()
                .find(|(arc, _)| arc.as_slice() == suffix)
                .map(|(_, value)| *value)
        };
        let integer = |suffix: &[u32], name: &str| -> Result<Option<u8>, Error> {
            find(suffix)
                .map(|value| {
                    der_u8(value)
                        .ok_or_else(|| malformed(format!("{} {name} is malformed", self.label)))
                })
                .transpose()
        };
        let mut spl = [None; 9];
        for (arc, value) in (1..).zip(&mut spl) {
            *value = integer(&[3, arc], "SPL")?;
        }
        let product_name = find(&[2]).and_then(ia5_string).ok_or_else(|| {
            malformed(format!("{} productName is absent or malformed", self.label))
        })?;
        let csp_id = find(&[5])
            .map(|value| {
                ia5_string(value)
                    .map(String::from)
                    .ok_or_else(|| malformed(format!("{} CSP ID is malformed", self.label)))
            })
            .transpose()?;
        Ok(EndorsementExtensions {
            struct_version: integer(&[1], "structVersion")?
                .ok_or_else(|| malformed(format!("{} has no structVersion", self.label)))?,
            product_name,
            hwid: find(&[4]),
            csp_id,
            spl,
        })
    }
}

/// AMD's extensions of a VCEK or VLEK, before they are checked against a product.
pub struct EndorsementExtensions<'a> {
    pub struct_version: u8,
    pub product_name: &'a str,
    /// The chip's ID, in a VCEK. KDS writes the bytes without an OCTET STRING header.
    pub hwid: Option<&'a [u8]>,
    /// The cloud provider's identity, in a VLEK.
    pub csp_id: Option<String>,
    /// `blSPL`, `teeSPL`, `snpSPL`, `spl4` (Milan and Genoa only), `spl5` to `spl7`,
    /// `ucodeSPL` and `fmcSPL` (Turin only), from arcs 3.1 to 3.9.
    pub spl: [Option<u8>; 9],
}

impl EndorsementExtensions<'_> {
    pub const fn signing_key(&self) -> Option<SigningKey> {
        match (self.hwid, &self.csp_id) {
            (Some(_), None) => Some(SigningKey::Vcek),
            (None, Some(_)) => Some(SigningKey::Vlek),
            _ => None,
        }
    }
}

fn amd_arc(oid: &ObjectIdentifier) -> Option<Vec<u32>> {
    let mut arcs = oid.arcs();
    for expected in AMD_ARC.arcs() {
        if arcs.next() != Some(expected) {
            return None;
        }
    }
    let rest: Vec<u32> = arcs.collect();
    (!rest.is_empty()).then_some(rest)
}

/// A DER INTEGER from 0 to 255 in its shortest form.
fn der_u8(value: &[u8]) -> Option<u8> {
    match value {
        [0x02, 0x01, byte] if *byte < 0x80 => Some(*byte),
        [0x02, 0x02, 0x00, byte] if *byte >= 0x80 => Some(*byte),
        _ => None,
    }
}

fn ia5_string(value: &[u8]) -> Option<&str> {
    der::asn1::Ia5StringRef::from_der(value)
        .ok()
        .map(|text| text.as_str())
}

/// The value of the only common name in a name, as AMD writes it.
fn common_name(name: &Name) -> Option<&str> {
    let mut names = name.iter().filter(|attribute| attribute.oid == rfc4519::CN);
    let value = &names.next()?.value;
    if names.next().is_some() {
        return None;
    }
    match value.tag() {
        der::Tag::Utf8String | der::Tag::PrintableString | der::Tag::Ia5String => {
            core::str::from_utf8(value.value()).ok()
        }
        _ => None,
    }
}

pub fn unix_seconds(time: Time) -> u64 {
    time.to_unix_duration().as_secs()
}

pub use rfc5280::{ID_CE_BASIC_CONSTRAINTS, ID_CE_KEY_USAGE};

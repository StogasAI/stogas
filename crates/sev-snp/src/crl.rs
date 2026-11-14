use alloc::{format, vec::Vec};

use const_oid::db::rfc5280;
use der::{Decode as _, Encode as _};
use x509_cert::{
    crl::CertificateList,
    ext::{Extension, pkix::AuthorityKeyIdentifier},
};

use crate::certificate::{AmdCertificate, Signed, unix_seconds};
use crate::error::{Error, certificate as malformed};
use crate::product::Product;
use crate::verify::Validity;

/// An AMD certificate revocation list (CRL) that the pinned root of its product signed.
///
/// AMD's root signs one CRL per product, which lists the intermediates (ASK and ASVK) it
/// revoked. AMD issues no delta, indirect or partial CRLs, so this type rejects them.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Crl {
    product: Product,
    number: [u8; 20],
    validity: Validity,
    revoked: Vec<Vec<u8>>,
}

impl Crl {
    /// Parse a CRL in DER and verify it with the pinned root of the product that issued it.
    ///
    /// # Errors
    /// Rejects malformed DER, another issuer, an invalid signature and anything outside AMD's
    /// profile, such as a critical, scoped or delta CRL.
    pub fn verify(der: &[u8]) -> Result<Self, Error> {
        let signed = Signed::split(der, "CRL")?;
        let crl = <CertificateList>::from_der(der)
            .map_err(|error| malformed(format!("CRL is not an X.509 CRL: {error}")))?;
        let list = &crl.tbs_cert_list;
        if list.version != x509_cert::Version::V2 {
            return Err(malformed("CRL is not an X.509 version 2 CRL"));
        }
        let (product, ark) = Product::ALL
            .into_iter()
            .find_map(|product| {
                let ark = AmdCertificate::parse(product.roots().ark, "ARK").ok()?;
                (*ark.subject() == list.issuer).then_some((product, ark))
            })
            .ok_or_else(|| malformed("CRL issuer is not an AMD root"))?;
        let signed_algorithm = list
            .signature
            .to_der()
            .map_err(|error| malformed(format!("CRL: {error}")))?;
        signed.verify(&signed_algorithm, &ark.rsa_key()?, "CRL")?;

        let next_update = list
            .next_update
            .ok_or_else(|| malformed("CRL has no next update"))?;
        let validity = Validity {
            not_before: unix_seconds(list.this_update),
            not_after: unix_seconds(next_update),
        };
        if validity.not_after <= validity.not_before {
            return Err(malformed("CRL's next update is not after its last update"));
        }
        let number = number_and_scope(list.crl_extensions.as_deref().unwrap_or_default(), &ark)?;

        let mut revoked = Vec::new();
        for entry in list.revoked_certificates.as_deref().unwrap_or_default() {
            check_entry_extensions(entry.crl_entry_extensions.as_deref().unwrap_or_default())?;
            revoked.push(entry.serial_number.as_bytes().to_vec());
        }
        revoked.sort_unstable();
        if revoked.windows(2).any(|pair| pair[0] == pair[1]) {
            return Err(malformed("CRL lists a certificate twice"));
        }
        Ok(Self {
            product,
            number,
            validity,
            revoked,
        })
    }

    /// The product whose root issued the CRL.
    #[must_use]
    pub const fn product(&self) -> Product {
        self.product
    }

    /// The CRL number, a big-endian integer of 20 bytes, so that comparing two numbers compares
    /// the integers. AMD increases it with each CRL, so a lower number than one seen before
    /// means a replayed CRL.
    #[must_use]
    pub const fn number(&self) -> [u8; 20] {
        self.number
    }

    /// From the CRL's last update to its next update.
    #[must_use]
    pub const fn validity(&self) -> Validity {
        self.validity
    }

    /// Whether the CRL revokes the certificate with this serial number, given as the content of
    /// its DER INTEGER, as [`crate::Endorsement::intermediate_serial`] returns it.
    #[must_use]
    pub fn is_revoked(&self, serial: &[u8]) -> bool {
        self.revoked
            .binary_search_by(|revoked| revoked.as_slice().cmp(serial))
            .is_ok()
    }

    /// The serial numbers that the CRL revokes, in the form of [`Self::is_revoked`], sorted.
    pub fn revoked(&self) -> impl ExactSizeIterator<Item = &[u8]> {
        self.revoked.iter().map(Vec::as_slice)
    }
}

/// The CRL number, after checking that the CRL is a complete CRL that the root's key signed.
fn number_and_scope(extensions: &[Extension], ark: &AmdCertificate<'_>) -> Result<[u8; 20], Error> {
    let mut number = None;
    let mut authority_key = false;
    for (index, extension) in extensions.iter().enumerate() {
        if extensions[..index]
            .iter()
            .any(|other| other.extn_id == extension.extn_id)
        {
            return Err(malformed(format!(
                "CRL repeats extension {}",
                extension.extn_id
            )));
        }
        if extension.critical {
            return Err(malformed(format!(
                "CRL has the critical extension {}",
                extension.extn_id
            )));
        }
        let value = extension.extn_value.as_bytes();
        match extension.extn_id {
            rfc5280::ID_CE_CRL_NUMBER => number = Some(crl_number(value)?),
            rfc5280::ID_CE_AUTHORITY_KEY_IDENTIFIER => {
                let key = AuthorityKeyIdentifier::from_der(value)
                    .ok()
                    .and_then(|identifier| identifier.key_identifier)
                    .ok_or_else(|| malformed("CRL authority key identifier is malformed"))?;
                if Some(key.as_bytes()) != ark.subject_key_identifier() {
                    return Err(malformed("CRL authority key differs from the root's key"));
                }
                authority_key = true;
            }
            rfc5280::ID_CE_DELTA_CRL_INDICATOR | rfc5280::ID_CE_ISSUING_DISTRIBUTION_POINT => {
                return Err(malformed("CRL is a delta or partial CRL"));
            }
            _ => {}
        }
    }
    if !authority_key {
        return Err(malformed("CRL has no authority key identifier"));
    }
    number.ok_or_else(|| malformed("CRL has no CRL number"))
}

/// A nonnegative DER INTEGER of at most 20 bytes, as RFC 5280 allows.
fn crl_number(value: &[u8]) -> Result<[u8; 20], Error> {
    let invalid = || malformed("CRL number is not a canonical nonnegative integer");
    let [0x02, length, digits @ ..] = value else {
        return Err(invalid());
    };
    if usize::from(*length) != digits.len() || digits.is_empty() || digits.len() > 21 {
        return Err(invalid());
    }
    let unsigned = match digits {
        [0x00] => &[][..],
        [first, ..] if first & 0x80 != 0 => return Err(invalid()),
        [0x00, second, ..] if second & 0x80 == 0 => return Err(invalid()),
        [0x00, rest @ ..] => rest,
        _ => digits,
    };
    let mut number = [0; 20];
    number
        .get_mut(20_usize.checked_sub(unsigned.len()).ok_or_else(invalid)?..)
        .ok_or_else(invalid)?
        .copy_from_slice(unsigned);
    Ok(number)
}

/// AMD's root revokes only certificates it issued itself, with no other issuer in the list.
fn check_entry_extensions(extensions: &[Extension]) -> Result<(), Error> {
    for (index, extension) in extensions.iter().enumerate() {
        if extension.critical
            || extension.extn_id == rfc5280::ID_CE_CERTIFICATE_ISSUER
            || extensions[..index]
                .iter()
                .any(|other| other.extn_id == extension.extn_id)
        {
            return Err(malformed(format!(
                "CRL entry has the unsupported extension {}",
                extension.extn_id
            )));
        }
    }
    Ok(())
}

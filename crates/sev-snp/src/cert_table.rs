use alloc::format;

use crate::error::{Error, certificate as malformed, missing, unsigned};
use crate::report::SigningKey;
use crate::verify::Endorsements;

/// GUIDs of the GHCB specification, in RFC 4122 byte order. The CRL's is the one that the `sev`
/// crate and its host tools use.
const VCEK: [u8; 16] = [
    0x63, 0xda, 0x75, 0x8d, 0xe6, 0x64, 0x45, 0x64, 0xad, 0xc5, 0xf4, 0xb9, 0x3b, 0xe8, 0xac, 0xcd,
];
const VLEK: [u8; 16] = [
    0xa8, 0x07, 0x4b, 0xc2, 0xa2, 0x5a, 0x48, 0x3e, 0xaa, 0xe6, 0x39, 0xc0, 0x45, 0xa0, 0xb8, 0xa1,
];
const ASK: [u8; 16] = [
    0x4a, 0xb7, 0xb3, 0x79, 0xbb, 0xac, 0x4f, 0xe4, 0xa0, 0x2f, 0x05, 0xae, 0xf3, 0x27, 0xc7, 0x82,
];
const ARK: [u8; 16] = [
    0xc0, 0xb4, 0x06, 0xa4, 0xa8, 0x03, 0x49, 0x52, 0x97, 0x43, 0x3f, 0xb6, 0x01, 0x4c, 0xd0, 0xae,
];
const CRL: [u8; 16] = [
    0x92, 0xf8, 0x1b, 0xc3, 0x58, 0x11, 0x4d, 0x3d, 0x97, 0xff, 0xd1, 0x9f, 0x88, 0xdc, 0x67, 0xea,
];
const ENTRY: usize = 24;

/// The certificates that a host returns with an extended report: the certificate table of the
/// GHCB specification, which `SNP_GET_EXT_REPORT` and the configfs-tsm `auxblob` return.
///
/// The table is untrusted. Verification relies on the pinned roots, never on the table's ARK.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct CertificateTable<'a> {
    pub vcek: Option<&'a [u8]>,
    pub vlek: Option<&'a [u8]>,
    pub ask: Option<&'a [u8]>,
    pub ark: Option<&'a [u8]>,
    /// AMD's CRL, which a host may add. [`Self::endorsements`] leaves it out, since a host can
    /// serve an outdated one: pass it in [`Endorsements::crl`] when you want it checked.
    pub crl: Option<&'a [u8]>,
}

impl<'a> CertificateTable<'a> {
    /// Parse a table of 24-byte entries (a GUID, then the offset and length of a certificate in
    /// little-endian), which an all-zero entry ends. Certificates follow the entries. Entries
    /// with other GUIDs are skipped, and an empty table holds no certificates.
    ///
    /// # Errors
    /// Rejects a table without its final entry, a certificate outside the table or inside its
    /// entries, and a GUID that appears twice.
    pub fn parse(table: &'a [u8]) -> Result<Self, Error> {
        let mut certificates = Self::default();
        if table.is_empty() {
            return Ok(certificates);
        }
        let entries = table
            .chunks_exact(ENTRY)
            .position(|entry| entry[..16] == [0; 16])
            .ok_or_else(|| malformed("the certificate table has no final entry"))?;
        let end = (entries + 1) * ENTRY;
        if table[end - 8..end] != [0; 8] {
            return Err(malformed("the certificate table's final entry is not zero"));
        }
        for (index, entry) in table[..end - ENTRY].chunks_exact(ENTRY).enumerate() {
            let slot = match <[u8; 16]>::try_from(&entry[..16]).unwrap_or_default() {
                VCEK => &mut certificates.vcek,
                VLEK => &mut certificates.vlek,
                ASK => &mut certificates.ask,
                ARK => &mut certificates.ark,
                CRL => &mut certificates.crl,
                _ => continue,
            };
            let offset = u32::from_le_bytes([entry[16], entry[17], entry[18], entry[19]]);
            let length = u32::from_le_bytes([entry[20], entry[21], entry[22], entry[23]]);
            let certificate = usize::try_from(offset)
                .ok()
                .filter(|offset| *offset >= end)
                .zip(usize::try_from(length).ok())
                .and_then(|(offset, length)| table.get(offset..offset.checked_add(length)?))
                .filter(|certificate| !certificate.is_empty())
                .ok_or_else(|| {
                    malformed(format!(
                        "certificate table entry {index} is empty or lies outside the certificates"
                    ))
                })?;
            if slot.replace(certificate).is_some() {
                return Err(malformed(format!(
                    "certificate table entry {index} repeats a certificate"
                )));
            }
        }
        Ok(certificates)
    }

    /// The endorsements of a report signed with `signing_key`. A VCEK's chain uses the table's
    /// ASK. A VLEK's uses the built-in ASVK, since the GHCB specification defines no entry for
    /// it.
    ///
    /// # Errors
    /// Rejects an unsigned report and a table without the report's certificate.
    pub fn endorsements(&self, signing_key: SigningKey) -> Result<Endorsements<'a>, Error> {
        let (leaf, intermediate) = match signing_key {
            SigningKey::Vcek => (self.vcek, self.ask),
            SigningKey::Vlek => (self.vlek, None),
            SigningKey::None => return Err(unsigned("the report is not signed")),
        };
        Ok(Endorsements {
            leaf: leaf.ok_or_else(|| {
                missing(format!(
                    "the certificate table has no {}",
                    if signing_key == SigningKey::Vcek {
                        "VCEK"
                    } else {
                        "VLEK"
                    }
                ))
            })?,
            intermediate,
            crl: None,
        })
    }
}

//! RFC 6962 embedded SCT verification for Fulcio certificates.

use crate::{
    crypto::{Scheme, verify_spki},
    trust_root::TrustedRoot,
};
use const_oid::db::rfc6962::CT_PRECERT_SCTS;
use sha2::{Digest as _, Sha256};
use tls_codec::{SerializeBytes as _, TlsByteVecU16, TlsByteVecU24, TlsSerializeBytes, TlsSize};
use x509_cert::{
    Certificate,
    der::{self, Any, Decode as _, Encode as _, Tag, TagNumber, Tagged as _},
    ext::{
        Extensions,
        pkix::{SignedCertificateTimestamp, SignedCertificateTimestampList, sct::Version},
    },
};

#[derive(PartialEq, Debug, TlsSerializeBytes, TlsSize)]
#[repr(u8)]
enum SignatureType {
    CertificateTimestamp = 0,
}

#[derive(PartialEq, Debug)]
#[repr(u16)]
enum LogEntryType {
    PrecertEntry = 1,
}

#[derive(PartialEq, Debug, TlsSerializeBytes, TlsSize)]
struct PreCert {
    issuer_key_hash: [u8; 32],
    tbs_certificate: TlsByteVecU24,
}

#[derive(PartialEq, Debug, TlsSerializeBytes, TlsSize)]
#[repr(u16)]
enum SignedEntry {
    #[tls_codec(discriminant = "LogEntryType::PrecertEntry")]
    PrecertEntry(PreCert),
}

#[derive(PartialEq, Debug, TlsSerializeBytes, TlsSize)]
struct DigitallySigned {
    version: Version,
    signature_type: SignatureType,
    timestamp: u64,
    signed_entry: SignedEntry,
    extensions: TlsByteVecU16,
}

pub fn verify(
    certificate_der: &[u8],
    issuer_spki_der: &[u8],
    validation_time: i64,
    root: &TrustedRoot,
) -> Result<(), String> {
    let certificate = Certificate::from_der(certificate_der)
        .map_err(|error| format!("could not parse Fulcio certificate for SCT: {error}"))?;
    let list: SignedCertificateTimestampList = certificate
        .tbs_certificate()
        .get_extension()
        .map_err(|error| format!("could not parse Fulcio SCT extension: {error}"))?
        .map(|(_, list)| list)
        .ok_or_else(|| "Fulcio certificate is missing its SCT".to_owned())?;
    let entries = list
        .parse_timestamps()
        .map_err(|error| format!("could not parse Fulcio SCT list: {error:?}"))?;
    let [entry] = entries.as_slice() else {
        return Err("the build profile requires exactly one SCT".into());
    };
    let sct = entry
        .parse_timestamp()
        .map_err(|error| format!("could not parse Fulcio SCT: {error:?}"))?;
    let sct_seconds = i64::try_from(sct.timestamp / 1000)
        .map_err(|_| "Fulcio SCT timestamp is too large".to_owned())?;
    if sct_seconds > validation_time + 60 {
        return Err("Fulcio SCT is later than the authenticated signing time".into());
    }
    let key = root.ct_key_at(&sct.log_id.key_id, sct_seconds)?;
    let signed = signed_data(&certificate, &sct, issuer_spki_der)?;
    let algorithm = u16::from_be_bytes([
        sct.signature.algorithm.hash as u8,
        sct.signature.algorithm.signature as u8,
    ]);
    let scheme = match algorithm {
        0x0403 => Scheme::EcdsaP256Sha256,
        0x0503 => Scheme::EcdsaP384Sha384,
        0x0401 => Scheme::RsaPkcs1Sha256,
        0x0501 => Scheme::RsaPkcs1Sha384,
        0x0601 => Scheme::RsaPkcs1Sha512,
        _ => {
            return Err(format!(
                "unsupported SCT signature algorithm: {algorithm:#06x}"
            ));
        }
    };
    verify_spki(
        &key.spki,
        scheme,
        &signed,
        sct.signature.signature.as_slice(),
    )
    .map_err(|error| format!("Fulcio SCT verification failed: {error}"))
}

fn signed_data(
    certificate: &Certificate,
    sct: &SignedCertificateTimestamp,
    issuer_spki_der: &[u8],
) -> Result<Vec<u8>, String> {
    let tbs = precertificate_tbs(certificate)
        .map_err(|error| format!("could not reconstruct Fulcio precertificate: {error}"))?;
    let digitally_signed = DigitallySigned {
        version: match sct.version {
            Version::V1 => Version::V1,
        },
        signature_type: SignatureType::CertificateTimestamp,
        timestamp: sct.timestamp,
        signed_entry: SignedEntry::PrecertEntry(PreCert {
            issuer_key_hash: Sha256::digest(issuer_spki_der).into(),
            tbs_certificate: tbs.as_slice().into(),
        }),
        extensions: sct.extensions.clone(),
    };
    digitally_signed
        .tls_serialize()
        .map_err(|error| format!("could not serialize Fulcio SCT input: {error}"))
}

/// RFC 6962 section 3.2: the certificate's `TBSCertificate` without its SCT extension. Every
/// other field keeps the exact encoding that the log signed.
fn precertificate_tbs(certificate: &Certificate) -> der::Result<Vec<u8>> {
    let extensions_tag = Tag::ContextSpecific {
        constructed: true,
        number: TagNumber(3),
    };
    let mut fields = Vec::<Any>::from_der(&certificate.tbs_certificate().to_der()?)?;
    for field in fields
        .iter_mut()
        .filter(|field| field.tag() == extensions_tag)
    {
        let extensions = Extensions::from_der(field.value())?
            .into_iter()
            .filter(|extension| extension.extn_id != CT_PRECERT_SCTS)
            .collect::<Extensions>();
        *field = Any::new(extensions_tag, extensions.to_der()?)?;
    }
    fields.to_der()
}

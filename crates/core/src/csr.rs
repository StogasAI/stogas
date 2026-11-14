//! The PKCS #10 request in which a booting gateway asks for its TLS certificate.

use crate::Error;
use const_oid::{
    AssociatedOid as _,
    db::{rfc4519, rfc5280, rfc5912},
};
use der::{Decode as _, Encode as _, Tag, Tagged as _, asn1::ObjectIdentifier};
use p256::ecdsa::{Signature, VerifyingKey, signature::Verifier as _};
use sha2::{Digest as _, Sha256};
use x509_cert::{
    ext::pkix::{SubjectAltName, name::GeneralName},
    request::{CertReq, ExtensionReq},
};

const MAX_CSR_BYTES: usize = 16 * 1024;

fn invalid(problem: &str) -> Error {
    Error::Node(format!("certificate CSR {problem}"))
}

/// Check that a CSR proves possession of the attested TLS key and asks for a certificate whose
/// only common name and only DNS name are `hostname`.
pub fn verify(der: &[u8], tls_spki_sha256: &str, hostname: &str) -> Result<(), Error> {
    if der.is_empty() || der.len() > MAX_CSR_BYTES {
        return Err(invalid("has an invalid length"));
    }
    // DER decoding also rejects trailing data and every version but 1.
    let csr = CertReq::from_der(der).map_err(|_| invalid("is not valid DER"))?;
    verify_possession(&csr, tls_spki_sha256)?;
    verify_subject(&csr, hostname)?;
    verify_dns_name(&csr, hostname)
}

fn verify_possession(csr: &CertReq, tls_spki_sha256: &str) -> Result<(), Error> {
    if csr.algorithm.oid != rfc5912::ECDSA_WITH_SHA_256 || csr.algorithm.parameters.is_some() {
        return Err(invalid("must use ECDSA with SHA-256"));
    }
    let key = &csr.info.public_key;
    let curve = key
        .algorithm
        .parameters
        .as_ref()
        .and_then(|parameters| parameters.decode_as::<ObjectIdentifier>().ok());
    if key.algorithm.oid != rfc5912::ID_EC_PUBLIC_KEY || curve != Some(rfc5912::SECP_256_R_1) {
        return Err(invalid("must contain a P-256 public key"));
    }
    let verifying_key = key
        .subject_public_key
        .as_bytes()
        .and_then(|bytes| VerifyingKey::from_sec1_bytes(bytes).ok())
        .ok_or_else(|| invalid("P-256 public key is invalid"))?;
    let signature = csr
        .signature
        .as_bytes()
        .and_then(|bytes| Signature::from_der(bytes).ok())
        .ok_or_else(|| invalid("signature is not canonical DER"))?;
    // Strict decoding makes these encodings the exact bytes that the request holds.
    let info = csr.info.to_der().map_err(|_| invalid("is not valid DER"))?;
    verifying_key
        .verify(&info, &signature)
        .map_err(|_| invalid("proof of possession is invalid"))?;
    let spki = key.to_der().map_err(|_| invalid("is not valid DER"))?;
    if hex::encode(Sha256::digest(spki)) != tls_spki_sha256 {
        return Err(invalid("SPKI does not match the attested node key"));
    }
    Ok(())
}

fn verify_subject(csr: &CertReq, hostname: &str) -> Result<(), Error> {
    let mut attributes = csr.info.subject.iter();
    let (Some(attribute), None) = (attributes.next(), attributes.next()) else {
        return Err(invalid("subject must hold only the common name"));
    };
    let text = matches!(
        attribute.value.tag(),
        Tag::Utf8String | Tag::PrintableString | Tag::Ia5String
    );
    if attribute.oid != rfc4519::CN || !text || attribute.value.value() != hostname.as_bytes() {
        return Err(invalid("common name differs from the certificate order"));
    }
    Ok(())
}

fn verify_dns_name(csr: &CertReq, hostname: &str) -> Result<(), Error> {
    let [attribute] = csr.info.attributes.as_slice() else {
        return Err(invalid(
            "must contain exactly one extension-request attribute",
        ));
    };
    let [value] = attribute.values.as_slice() else {
        return Err(invalid("extension request must hold one value"));
    };
    if attribute.oid != ExtensionReq::OID {
        return Err(invalid("contains an unexpected attribute"));
    }
    let request = value
        .decode_as::<ExtensionReq>()
        .map_err(|_| invalid("extension request is not valid DER"))?;
    let [extension] = request.0.as_slice() else {
        return Err(invalid("must request exactly one extension"));
    };
    if extension.extn_id != rfc5280::ID_CE_SUBJECT_ALT_NAME {
        return Err(invalid("contains an unexpected requested extension"));
    }
    let names = SubjectAltName::from_der(extension.extn_value.as_bytes())
        .map_err(|_| invalid("SAN is not valid DER"))?;
    let [GeneralName::DnsName(name)] = names.0.as_slice() else {
        return Err(invalid("SAN must hold exactly one DNS name"));
    };
    if !name.as_str().eq_ignore_ascii_case(hostname) {
        return Err(invalid("DNS name differs from the certificate order"));
    }
    Ok(())
}

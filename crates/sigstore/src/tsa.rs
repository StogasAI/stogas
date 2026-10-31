//! Networkless RFC 3161/CMS timestamp verification.

use crate::{
    crypto::{Scheme, WEBPKI_ALGORITHMS, verify_spki},
    sigstore::SignedTimestamp,
    trust_root::{Authority, TrustedRoot},
};
use base64::{Engine as _, engine::general_purpose::STANDARD};
use cms::{
    cert::CertificateChoices,
    content_info::ContentInfo,
    signed_data::{SignedData, SignerIdentifier},
};
use const_oid::{ObjectIdentifier, db};
use der::{
    Decode as _, Encode as _, Sequence,
    asn1::{BitString, GeneralizedTime, Int, OctetString},
};
use rustls_pki_types::{CertificateDer, UnixTime};
use sha2::{Digest as _, Sha256, Sha384, Sha512};
use std::time::Duration;
use webpki::{EndEntityCert, KeyUsage, anchor_from_trusted_cert};
use x509_cert::{
    Certificate,
    ext::{Extensions, pkix::name::GeneralName},
};

const OID_TST_INFO: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.840.113549.1.9.16.1.4");
const OID_SIGNED_DATA: ObjectIdentifier = db::rfc5911::ID_SIGNED_DATA;
const OID_MESSAGE_DIGEST: ObjectIdentifier = db::rfc6268::ID_MESSAGE_DIGEST;
const OID_CONTENT_TYPE: ObjectIdentifier = db::rfc5911::ID_CONTENT_TYPE;
const OID_TIME_STAMPING: ObjectIdentifier = db::rfc5280::ID_KP_TIME_STAMPING;
const MAX_TIMESTAMPS: usize = 4;
const MAX_CMS_CERTIFICATES: usize = 16;

#[derive(Clone, Debug, Eq, PartialEq, Sequence)]
struct AlgorithmIdentifier {
    algorithm: ObjectIdentifier,
    #[asn1(optional = "true")]
    parameters: Option<der::Any>,
}

#[derive(Clone, Debug, Eq, PartialEq, Sequence)]
struct MessageImprint {
    hash_algorithm: AlgorithmIdentifier,
    hashed_message: OctetString,
}

#[derive(Clone, Debug, Eq, PartialEq, Sequence)]
struct Accuracy {
    #[asn1(optional = "true")]
    seconds: Option<u64>,
    #[asn1(context_specific = "0", optional = "true")]
    millis: Option<u16>,
    #[asn1(context_specific = "1", optional = "true")]
    micros: Option<u16>,
}

#[derive(Clone, Debug, Eq, PartialEq, Sequence)]
struct TstInfo {
    version: u8,
    policy: ObjectIdentifier,
    message_imprint: MessageImprint,
    serial_number: Int,
    gen_time: GeneralizedTime,
    #[asn1(optional = "true")]
    accuracy: Option<Accuracy>,
    #[asn1(default = "default_false")]
    ordering: bool,
    #[asn1(optional = "true")]
    nonce: Option<Int>,
    #[asn1(context_specific = "0", optional = "true", tag_mode = "EXPLICIT")]
    tsa: Option<GeneralName>,
    #[asn1(context_specific = "1", optional = "true", tag_mode = "IMPLICIT")]
    extensions: Option<Extensions>,
}

#[derive(Clone, Debug, Eq, PartialEq, Sequence)]
struct PkiStatusInfo {
    status: u8,
    #[asn1(optional = "true")]
    fail_info: Option<BitString>,
}

#[derive(Clone, Debug, Eq, PartialEq, Sequence)]
struct TimeStampResponse {
    status: PkiStatusInfo,
    #[asn1(optional = "true")]
    time_stamp_token: Option<der::Any>,
}

const fn default_false() -> bool {
    false
}

pub fn verify_all(
    timestamps: &[SignedTimestamp],
    signature: &[u8],
    root: &TrustedRoot,
) -> Result<Option<i64>, String> {
    if timestamps.len() > MAX_TIMESTAMPS {
        return Err("too many RFC 3161 timestamps".into());
    }
    let mut earliest = None;
    for timestamp in timestamps {
        let bytes = STANDARD
            .decode(&timestamp.signed_timestamp)
            .map_err(|error| format!("invalid RFC 3161 timestamp encoding: {error}"))?;
        let verified = verify_timestamp(&bytes, signature, root)?;
        earliest = Some(earliest.map_or(verified, |current: i64| current.min(verified)));
    }
    Ok(earliest)
}

fn verify_timestamp(token: &[u8], signature: &[u8], root: &TrustedRoot) -> Result<i64, String> {
    let (info, signed_data, content) = parse_timestamp(token)?;
    if info.version != 1
        || info.accuracy.as_ref().is_some_and(|accuracy| {
            accuracy
                .millis
                .is_some_and(|value| !(1..=999).contains(&value))
                || accuracy
                    .micros
                    .is_some_and(|value| !(1..=999).contains(&value))
        })
    {
        return Err("unsupported RFC 3161 TSTInfo".into());
    }
    verify_message_imprint(&info.message_imprint, signature)?;
    let time = info
        .gen_time
        .to_system_time()
        .duration_since(std::time::UNIX_EPOCH)
        .map_err(|_| "RFC 3161 timestamp predates the Unix epoch".to_owned())?
        .as_secs();
    let time = i64::try_from(time).map_err(|_| "RFC 3161 timestamp is too large".to_owned())?;
    let authorities = root.tsa_authorities_at(time)?;
    if authorities.is_empty() {
        return Err("no TSA authority was valid at the RFC 3161 time".into());
    }
    let signer = verify_cms(&signed_data, &content, &authorities)?;
    verify_tsa_profile(&signer)?;
    verify_tsa_chain(&signer, &signed_data, &authorities, time)?;
    Ok(time)
}

fn parse_timestamp(token: &[u8]) -> Result<(TstInfo, SignedData, Vec<u8>), String> {
    let content_info = match TimeStampResponse::from_der(token) {
        Ok(response) => {
            if !matches!(response.status.status, 0 | 1) {
                return Err("RFC 3161 response was not granted".into());
            }
            let encoded = response
                .time_stamp_token
                .ok_or_else(|| "RFC 3161 response has no token".to_owned())?
                .to_der()
                .map_err(|error| format!("could not encode RFC 3161 token: {error}"))?;
            ContentInfo::from_der(&encoded)
                .map_err(|error| format!("invalid RFC 3161 ContentInfo: {error}"))?
        }
        Err(_) => ContentInfo::from_der(token)
            .map_err(|error| format!("invalid RFC 3161 token: {error}"))?,
    };
    if content_info.content_type != OID_SIGNED_DATA {
        return Err("RFC 3161 ContentInfo is not SignedData".into());
    }
    let signed_data = SignedData::from_der(
        &content_info
            .content
            .to_der()
            .map_err(|error| format!("could not encode RFC 3161 SignedData: {error}"))?,
    )
    .map_err(|error| format!("invalid RFC 3161 SignedData: {error}"))?;
    if signed_data.encap_content_info.econtent_type != OID_TST_INFO {
        return Err("RFC 3161 SignedData does not contain TSTInfo".into());
    }
    let content = signed_data
        .encap_content_info
        .econtent
        .as_ref()
        .ok_or_else(|| "RFC 3161 SignedData has detached content".to_owned())?
        .value()
        .to_vec();
    let info = TstInfo::from_der(&content)
        .map_err(|error| format!("invalid RFC 3161 TSTInfo: {error}"))?;
    Ok((info, signed_data, content))
}

fn verify_message_imprint(imprint: &MessageImprint, signature: &[u8]) -> Result<(), String> {
    let digest = hash(imprint.hash_algorithm.algorithm, signature)?;
    if digest != imprint.hashed_message.as_bytes() {
        return Err("RFC 3161 message imprint does not bind the signature".into());
    }
    Ok(())
}

fn verify_cms(
    signed_data: &SignedData,
    content: &[u8],
    authorities: &[&Authority],
) -> Result<Certificate, String> {
    let signers = &signed_data.signer_infos.0;
    if signers.len() != 1 {
        return Err("RFC 3161 requires exactly one CMS signer".into());
    }
    let signer = signers
        .get(0)
        .ok_or_else(|| "RFC 3161 CMS signer is absent".to_owned())?;
    let mut certificates = extract_certificates(signed_data)?;
    for authority in authorities {
        for certificate in &authority.certificates {
            if let Ok(certificate) = Certificate::from_der(certificate) {
                certificates.push(certificate);
            }
        }
    }
    let certificate = find_signer(&signer.sid, &certificates)?;
    let attributes = signer
        .signed_attrs
        .as_ref()
        .ok_or_else(|| "RFC 3161 CMS signer has no signed attributes".to_owned())?;
    verify_single_attribute_digest(
        attributes,
        OID_MESSAGE_DIGEST,
        &hash(signer.digest_alg.oid, content)?,
    )?;
    verify_single_attribute_oid(attributes, OID_CONTENT_TYPE, OID_TST_INFO)?;
    let attributes = reencode_attributes(attributes)?;
    let scheme = scheme_for_signer(
        &certificate,
        signer.digest_alg.oid,
        signer.signature_algorithm.oid,
    )?;
    let spki = certificate
        .tbs_certificate
        .subject_public_key_info
        .to_der()
        .map_err(|error| format!("could not encode TSA signer key: {error}"))?;
    verify_spki(&spki, scheme, &attributes, signer.signature.as_bytes())
        .map_err(|error| format!("RFC 3161 CMS signature failed: {error}"))?;
    Ok(certificate)
}

fn extract_certificates(signed_data: &SignedData) -> Result<Vec<Certificate>, String> {
    let certificates = signed_data
        .certificates
        .as_ref()
        .map(|set| {
            set.0
                .iter()
                .filter_map(|choice| match choice {
                    CertificateChoices::Certificate(certificate) => Some(certificate.clone()),
                    CertificateChoices::Other(_) => None,
                })
                .collect::<Vec<_>>()
        })
        .unwrap_or_default();
    if certificates.len() > MAX_CMS_CERTIFICATES {
        return Err("RFC 3161 CMS certificate set exceeds resource limits".into());
    }
    Ok(certificates)
}

fn find_signer(id: &SignerIdentifier, certificates: &[Certificate]) -> Result<Certificate, String> {
    let mut matches: Vec<&Certificate> = Vec::new();
    for certificate in certificates.iter().filter(|certificate| match id {
        SignerIdentifier::IssuerAndSerialNumber(issuer) => {
            certificate.tbs_certificate.issuer == issuer.issuer
                && certificate.tbs_certificate.serial_number == issuer.serial_number
        }
        SignerIdentifier::SubjectKeyIdentifier(expected) => {
            certificate
                .tbs_certificate
                .extensions
                .as_ref()
                .into_iter()
                .flat_map(|extensions| extensions.iter())
                .find(|extension| extension.extn_id == db::rfc5280::ID_CE_SUBJECT_KEY_IDENTIFIER)
                .and_then(|extension| {
                    x509_cert::ext::pkix::SubjectKeyIdentifier::from_der(
                        extension.extn_value.as_bytes(),
                    )
                    .ok()
                })
                .as_ref()
                == Some(expected)
        }
    }) {
        // Timestamp authorities embed the signing certificate that trusted roots also list.
        if !matches.contains(&certificate) {
            matches.push(certificate);
        }
    }
    let [signer] = matches[..] else {
        return Err("RFC 3161 signer identifier is absent or ambiguous".into());
    };
    Ok(signer.clone())
}

fn verify_single_attribute_digest(
    attributes: &x509_cert::attr::Attributes,
    oid: ObjectIdentifier,
    expected: &[u8],
) -> Result<(), String> {
    use der::asn1::OctetStringRef;
    let matches = attributes
        .iter()
        .filter(|attribute| attribute.oid == oid)
        .collect::<Vec<_>>();
    if matches.len() != 1 || matches[0].values.len() != 1 {
        return Err("RFC 3161 CMS message-digest attribute is absent or ambiguous".into());
    }
    let value = matches[0]
        .values
        .get(0)
        .ok_or_else(|| "RFC 3161 CMS message digest is absent".to_owned())?
        .to_der()
        .map_err(|error| format!("could not encode CMS message digest: {error}"))?;
    let digest = OctetStringRef::from_der(&value)
        .map_err(|error| format!("invalid CMS message digest: {error}"))?;
    if digest.as_bytes() != expected {
        return Err("RFC 3161 CMS message digest differs from TSTInfo".into());
    }
    Ok(())
}

fn verify_single_attribute_oid(
    attributes: &x509_cert::attr::Attributes,
    oid: ObjectIdentifier,
    expected: ObjectIdentifier,
) -> Result<(), String> {
    let matches = attributes
        .iter()
        .filter(|attribute| attribute.oid == oid)
        .collect::<Vec<_>>();
    if matches.len() != 1 || matches[0].values.len() != 1 {
        return Err("RFC 3161 CMS content-type attribute is absent or ambiguous".into());
    }
    let value = matches[0]
        .values
        .get(0)
        .ok_or_else(|| "RFC 3161 CMS content type is absent".to_owned())?
        .decode_as::<ObjectIdentifier>()
        .map_err(|error| format!("invalid CMS content type: {error}"))?;
    if value != expected {
        return Err("RFC 3161 CMS content type is not TSTInfo".into());
    }
    Ok(())
}

fn reencode_attributes(attributes: &x509_cert::attr::Attributes) -> Result<Vec<u8>, String> {
    let values = attributes.iter().cloned().collect::<Vec<_>>();
    der::asn1::SetOfVec::try_from(values)
        .and_then(|set| set.to_der())
        .map_err(|error| format!("could not canonicalize RFC 3161 CMS attributes: {error}"))
}

fn scheme_for_signer(
    certificate: &Certificate,
    digest: ObjectIdentifier,
    signature: ObjectIdentifier,
) -> Result<Scheme, String> {
    let spki = &certificate.tbs_certificate.subject_public_key_info;
    if spki.algorithm.oid == db::rfc5912::ID_EC_PUBLIC_KEY {
        let curve = spki
            .algorithm
            .parameters
            .as_ref()
            .ok_or_else(|| "TSA EC key has no curve".to_owned())?
            .decode_as::<ObjectIdentifier>()
            .map_err(|error| format!("invalid TSA EC curve: {error}"))?;
        return match (curve, digest, signature) {
            (
                db::rfc5912::SECP_256_R_1,
                db::rfc5912::ID_SHA_256,
                db::rfc5912::ECDSA_WITH_SHA_256,
            ) => Ok(Scheme::EcdsaP256Sha256),
            (
                db::rfc5912::SECP_256_R_1,
                db::rfc5912::ID_SHA_384,
                db::rfc5912::ECDSA_WITH_SHA_384,
            ) => Ok(Scheme::EcdsaP256Sha384),
            (
                db::rfc5912::SECP_384_R_1,
                db::rfc5912::ID_SHA_256,
                db::rfc5912::ECDSA_WITH_SHA_256,
            ) => Ok(Scheme::EcdsaP384Sha256),
            (
                db::rfc5912::SECP_384_R_1,
                db::rfc5912::ID_SHA_384,
                db::rfc5912::ECDSA_WITH_SHA_384,
            ) => Ok(Scheme::EcdsaP384Sha384),
            _ => Err("unsupported TSA EC signature algorithm".into()),
        };
    }
    Err("unsupported TSA signer key".into())
}

fn verify_tsa_profile(certificate: &Certificate) -> Result<(), String> {
    use x509_cert::ext::pkix::ExtendedKeyUsage;
    let (critical, usage): (bool, ExtendedKeyUsage) = certificate
        .tbs_certificate
        .get()
        .map_err(|error| format!("could not parse TSA EKU: {error}"))?
        .ok_or_else(|| "TSA certificate has no EKU".to_owned())?;
    if !critical || usage.0.as_slice() != [OID_TIME_STAMPING] {
        return Err("TSA certificate must have one critical timeStamping EKU".into());
    }
    Ok(())
}

fn verify_tsa_chain(
    signer: &Certificate,
    signed_data: &SignedData,
    authorities: &[&Authority],
    time: i64,
) -> Result<(), String> {
    let signer_der = CertificateDer::from(
        signer
            .to_der()
            .map_err(|error| format!("could not encode TSA signer certificate: {error}"))?,
    );
    let end_entity = EndEntityCert::try_from(&signer_der)
        .map_err(|error| format!("invalid TSA signer certificate: {error}"))?;
    let mut anchors = Vec::new();
    let mut intermediates = extract_certificates(signed_data)?
        .into_iter()
        .filter(|certificate| certificate != signer)
        .map(|certificate| certificate.to_der())
        .collect::<Result<Vec<_>, _>>()
        .map_err(|error| format!("could not encode TSA certificate: {error}"))?
        .into_iter()
        .map(CertificateDer::from)
        .collect::<Vec<_>>();
    for authority in authorities {
        let (root, rest) = authority
            .certificates
            .split_last()
            .ok_or_else(|| "TSA authority contains no certificates".to_owned())?;
        let root = CertificateDer::from(root.as_slice());
        anchors.push(
            anchor_from_trusted_cert(&root)
                .map(|anchor| anchor.to_owned())
                .map_err(|error| format!("invalid TSA root: {error}"))?,
        );
        intermediates.extend(
            rest.iter()
                .map(|certificate| CertificateDer::from(certificate.clone())),
        );
    }
    let seconds = u64::try_from(time).map_err(|_| "negative TSA verification time".to_owned())?;
    end_entity
        .verify_for_usage(
            WEBPKI_ALGORITHMS,
            &anchors,
            &intermediates,
            UnixTime::since_unix_epoch(Duration::from_secs(seconds)),
            KeyUsage::required(OID_TIME_STAMPING.as_bytes()),
            None,
            None,
        )
        .map_err(|error| format!("TSA certificate-chain validation failed: {error}"))?;
    Ok(())
}

fn hash(algorithm: ObjectIdentifier, value: &[u8]) -> Result<Vec<u8>, String> {
    match algorithm {
        db::rfc5912::ID_SHA_256 => Ok(Sha256::digest(value).to_vec()),
        db::rfc5912::ID_SHA_384 => Ok(Sha384::digest(value).to_vec()),
        db::rfc5912::ID_SHA_512 => Ok(Sha512::digest(value).to_vec()),
        _ => Err(format!("unsupported digest algorithm: {algorithm}")),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[derive(serde::Deserialize)]
    struct Fixture {
        signature: String,
        timestamp: String,
    }

    fn fixture() -> (Vec<u8>, SignedTimestamp, TrustedRoot) {
        let fixture: Fixture = serde_json::from_str(include_str!(
            "../../../tests/fixtures/github-rfc3161-sha384.json"
        ))
        .unwrap();
        let signature = STANDARD.decode(fixture.signature).unwrap();
        let timestamp = SignedTimestamp {
            signed_timestamp: fixture.timestamp,
        };
        let root = TrustedRoot::from_json(include_str!(
            "../../../tests/fixtures/github-rfc3161-trusted-root.json"
        ))
        .unwrap();
        (signature, timestamp, root)
    }

    #[test]
    fn verifies_real_github_sha384_timestamp() {
        let (signature, timestamp, root) = fixture();
        assert_eq!(
            verify_all(&[timestamp], &signature, &root).unwrap(),
            Some(1_772_445_135)
        );
    }

    #[test]
    fn rejects_timestamp_imprint_and_cms_mutations() {
        let (signature, timestamp, root) = fixture();
        let mut changed_signature = signature.clone();
        changed_signature[0] ^= 1;
        assert!(verify_all(std::slice::from_ref(&timestamp), &changed_signature, &root).is_err());

        let mut token = STANDARD.decode(timestamp.signed_timestamp).unwrap();
        let last = token.len() - 1;
        token[last] ^= 1;
        let changed = SignedTimestamp {
            signed_timestamp: STANDARD.encode(token),
        };
        assert!(verify_all(&[changed], &signature, &root).is_err());
    }

    // timestamp.sigstore.dev embeds its signing certificate, which Sigstore's trusted root also
    // lists, so one certificate is found twice.
    #[test]
    fn verifies_a_production_sigstore_timestamp() {
        use ed25519_dalek::SigningKey;
        let vectors: serde_json::Value = serde_json::from_str(include_str!(
            "../../../tests/fixtures/rekor-v2-vectors.json"
        ))
        .unwrap();
        let root = TrustedRoot::from_json(
            &serde_json::json!({
                "mediaType": "application/vnd.dev.sigstore.trustedroot.v0.2+json",
                "timestampAuthorities": vectors["timestamp_authorities"]
            })
            .to_string(),
        )
        .unwrap();
        let signature = SigningKey::from_bytes(&[9; 32])
            .sign_prehashed(
                Sha512::new_with_prefix(
                    b"exact document bytes, including its independent author signature\n",
                ),
                None,
            )
            .unwrap()
            .to_bytes();
        let timestamp = SignedTimestamp {
            signed_timestamp: vectors["document_signature_timestamp"]
                .as_str()
                .unwrap()
                .to_owned(),
        };
        assert_eq!(
            verify_all(std::slice::from_ref(&timestamp), &signature, &root).unwrap(),
            Some(1_793_423_809)
        );
        assert!(verify_all(&[timestamp], &[0; 64], &root).is_err());
    }

    #[test]
    fn official_timestamp_cases() {
        // Copied unchanged from sigstore/sigstore-conformance at
        // acb38c9ee4274fa058127e6a5a4cdb9e94e449e1 (test/assets/bundle-verify), which is licensed
        // under the Apache License 2.0. Each case's message signature is what its token dates.
        let cases = [
            ("rekor2-happy-path", true),
            ("rekor2-timestamp-with-embedded-cert", true),
            ("rekor2-timestamp-without-embedded-cert", true),
            ("rekor2-timestamp-with-expired-cert-chain", true),
            ("trust-root-tsa-validity-end-inclusive", true),
            // Bundle verification rejects this one because it dates the signature outside the
            // Fulcio certificate. Here it already fails: its base64 is line-wrapped, which Go
            // tolerates but no Sigstore client writes.
            ("rekor2-timestamp-with-incorrect-time_fail", false),
            (
                "rekor2-timestamp-outside-trust-root-tsa-validity_fail",
                false,
            ),
            ("rekor2-timestamp-outside-tsa-cert-validity_fail", false),
            ("rekor2-timestamp-payload-mismatch_fail", false),
            (
                "rekor2-timestamp-untrusted-tsa-with-embedded-cert_fail",
                false,
            ),
            (
                "rekor2-timestamp-untrusted-tsa-without-embedded-cert_fail",
                false,
            ),
        ];
        let directory = concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../../tests/fixtures/sigstore-conformance"
        );
        for (case, valid) in cases {
            let read =
                |file: &str| std::fs::read_to_string(format!("{directory}/{case}/{file}")).unwrap();
            let bundle: serde_json::Value =
                serde_json::from_str(&read("bundle.sigstore.json")).unwrap();
            let root = TrustedRoot::from_json(&read("trusted_root.json")).unwrap();
            let signature = STANDARD
                .decode(bundle["messageSignature"]["signature"].as_str().unwrap())
                .unwrap();
            let timestamps: Vec<SignedTimestamp> = serde_json::from_value(
                bundle["verificationMaterial"]["timestampVerificationData"]["rfc3161Timestamps"]
                    .clone(),
            )
            .unwrap();
            let verified = verify_all(&timestamps, &signature, &root);
            assert_eq!(verified.is_ok(), valid, "{case}: {verified:?}");
        }
    }
}

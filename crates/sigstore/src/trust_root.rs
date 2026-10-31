//! Sigstore trusted roots with deterministic time selection.

use base64::{Engine as _, engine::general_purpose::STANDARD};
use chrono::{DateTime, Utc};
use serde::Deserialize;
use sha2::{Digest as _, Sha256};
use std::collections::HashSet;

// Sigstore's v0.2 adds fields that this verifier does not need, and newer roots must use it.
const MEDIA_TYPES: [&str; 3] = [
    "application/vnd.dev.sigstore.trustedroot+json;version=0.1",
    "application/vnd.dev.sigstore.trustedroot.v0.1+json",
    "application/vnd.dev.sigstore.trustedroot.v0.2+json",
];

// Evidence delivers Sigstore's current trusted root to every released verifier, so parsing
// ignores fields and skips logs that a later Sigstore format adds. A proof that needs a
// skipped log still fails.
#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct TrustedRootDocument {
    media_type: String,
    #[serde(default)]
    certificate_authorities: Vec<CertificateAuthority>,
    #[serde(default)]
    tlogs: Vec<TransparencyLog>,
    #[serde(default)]
    ctlogs: Vec<TransparencyLog>,
    #[serde(default)]
    timestamp_authorities: Vec<CertificateAuthority>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct CertificateAuthority {
    cert_chain: CertificateChain,
    #[serde(default)]
    valid_for: Option<Validity>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct CertificateChain {
    certificates: Vec<CertificateEntry>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct CertificateEntry {
    raw_bytes: String,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct TransparencyLog {
    #[serde(default)]
    base_url: String,
    hash_algorithm: String,
    public_key: PublicKey,
    log_id: LogId,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct PublicKey {
    raw_bytes: String,
    key_details: String,
    #[serde(default)]
    valid_for: Option<Validity>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct LogId {
    key_id: String,
}

#[derive(Clone, Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct Validity {
    #[serde(default)]
    start: Option<String>,
    #[serde(default)]
    end: Option<String>,
}

impl Validity {
    fn contains_seconds(&self, time: i64) -> Result<bool, String> {
        let start = self.start.as_deref().map(parse_time).transpose()?;
        let end = self.end.as_deref().map(parse_time).transpose()?;
        Ok(start.is_none_or(|start| time >= start) && end.is_none_or(|end| time <= end))
    }
}

#[derive(Clone, Debug)]
pub struct LogKey {
    pub id: Vec<u8>,
    pub spki: Vec<u8>,
    /// The host of the log's base URL: the name that signs its checkpoints, and a Rekor v2
    /// checkpoint's origin.
    pub origin: String,
    validity: Option<Validity>,
}

impl LogKey {
    /// When the trusted root starts this key's validity, in Unix seconds, if it names a start.
    pub(crate) fn start(&self) -> Result<Option<i64>, String> {
        self.validity
            .as_ref()
            .and_then(|validity| validity.start.as_deref())
            .map(parse_time)
            .transpose()
    }
}

#[derive(Clone, Debug)]
pub struct Authority {
    pub certificates: Vec<Vec<u8>>,
    validity: Option<Validity>,
}

/// Sigstore's Fulcio, Rekor, CT and timestamp keys with their validity periods.
#[derive(Clone, Debug)]
pub struct TrustedRoot {
    fulcio: Vec<Authority>,
    rekor: Vec<LogKey>,
    ct: Vec<LogKey>,
    tsa: Vec<Authority>,
}

impl TrustedRoot {
    /// Parses a Sigstore trusted root. The caller vouches for it: take it from
    /// [`crate::verify_trust_update`], or from evidence whose verification did.
    ///
    /// # Errors
    /// Rejects malformed roots, unsupported media types and duplicate keys.
    pub fn from_json(json: &str) -> Result<Self, crate::Error> {
        Self::parse(json).map_err(crate::Error::Trust)
    }

    /// Sigstore's production trusted root as the TUF fixture captured it.
    #[cfg(test)]
    pub(crate) fn production() -> &'static Self {
        static ROOT: std::sync::LazyLock<TrustedRoot> = std::sync::LazyLock::new(|| {
            TrustedRoot::complete(include_str!(
                "../../../tests/fixtures/sigstore-tuf/trusted_root.json"
            ))
            .unwrap()
        });
        &ROOT
    }

    /// Parse a trusted root that has every key type the supported proofs use.
    pub(crate) fn complete(json: &str) -> Result<Self, String> {
        let root = Self::parse(json)?;
        if root.fulcio.is_empty() || root.rekor.is_empty() || root.ct.is_empty() {
            return Err("Sigstore trusted root is incomplete".into());
        }
        Ok(root)
    }

    fn parse(json: &str) -> Result<Self, String> {
        let document: TrustedRootDocument = serde_json::from_str(json)
            .map_err(|error| format!("invalid Sigstore trusted root: {error}"))?;
        if !MEDIA_TYPES.contains(&document.media_type.as_str()) {
            return Err("unsupported Sigstore trusted-root media type".into());
        }
        let fulcio = parse_authorities(document.certificate_authorities, "Fulcio")?;
        let tsa = parse_authorities(document.timestamp_authorities, "TSA")?;
        let rekor = parse_logs(document.tlogs, "Rekor")?;
        let ct = parse_logs(document.ctlogs, "CT")?;
        Ok(Self {
            fulcio,
            rekor,
            ct,
            tsa,
        })
    }

    pub(crate) fn fulcio_certificates_at(&self, time: i64) -> Result<Vec<Vec<u8>>, String> {
        certificates_at(&self.fulcio, time)
    }

    pub(crate) fn rekor_key_at(&self, id: &[u8], time: i64) -> Result<&LogKey, String> {
        key_at(&self.rekor, id, time, "Rekor")
    }

    pub(crate) fn ct_key_at(&self, id: &[u8], time: i64) -> Result<&LogKey, String> {
        key_at(&self.ct, id, time, "CT")
    }

    pub(crate) fn tsa_authorities_at(&self, time: i64) -> Result<Vec<&Authority>, String> {
        self.tsa
            .iter()
            .filter_map(|authority| {
                authority
                    .validity
                    .as_ref()
                    .map_or(Some(Ok(authority)), |validity| {
                        match validity.contains_seconds(time) {
                            Ok(true) => Some(Ok(authority)),
                            Ok(false) => None,
                            Err(error) => Some(Err(error)),
                        }
                    })
            })
            .collect()
    }
}

fn parse_authorities(
    authorities: Vec<CertificateAuthority>,
    label: &str,
) -> Result<Vec<Authority>, String> {
    let mut hashes = HashSet::new();
    authorities
        .into_iter()
        .map(|authority| {
            if authority.cert_chain.certificates.is_empty() {
                return Err(format!("{label} authority contains no certificates"));
            }
            let certificates = authority
                .cert_chain
                .certificates
                .into_iter()
                .map(|certificate| decode(&certificate.raw_bytes, "certificate"))
                .collect::<Result<Vec<_>, _>>()?;
            for certificate in &certificates {
                if !hashes.insert(Sha256::digest(certificate).to_vec()) {
                    return Err(format!("duplicate {label} certificate"));
                }
            }
            Ok(Authority {
                certificates,
                validity: authority.valid_for,
            })
        })
        .collect()
}

fn parse_logs(logs: Vec<TransparencyLog>, label: &str) -> Result<Vec<LogKey>, String> {
    let mut ids = HashSet::new();
    logs.into_iter()
        .filter(|log| {
            log.hash_algorithm == "SHA2_256"
                && matches!(
                    log.public_key.key_details.as_str(),
                    "PKIX_ECDSA_P256_SHA_256" | "PKIX_ED25519"
                )
        })
        .map(|log| {
            let spki = decode(&log.public_key.raw_bytes, "log public key")?;
            let id = decode(&log.log_id.key_id, "log id")?;
            if id.len() != 32 || !ids.insert(id.clone()) {
                return Err(format!("invalid or duplicate {label} log id"));
            }
            Ok(LogKey {
                id,
                spki,
                origin: host(&log.base_url),
                validity: log.public_key.valid_for,
            })
        })
        .collect()
}

/// Like sigstore-go's `url.Hostname`, so `https://log2025-1.rekor.sigstore.dev` names
/// `log2025-1.rekor.sigstore.dev`. Without a scheme there is no host, so no checkpoint matches.
fn host(base_url: &str) -> String {
    let Some((_, rest)) = base_url.split_once("://") else {
        return String::new();
    };
    let authority = rest.split(['/', '?', '#']).next().unwrap_or_default();
    let host = authority
        .rsplit_once('@')
        .map_or(authority, |(_, host)| host);
    host.strip_prefix('[')
        .map_or_else(
            || host.split(':').next(),
            |bracketed| bracketed.split(']').next(),
        )
        .unwrap_or_default()
        .to_owned()
}

fn key_at<'a>(keys: &'a [LogKey], id: &[u8], time: i64, label: &str) -> Result<&'a LogKey, String> {
    for key in keys.iter().filter(|key| key.id == id) {
        if key
            .validity
            .as_ref()
            .map_or(Ok(true), |validity| validity.contains_seconds(time))?
        {
            return Ok(key);
        }
    }
    Err(format!(
        "no {label} key was valid for the authenticated time"
    ))
}

fn certificates_at(authorities: &[Authority], time: i64) -> Result<Vec<Vec<u8>>, String> {
    let mut certificates = Vec::new();
    for authority in authorities {
        if authority
            .validity
            .as_ref()
            .map_or(Ok(true), |validity| validity.contains_seconds(time))?
        {
            certificates.extend(authority.certificates.iter().cloned());
        }
    }
    if certificates.is_empty() {
        return Err("no certificate authority was valid for the authenticated time".into());
    }
    Ok(certificates)
}

fn decode(value: &str, label: &str) -> Result<Vec<u8>, String> {
    STANDARD
        .decode(value)
        .map_err(|error| format!("invalid base64 {label}: {error}"))
}

fn parse_time(value: &str) -> Result<i64, String> {
    DateTime::parse_from_rfc3339(value)
        .map(|time| time.with_timezone(&Utc).timestamp())
        .map_err(|error| format!("invalid trusted-root time {value:?}: {error}"))
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    const CHANGE: &str = "2026-01-01T00:00:00Z";

    fn log(seed: u8, valid_for: &serde_json::Value) -> serde_json::Value {
        json!({
            "baseUrl": "https://rekor.sigstore.dev", "hashAlgorithm": "SHA2_256",
            "publicKey": {"rawBytes": STANDARD.encode([seed; 4]), "keyDetails": "PKIX_ED25519", "validFor": valid_for},
            "logId": {"keyId": STANDARD.encode([seed; 32])}
        })
    }

    fn authority(seed: u8, valid_for: &serde_json::Value) -> serde_json::Value {
        json!({
            "subject": {}, "validFor": valid_for,
            "certChain": {"certificates": [{"rawBytes": STANDARD.encode([seed; 4])}]}
        })
    }

    // Sigstore replaces a key by ending the old key's validity and adding a new key, and
    // never deletes the old one. Each proof uses the key that was valid at its logged time.
    #[test]
    fn rotated_keys_verify_only_proofs_from_their_own_validity_window() {
        let root = TrustedRoot::from_json(
            &json!({
                "mediaType": MEDIA_TYPES[0],
                "tlogs": [
                    log(1, &json!({"start": "2021-01-12T11:53:27Z", "end": CHANGE})),
                    log(2, &json!({"start": CHANGE}))
                ],
                "certificateAuthorities": [
                    authority(1, &json!({"start": "2022-04-13T20:06:15Z", "end": CHANGE})),
                    authority(2, &json!({"start": CHANGE}))
                ],
                "ctlogs": [], "timestampAuthorities": []
            })
            .to_string(),
        )
        .unwrap();
        let change = parse_time(CHANGE).unwrap();
        let (before, after) = (change - 1, change + 1);

        assert_eq!(root.rekor_key_at(&[1; 32], before).unwrap().spki, [1; 4]);
        assert!(root.rekor_key_at(&[1; 32], after).is_err());
        assert!(root.rekor_key_at(&[2; 32], before).is_err());
        assert_eq!(root.rekor_key_at(&[2; 32], after).unwrap().spki, [2; 4]);
        // The boundary second belongs to both windows, so no proof falls between them.
        assert!(root.rekor_key_at(&[1; 32], change).is_ok());
        assert!(root.rekor_key_at(&[2; 32], change).is_ok());

        assert_eq!(root.fulcio_certificates_at(before).unwrap(), [vec![1; 4]]);
        assert_eq!(root.fulcio_certificates_at(after).unwrap(), [vec![2; 4]]);
        assert!(
            root.fulcio_certificates_at(parse_time("2020-01-01T00:00:00Z").unwrap())
                .is_err()
        );
    }

    // Released verifiers read whatever trusted root current evidence carries.
    #[test]
    fn later_fields_and_unsupported_logs_do_not_reject_the_root() {
        let mut p384 = log(3, &json!({}));
        p384["publicKey"]["keyDetails"] = json!("PKIX_ECDSA_P384_SHA_384");
        let mut extended = log(1, &json!({}));
        extended["operator"] = json!("sigstore.dev");
        extended["checkpointKeyId"] = json!({"keyId": STANDARD.encode([1; 32])});
        let root = TrustedRoot::complete(
            &json!({
                "mediaType": MEDIA_TYPES[0], "tlogs": [extended, p384], "ctlogs": [log(2, &json!({}))],
                "certificateAuthorities": [authority(1, &json!({}))], "signingConfig": {}
            })
            .to_string(),
        )
        .unwrap();
        assert!(root.rekor_key_at(&[1; 32], 0).is_ok());
        assert!(root.rekor_key_at(&[3; 32], 0).is_err());
        assert!(root.tsa_authorities_at(0).unwrap().is_empty());
        let other =
            json!({"mediaType": "application/vnd.dev.sigstore.trustedroot+json;version=0.2"});
        assert!(TrustedRoot::complete(&other.to_string()).is_err());
    }

    // Sigstore requires new trusted roots to use v0.2, which only adds fields.
    #[test]
    fn accepts_each_published_media_type() {
        let root = |media_type: &str| {
            TrustedRoot::from_json(
                &json!({"mediaType": media_type, "tlogs": [log(1, &json!({}))]}).to_string(),
            )
        };
        for media_type in MEDIA_TYPES {
            assert!(root(media_type).is_ok(), "{media_type}");
        }
        for media_type in [
            "application/vnd.dev.sigstore.trustedroot.v0.3+json",
            "application/vnd.dev.sigstore.trustedroot+json;version=0.2",
            "application/vnd.dev.sigstore.trustedroot.v0.2+json ",
            "",
        ] {
            assert!(root(media_type).is_err(), "{media_type}");
        }
    }

    #[test]
    fn names_each_log_by_its_base_url_host() {
        for (base_url, origin) in [
            (
                "https://log2025-1.rekor.sigstore.dev",
                "log2025-1.rekor.sigstore.dev",
            ),
            (
                "https://log2025-1.rekor.sigstore.dev/",
                "log2025-1.rekor.sigstore.dev",
            ),
            ("https://rekor.sigstore.dev/api/v1", "rekor.sigstore.dev"),
            (
                "https://user@log.example:8443/path?query#fragment",
                "log.example",
            ),
            ("https://log.example?query", "log.example"),
            ("http://[2001:db8::1]:8080/", "2001:db8::1"),
            ("log.example", ""),
            ("", ""),
        ] {
            assert_eq!(host(base_url), origin, "{base_url}");
        }
    }
}

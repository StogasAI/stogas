//! Offline verification of GitHub build attestations and Stogas document publication.

mod crypto;
mod hashedrekord;
mod note;
mod sct;
mod sigstore;
pub mod strict_json;
mod tlog;
mod trust_root;
mod tsa;
mod tuf;

pub use trust_root::TrustedRoot;
pub use tuf::{TrustUpdate, verify_current_trust_update, verify_trust_update};

use const_oid::ObjectIdentifier;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use sigstore::CertificatePolicy;
use std::collections::{HashMap, HashSet};
use thiserror::Error;

/// Maximum accepted serialized Sigstore bundle size.
pub const MAX_BUNDLE_BYTES: usize = 1_048_576;
/// Maximum document bytes hashed by the public document-inclusion verifier.
pub const MAX_DOCUMENT_BYTES: usize = 16 * 1024 * 1024;
// GitHub's attestation action accepts at most 1,024 subjects per statement.
const MAX_SUBJECTS: usize = 1024;
const MAX_BUNDLES: usize = 16;
const DSSE_PAYLOAD_TYPE: &str = "application/vnd.in-toto+json";
const SIGSTORE_BUNDLE_MEDIA_TYPE: &str = "application/vnd.dev.sigstore.bundle.v0.3+json";
const GITHUB_OIDC_ISSUER: &str = "https://token.actions.githubusercontent.com";
// Fulcio copies these claims from GitHub's OIDC token into the certificate. The workflow writes
// the provenance predicate itself, so a workflow at a moved tag or on a self-hosted runner could
// put anything there; the certificate is the only place GitHub vouches for them.
const RUNNER_ENVIRONMENT: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.3.6.1.4.1.57264.1.11");
const SOURCE_REPOSITORY_URI: ObjectIdentifier =
    ObjectIdentifier::new_unwrap("1.3.6.1.4.1.57264.1.12");
const SOURCE_REPOSITORY_DIGEST: ObjectIdentifier =
    ObjectIdentifier::new_unwrap("1.3.6.1.4.1.57264.1.13");
const SOURCE_REPOSITORY_REF: ObjectIdentifier =
    ObjectIdentifier::new_unwrap("1.3.6.1.4.1.57264.1.14");

/// Policy for one build attestation from a GitHub-hosted Actions runner.
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct GithubPolicy {
    /// Repository URI, for example `https://github.com/StogasAI/gateway`.
    pub repository: String,
    /// Workflow identity URI pinned to a workflow path and ref.
    pub workflow_identity: String,
    /// Git ref which invoked the workflow.
    pub source_ref: String,
    /// Git commit SHA which invoked the workflow.
    pub source_commit: String,
    /// Required in-toto predicate type.
    pub predicate_type: String,
}

/// Generic identity policy for the supported Sigstore v0.3 DSSE profile.
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct IdentityPolicy {
    /// Exact URI SAN expected in the Fulcio leaf certificate.
    pub certificate_identity: String,
    /// Exact OIDC issuer expected in the Fulcio extension.
    pub certificate_oidc_issuer: String,
    /// Required in-toto predicate type.
    pub predicate_type: String,
}

/// A subject which must be bound by the attestation.
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Subject<'a> {
    /// Subject name in the in-toto statement.
    pub name: &'a str,
    /// Lowercase SHA-256 digest.
    pub sha256: &'a str,
}

/// Authenticated claims returned after cryptographic and policy verification.
#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct VerifiedAttestation {
    /// Authenticated integration/signing time in Unix seconds.
    pub integrated_time: i64,
    /// Predicate type from the verified in-toto statement.
    pub predicate_type: String,
    /// Subject names and SHA-256 digests from the verified statement.
    pub subjects: Vec<(String, String)>,
}

/// A verified Rekor entry that logged a document.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DocumentEntry {
    /// Unix seconds: Rekor v1's signed entry time, or for Rekor v2, which signs no time, the
    /// timestamp authority's.
    pub time: i64,
    /// Where a Rekor v2 log holds the entry. Rekor v1 is one log with a search index.
    pub v2: Option<LogPosition>,
}

/// An entry's place in a Rekor v2 log.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct LogPosition {
    /// The log's checkpoint origin: the host of its base URL in the trusted root.
    pub origin: String,
    /// The entry's index, which its inclusion proof binds.
    pub index: u64,
    /// When the trusted root starts the log key's validity, in Unix seconds, if it names one.
    pub log_start: Option<i64>,
}

/// Verify that the designated submitter logged exact artifact bytes through Rekor's
/// SHA-512/Ed25519ph profile, and return when and, in Rekor v2, where it was logged.
///
/// `submitter` is the Ed25519 `SubjectPublicKeyInfo` DER that must have submitted the entry,
/// so a Rekor v1 search by that key finds every accepted entry. Rekor v2 has no search index:
/// a caller that must find every entry also limits the logs and indexes it accepts and reads
/// every entry there. The submission key does not approve the artifact: separately
/// authenticate it with its trusted signing policy, including any post-quantum signature.
///
/// # Errors
/// Rejects malformed bundles, substituted artifacts, other submitters, invalid signatures,
/// log proofs or times.
pub fn verify_rekor_document_inclusion(
    trust: &TrustedRoot,
    bundle: &[u8],
    artifact: &[u8],
    submitter: &[u8],
) -> Result<DocumentEntry, Error> {
    if bundle.len() > MAX_BUNDLE_BYTES || artifact.len() > MAX_DOCUMENT_BYTES {
        return Err(Error::TooLarge);
    }
    let value =
        strict_json::from_slice(bundle).map_err(|error| Error::InvalidBundle(error.to_string()))?;
    hashedrekord::verify(&value, artifact, submitter, trust).map_err(Error::Cryptographic)
}

/// Offline Sigstore verification failure.
#[derive(Debug, Error)]
pub enum Error {
    /// Input exceeded a hard resource bound.
    #[error("sigstore bundle exceeds {MAX_BUNDLE_BYTES} bytes")]
    TooLarge,
    /// JSON was malformed or used an unsupported representation.
    #[error("invalid Sigstore bundle: {0}")]
    InvalidBundle(String),
    /// The in-toto statement did not match policy.
    #[error("Sigstore policy mismatch: {0}")]
    Policy(String),
    /// Upstream cryptographic verification failed.
    #[error("Sigstore cryptographic verification failed: {0}")]
    Cryptographic(String),
    /// Sigstore's keys or TUF metadata failed verification.
    #[error("Sigstore trust verification failed: {0}")]
    Trust(String),
}

/// Verify one Sigstore v0.3 bundle without network access.
///
/// Validates Fulcio, Rekor, SCT, inclusion material, authenticated signing time and the artifact
/// signature, then requires the exact predicate type and artifact subjects. The repository, commit,
/// ref and GitHub-hosted runner come from the certificate, never from the workflow's predicate.
///
/// # Errors
///
/// Returns an error if parsing, cryptographic verification, or any pinned policy check fails.
pub fn verify_github_attestation(
    trust: &TrustedRoot,
    bundle_bytes: &[u8],
    expected_subjects: &[Subject<'_>],
    policy: &GithubPolicy,
) -> Result<VerifiedAttestation, Error> {
    verify_single_attestation(bundle_bytes, |value| {
        verify_github_attestation_value(trust, value, expected_subjects, policy)
    })
}

/// Verify the supported Sigstore v0.3 DSSE profile with exact identity and subjects.
///
/// This generic seam contains no Stogas release policy. Callers which need GitHub build claims
/// must apply their policy to the authenticated statement, as `verify_github_attestation` does.
///
/// # Errors
///
/// Returns an error for malformed, unsupported, untrusted, or policy-mismatched evidence.
pub fn verify_dsse_attestation(
    trust: &TrustedRoot,
    bundle_bytes: &[u8],
    expected_subjects: &[Subject<'_>],
    policy: &IdentityPolicy,
) -> Result<VerifiedAttestation, Error> {
    verify_single_attestation(bundle_bytes, |value| {
        verify_dsse_attestation_value(trust, value, expected_subjects, policy)
    })
}

fn verify_single_attestation(
    bundle_bytes: &[u8],
    mut verify: impl FnMut(&Value) -> Result<VerifiedAttestation, Error>,
) -> Result<VerifiedAttestation, Error> {
    if bundle_bytes.len() > MAX_BUNDLE_BYTES {
        return Err(Error::TooLarge);
    }
    let documents = parse_bundle_documents(bundle_bytes)?;
    let mut verified = None;
    let mut last_error = None;
    for value in documents {
        match verify(&value) {
            Ok(result) if verified.is_none() => verified = Some(result),
            Ok(_) => {
                return Err(Error::Policy(
                    "multiple attestations match the required subjects and policy".into(),
                ));
            }
            Err(error) => last_error = Some(error),
        }
    }
    verified.ok_or_else(|| {
        last_error.unwrap_or_else(|| Error::InvalidBundle("attestation input is empty".into()))
    })
}

fn verify_dsse_attestation_value(
    trust: &TrustedRoot,
    value: &Value,
    expected_subjects: &[Subject<'_>],
    policy: &IdentityPolicy,
) -> Result<VerifiedAttestation, Error> {
    verify_statement(
        trust,
        value,
        expected_subjects,
        &policy.predicate_type,
        &CertificatePolicy {
            identity: &policy.certificate_identity,
            issuer: &policy.certificate_oidc_issuer,
            extensions: &[],
        },
    )
}

fn verify_github_attestation_value(
    trust: &TrustedRoot,
    value: &Value,
    expected_subjects: &[Subject<'_>],
    policy: &GithubPolicy,
) -> Result<VerifiedAttestation, Error> {
    verify_statement(
        trust,
        value,
        expected_subjects,
        &policy.predicate_type,
        &CertificatePolicy {
            identity: &policy.workflow_identity,
            issuer: GITHUB_OIDC_ISSUER,
            extensions: &[
                (SOURCE_REPOSITORY_URI, &policy.repository),
                (SOURCE_REPOSITORY_DIGEST, &policy.source_commit),
                (SOURCE_REPOSITORY_REF, &policy.source_ref),
                (RUNNER_ENVIRONMENT, "github-hosted"),
            ],
        },
    )
}

fn verify_statement(
    trust: &TrustedRoot,
    value: &Value,
    expected_subjects: &[Subject<'_>],
    predicate_type: &str,
    certificate: &CertificatePolicy<'_>,
) -> Result<VerifiedAttestation, Error> {
    check_bundle_shape(value)?;
    let payload = decode_dsse_payload(value)?;
    let statement_value = strict_json::from_slice(&payload)
        .map_err(|error| Error::InvalidBundle(format!("invalid DSSE statement: {error}")))?;
    let statement: Statement = serde_json::from_value(statement_value)
        .map_err(|error| Error::InvalidBundle(format!("invalid DSSE statement: {error}")))?;
    check_subjects(&statement, expected_subjects)?;
    if statement.kind != "https://in-toto.io/Statement/v1"
        || statement.predicate_type != predicate_type
    {
        return Err(Error::Policy(
            "in-toto statement or predicate type differs".into(),
        ));
    }
    let integrated_time =
        sigstore::verify(trust, value, certificate).map_err(Error::Cryptographic)?;
    Ok(VerifiedAttestation {
        integrated_time,
        predicate_type: statement.predicate_type,
        subjects: statement
            .subject
            .into_iter()
            .map(|subject| (subject.name, subject.digest.sha256))
            .collect(),
    })
}

fn parse_bundle_documents(bundle_bytes: &[u8]) -> Result<Vec<Value>, Error> {
    match strict_json::from_slice(bundle_bytes) {
        Ok(value) => Ok(vec![value]),
        Err(single_error) => {
            let text = std::str::from_utf8(bundle_bytes)
                .map_err(|_| Error::InvalidBundle(single_error.to_string()))?;
            let lines: Vec<_> = text
                .lines()
                .filter(|line| !line.trim().is_empty())
                .collect();
            if lines.len() <= 1 || lines.len() > MAX_BUNDLES {
                return Err(Error::InvalidBundle(single_error.to_string()));
            }
            lines
                .into_iter()
                .map(|line| {
                    strict_json::from_slice(line.as_bytes())
                        .map_err(|error| Error::InvalidBundle(error.to_string()))
                })
                .collect()
        }
    }
}

fn decode_dsse_payload(value: &Value) -> Result<Vec<u8>, Error> {
    use base64::{Engine as _, engine::general_purpose::STANDARD};
    let payload = value
        .pointer("/dsseEnvelope/payload")
        .and_then(Value::as_str)
        .ok_or_else(|| Error::InvalidBundle("expected Sigstore v0.3 DSSE envelope".into()))?;
    STANDARD
        .decode(payload)
        .map_err(|error| Error::InvalidBundle(format!("invalid DSSE payload encoding: {error}")))
}

fn check_bundle_shape(value: &Value) -> Result<(), Error> {
    let media_type = value
        .get("mediaType")
        .and_then(Value::as_str)
        .ok_or_else(|| Error::InvalidBundle("missing Sigstore bundle media type".into()))?;
    if media_type != SIGSTORE_BUNDLE_MEDIA_TYPE {
        return Err(Error::InvalidBundle(format!(
            "unsupported Sigstore bundle media type: {media_type}"
        )));
    }

    let envelope = value
        .get("dsseEnvelope")
        .and_then(Value::as_object)
        .ok_or_else(|| Error::InvalidBundle("expected Sigstore v0.3 DSSE envelope".into()))?;
    if envelope.get("payloadType").and_then(Value::as_str) != Some(DSSE_PAYLOAD_TYPE) {
        return Err(Error::InvalidBundle("unsupported DSSE payload type".into()));
    }
    let signatures = envelope
        .get("signatures")
        .and_then(Value::as_array)
        .ok_or_else(|| Error::InvalidBundle("missing DSSE signatures".into()))?;
    if signatures.len() != 1 {
        return Err(Error::InvalidBundle(
            "GitHub profile requires exactly one DSSE signature".into(),
        ));
    }
    if signatures[0]
        .get("sig")
        .and_then(Value::as_str)
        .is_none_or(str::is_empty)
    {
        return Err(Error::InvalidBundle("empty DSSE signature".into()));
    }

    let log_entries = value
        .pointer("/verificationMaterial/tlogEntries")
        .and_then(Value::as_array)
        .ok_or_else(|| Error::InvalidBundle("missing Rekor entry".into()))?;
    if log_entries.len() != 1 {
        return Err(Error::InvalidBundle(
            "GitHub profile requires exactly one Rekor entry".into(),
        ));
    }
    Ok(())
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Statement {
    #[serde(rename = "_type")]
    kind: String,
    subject: Vec<StatementSubject>,
    #[serde(rename = "predicateType")]
    predicate_type: String,
    // Required but unread: whoever controls the workflow writes it.
    #[serde(rename = "predicate")]
    _predicate: Value,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct StatementSubject {
    name: String,
    digest: StatementDigest,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct StatementDigest {
    sha256: String,
}

fn check_subjects(statement: &Statement, expected_subjects: &[Subject<'_>]) -> Result<(), Error> {
    if expected_subjects.is_empty() || expected_subjects.len() > MAX_SUBJECTS {
        return Err(Error::Policy(format!(
            "expected subject count must be between 1 and {MAX_SUBJECTS}"
        )));
    }
    if statement.subject.len() != expected_subjects.len() {
        return Err(Error::Policy(
            "attestation contains missing or unexpected subjects".into(),
        ));
    }
    let mut expected_names = HashSet::new();
    for expected in expected_subjects {
        if expected.name.is_empty()
            || !expected_names.insert(expected.name)
            || expected.sha256.len() != 64
            || !expected
                .sha256
                .bytes()
                .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
        {
            return Err(Error::Policy(
                "expected subjects require unique names and lowercase SHA-256 digests".into(),
            ));
        }
    }
    let actual: HashMap<_, _> = statement
        .subject
        .iter()
        .map(|subject| (subject.name.as_str(), subject.digest.sha256.as_str()))
        .collect();
    if actual.len() != statement.subject.len() {
        return Err(Error::Policy(
            "attestation has duplicate subject names".into(),
        ));
    }
    for expected in expected_subjects {
        if actual.get(expected.name) != Some(&expected.sha256) {
            return Err(Error::Policy(format!(
                "expected exactly one subject {} with digest {}",
                expected.name, expected.sha256
            )));
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn policy() -> GithubPolicy {
        GithubPolicy {
            repository: "https://github.com/StogasAI/gateway".into(),
            workflow_identity: "https://github.com/StogasAI/gateway/.github/workflows/gateway-igvm-release.yml@refs/tags/v0.0.1".into(),
            source_ref: "refs/tags/v0.0.1".into(),
            source_commit: "27eb4b954a372975c9e7c5dbc77fbf0d0ca53b3f".into(),
            predicate_type: "https://slsa.dev/provenance/v1".into(),
        }
    }

    fn statement(subject: Vec<StatementSubject>) -> Statement {
        Statement {
            kind: "https://in-toto.io/Statement/v1".into(),
            subject,
            predicate_type: "https://slsa.dev/provenance/v1".into(),
            _predicate: json!({}),
        }
    }

    fn subject(name: &str, digest: &str) -> StatementSubject {
        StatementSubject {
            name: name.into(),
            digest: StatementDigest {
                sha256: digest.into(),
            },
        }
    }

    #[test]
    fn rejects_oversized_input_before_parsing() {
        let bytes = vec![b' '; MAX_BUNDLE_BYTES + 1];
        assert!(matches!(
            verify_github_attestation(TrustedRoot::production(), &bytes, &[], &policy()),
            Err(Error::TooLarge)
        ));
    }

    #[test]
    fn rejects_duplicate_json_keys() {
        let error =
            strict_json::from_slice(br#"{"mediaType":"first","mediaType":"second"}"#).unwrap_err();
        assert!(error.to_string().contains("duplicate JSON key: mediaType"));
    }

    #[test]
    fn parses_github_json_and_jsonl_without_weakening_strict_json() {
        assert_eq!(parse_bundle_documents(br#"{"one":1}"#).unwrap().len(), 1);
        assert_eq!(
            parse_bundle_documents(b"{\"one\":1}\n\n{\"two\":2}\n")
                .unwrap()
                .len(),
            2
        );
        assert!(parse_bundle_documents(b"{\"one\":1}\nnot-json").is_err());
    }

    #[test]
    fn rejects_extra_or_duplicate_subjects() {
        const DIGEST: &str = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
        let expected = [Subject {
            name: "gateway.igvm",
            sha256: DIGEST,
        }];
        let extra = statement(vec![
            subject("gateway.igvm", DIGEST),
            subject("unexpected", DIGEST),
        ]);
        assert!(matches!(
            check_subjects(&extra, &expected),
            Err(Error::Policy(message)) if message.contains("unexpected subjects")
        ));

        let duplicate = statement(vec![
            subject("gateway.igvm", DIGEST),
            subject("gateway.igvm", DIGEST),
        ]);
        let duplicate_expected = [
            Subject {
                name: "gateway.igvm",
                sha256: DIGEST,
            },
            Subject {
                name: "gateway.igvm",
                sha256: DIGEST,
            },
        ];
        assert!(matches!(
            check_subjects(&duplicate, &duplicate_expected),
            Err(Error::Policy(message)) if message.contains("unique names")
        ));
    }

    #[test]
    fn accepts_only_the_exact_github_subject_set() {
        const IGVM: &str = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
        const MANIFEST: &str = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";
        let statement = statement(vec![
            subject("gateway.igvm", IGVM),
            subject("release-manifest.json", MANIFEST),
        ]);
        check_subjects(
            &statement,
            &[
                Subject {
                    name: "gateway.igvm",
                    sha256: IGVM,
                },
                Subject {
                    name: "release-manifest.json",
                    sha256: MANIFEST,
                },
            ],
        )
        .unwrap();
    }

    #[test]
    fn rejects_ambiguous_sigstore_bundle_shape() {
        let mut bundle = json!({
            "mediaType": SIGSTORE_BUNDLE_MEDIA_TYPE,
            "dsseEnvelope": {
                "payload": "e30=",
                "payloadType": DSSE_PAYLOAD_TYPE,
                "signatures": [{ "sig": "AA==" }]
            },
            "verificationMaterial": {
                "tlogEntries": [{}]
            }
        });
        check_bundle_shape(&bundle).unwrap();
        bundle["dsseEnvelope"]["signatures"] = json!([{ "sig": "AA==" }, { "sig": "AA==" }]);
        assert!(matches!(
            check_bundle_shape(&bundle),
            Err(Error::InvalidBundle(message)) if message.contains("exactly one DSSE signature")
        ));
    }
}

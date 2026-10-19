//! SDK release signatures under the normal Stogas root hierarchy.

use serde::{Deserialize, Serialize};
use serde_json::Value;
use sha2::{Digest as _, Sha256};
use stogas_sigstore::{GithubPolicy, Subject, TrustedRoot, verify_github_attestation};

use crate::{
    MAX_INPUT_BYTES, StogasSignature,
    approvals::{self, ApprovalVerifier, Environment, SignedKeyManifest},
    strict_json,
};

const REPOSITORY: &str = "https://github.com/StogasAI/stogas";
pub const MANIFEST: &str = "release-manifest.json";
pub const ATTESTATION: &str = "github-attestation.jsonl";
pub const SIGNATURE: &str = "stogas-signature.json";
pub const QUALIFICATION: &str = "qualification.json";
/// The release files besides its artifacts; no artifact may share these names.
pub const METADATA: [&str; 4] = [MANIFEST, ATTESTATION, SIGNATURE, QUALIFICATION];

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Source {
    pub commit: String,
    pub sha256: String,
    pub dirty: bool,
    pub epoch: u64,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Artifact {
    pub name: String,
    pub sha256: String,
    pub size: u64,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Manifest {
    pub schema: String,
    pub environment: Environment,
    pub version: String,
    pub source: Source,
    pub targets: Vec<String>,
    pub artifacts: Vec<Artifact>,
}

/// The online key's signature over GitHub's unchanged manifest, logged in Rekor.
/// Stogas signs only after its own build matched GitHub's bytes and every test passed.
#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Signature {
    pub keys: SignedKeyManifest,
    pub signature: StogasSignature,
    pub inclusion: Value,
}

/// Verify GitHub's build proof and the Stogas signature of a production SDK release.
///
/// GitHub's one proof names every artifact, the manifest and the test report, so it exists
/// only for files that passed every test in the same workflow run. This authenticates
/// historical publication, without granting current gateway authority. The caller must also
/// compare artifact bytes with the returned manifest.
///
/// # Errors
/// Rejects unsigned, altered, staging or dirty releases and signing keys that had expired
/// when Rekor logged the signature. A later key expiry does not invalidate old software.
pub fn verify(
    manifest_bytes: &[u8],
    github_attestation: &[u8],
    qualification: &[u8],
    signature_bytes: &[u8],
    now_unix_ms: i64,
) -> Result<Manifest, approvals::Error> {
    if [
        manifest_bytes.len(),
        github_attestation.len(),
        qualification.len(),
        signature_bytes.len(),
    ]
    .into_iter()
    .any(|length| length > MAX_INPUT_BYTES)
    {
        return Err(approvals::Error::TooLarge);
    }
    let manifest: Manifest =
        serde_json::from_value(strict_json::from_slice(manifest_bytes).map_err(invalid)?)
            .map_err(invalid)?;
    validate_manifest(&manifest)?;
    let signed: Signature =
        serde_json::from_value(strict_json::from_slice(signature_bytes).map_err(invalid)?)
            .map_err(invalid)?;
    let document = serde_json::to_value(&manifest).map_err(invalid)?;
    // Without current evidence, the Sigstore keys compiled into this release check its successors.
    let trust =
        TrustedRoot::embedded().map_err(|error| approvals::Error::Sigstore(error.to_string()))?;
    let published = approvals::verify_document_inclusion(
        &document,
        &signed.signature,
        &signed.inclusion,
        trust,
        now_unix_ms,
    )?;
    let published_ms = published
        .checked_mul(1000)
        .ok_or_else(|| invalid("log time overflow"))?;
    let authority = ApprovalVerifier::new(
        Environment::Production,
        Environment::Production.stogas_root()?,
    )?;
    let keys = authority.verify_key_manifest(
        &serde_json::to_vec(&signed.keys).map_err(invalid)?,
        trust,
        published_ms,
    )?;
    approvals::verify_signature(
        &document,
        &signed.signature,
        &keys.active_key.key_id,
        &keys.active_key.public_key,
    )?;
    let reference = format!("refs/tags/v{}", manifest.version);
    let manifest_sha256 = hex::encode(Sha256::digest(manifest_bytes));
    let qualification_sha256 = hex::encode(Sha256::digest(qualification));
    let subjects: Vec<_> = manifest
        .artifacts
        .iter()
        .map(|artifact| Subject {
            name: &artifact.name,
            sha256: &artifact.sha256,
        })
        .chain([
            Subject {
                name: MANIFEST,
                sha256: &manifest_sha256,
            },
            Subject {
                name: QUALIFICATION,
                sha256: &qualification_sha256,
            },
        ])
        .collect();
    verify_github_attestation(
        trust,
        github_attestation,
        &subjects,
        &GithubPolicy {
            repository: REPOSITORY.into(),
            workflow_identity: format!("{REPOSITORY}/.github/workflows/release.yml@{reference}"),
            source_ref: reference,
            source_commit: manifest.source.commit.clone(),
            predicate_type: "https://slsa.dev/provenance/v1".into(),
        },
        now_unix_ms,
    )
    .map_err(invalid)?;
    Ok(manifest)
}

fn validate_manifest(manifest: &Manifest) -> Result<(), approvals::Error> {
    if manifest.schema != "stogas.sdk-release.v1"
        || manifest.environment != Environment::Production
        || manifest.source.dirty
        || !hex_digest(&manifest.source.commit, 40)
        || !sha256(&manifest.source.sha256)
        || manifest.source.epoch > 0xffff_ffff
        || !safe_name(&manifest.version)
        || manifest.artifacts.is_empty()
        || manifest.targets.is_empty()
        || manifest.targets.iter().any(|target| !safe_name(target))
        || manifest.targets.windows(2).any(|pair| pair[0] >= pair[1])
        || manifest
            .artifacts
            .windows(2)
            .any(|pair| pair[0].name >= pair[1].name)
        || manifest.artifacts.iter().any(|artifact| {
            !safe_name(&artifact.name)
                || METADATA.contains(&artifact.name.as_str())
                || !sha256(&artifact.sha256)
                || artifact.size == 0
                || artifact.size > 2 * 1024 * 1024 * 1024
        })
    {
        return Err(invalid("invalid production SDK release manifest"));
    }
    Ok(())
}

fn safe_name(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 200
        && value.as_bytes()[0].is_ascii_alphanumeric()
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || b"._+-".contains(&byte))
}

fn sha256(value: &str) -> bool {
    hex_digest(value, 64)
}

fn hex_digest(value: &str, length: usize) -> bool {
    value.len() == length
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

fn invalid(error: impl std::fmt::Display) -> approvals::Error {
    approvals::Error::Invalid(error.to_string())
}

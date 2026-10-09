//! Historical SDK release authorization under the normal Stogas root hierarchy.

use serde::{Deserialize, Serialize};
use sha2::{Digest as _, Sha256};
use stogas_offline_sigstore::{GithubPolicy, Subject, verify_github_attestation};

use crate::{
    LoggedDocument, MAX_INPUT_BYTES,
    approvals::{self, ApprovalVerifier, Environment, SignedKeyManifest},
    strict_json,
};

const REPOSITORY: &str = "https://github.com/StogasAI/verifier";

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

/// The online signer binds the GitHub build, independent rebuild and complete test report.
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Approval {
    pub schema: String,
    pub environment: Environment,
    /// Identity of the canonical unsigned manifest, without a trailing newline.
    pub manifest_sha256: String,
    pub key_manifest_sha256: String,
    pub github_attestation_sha256: String,
    pub qualification_sha256: String,
    pub rebuild_sha256: String,
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Proof {
    pub keys: SignedKeyManifest,
    pub approval: LoggedDocument<Approval>,
}

/// Verify immutable release authorization, including the exact GitHub build identity.
///
/// This authenticates historical publication, without granting current gateway authority.
/// The caller must also compare artifact and report bytes with their authenticated hashes.
///
/// # Errors
/// Rejects unsigned, incomplete, altered, staging or dirty releases and expired signing authority
/// at the authenticated publication time. A later key expiry does not invalidate old software.
pub fn verify(
    manifest_bytes: &[u8],
    github_attestation: &[u8],
    proof_bytes: &[u8],
    now_unix_ms: i64,
) -> Result<Approval, approvals::Error> {
    if [
        manifest_bytes.len(),
        github_attestation.len(),
        proof_bytes.len(),
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
    let proof: Proof =
        serde_json::from_value(strict_json::from_slice(proof_bytes).map_err(invalid)?)
            .map_err(invalid)?;
    let approval = &proof.approval.document;
    if approval.schema != "stogas.sdk-release-approval.v1"
        || approval.environment != Environment::Production
        || approval.manifest_sha256 != approvals::payload_sha256(&manifest)?
        || approval.key_manifest_sha256 != approvals::payload_sha256(&proof.keys.document)?
        || approval.github_attestation_sha256 != hex::encode(Sha256::digest(github_attestation))
        || !sha256(&approval.qualification_sha256)
        || !sha256(&approval.rebuild_sha256)
    {
        return Err(invalid(
            "SDK approval does not bind this production release",
        ));
    }
    let document = serde_json::to_value(approval).map_err(invalid)?;
    let published = approvals::verify_document_inclusion(
        &document,
        &proof.approval.signature,
        &proof.approval.inclusion,
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
        &serde_json::to_vec(&proof.keys).map_err(invalid)?,
        published_ms,
    )?;
    approvals::verify_signature(
        &document,
        &proof.approval.signature,
        &keys.active_key.key_id,
        &keys.active_key.public_key,
    )?;
    let reference = format!("refs/tags/v{}", manifest.version);
    let github = verify_github_attestation(
        github_attestation,
        &[Subject {
            name: "release-manifest.json",
            sha256: &hex::encode(Sha256::digest(manifest_bytes)),
        }],
        &GithubPolicy {
            repository: REPOSITORY.into(),
            workflow_identity: format!("{REPOSITORY}/.github/workflows/release.yml@{reference}"),
            source_ref: reference,
            source_commit: manifest.source.commit,
            predicate_type: "https://slsa.dev/provenance/v1".into(),
            require_github_hosted: true,
        },
        now_unix_ms,
    )
    .map_err(invalid)?;
    if github.integrated_time > published {
        return Err(invalid("SDK approval precedes the GitHub build proof"));
    }
    Ok(proof.approval.document)
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

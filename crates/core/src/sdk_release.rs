//! SDK release signatures under the normal Stogas root hierarchy.

use serde::{Deserialize, Serialize};
use serde_json::Value;
use sha2::{Digest as _, Sha256};
use stogas_sigstore::{GithubPolicy, Subject, verify_github_attestation};

use crate::{
    MAX_INPUT_BYTES, StogasSignature,
    authority::{self, Authority, Environment, SignedKeyManifest, VerifiedSigstore},
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
/// compare artifact bytes with the returned manifest. Sigstore keeps a replaced key with its
/// validity ended, so current Sigstore keys also verify older releases.
///
/// # Errors
/// Rejects unsigned, altered, staging or dirty releases, and signing keys that a key manifest
/// had not yet authorized, or no longer authorized, when Rekor logged the signature. A later
/// key expiry does not invalidate old software.
pub fn verify(
    manifest_bytes: &[u8],
    github_attestation: &[u8],
    qualification: &[u8],
    signature_bytes: &[u8],
    sigstore: &VerifiedSigstore,
) -> Result<Manifest, authority::Error> {
    if [
        manifest_bytes.len(),
        github_attestation.len(),
        qualification.len(),
        signature_bytes.len(),
    ]
    .into_iter()
    .any(|length| length > MAX_INPUT_BYTES)
    {
        return Err(authority::Error::TooLarge);
    }
    let manifest: Manifest =
        serde_json::from_value(strict_json::from_slice(manifest_bytes).map_err(invalid)?)
            .map_err(invalid)?;
    validate_manifest(&manifest)?;
    let signed: Signature =
        serde_json::from_value(strict_json::from_slice(signature_bytes).map_err(invalid)?)
            .map_err(invalid)?;
    let document = serde_json::to_value(&manifest).map_err(invalid)?;
    let trust = sigstore.trusted_root();
    // The root signature over this key manifest, checked next, authenticates its Rekor key.
    let published = authority::verify_document_inclusion(
        &document,
        &signed.signature,
        &signed.inclusion,
        trust,
        &signed.keys.document.active_key.rekor_public_key,
    )?;
    let authority = Authority::new(
        Environment::Production,
        Environment::Production.stogas_root()?,
    )?;
    let keys = authority.verify_key_manifest_at(
        &serde_json::to_vec(&signed.keys).map_err(invalid)?,
        trust,
        published,
    )?;
    authority::verify_signature(
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
    )
    .map_err(invalid)?;
    Ok(manifest)
}

fn validate_manifest(manifest: &Manifest) -> Result<(), authority::Error> {
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

fn invalid(error: impl std::fmt::Display) -> authority::Error {
    authority::Error::Invalid(error.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn manifest() -> Value {
        json!({
            "schema": "stogas.sdk-release.v1",
            "environment": "prod",
            "version": "0.1.0",
            "source": {
                "commit": "0123456789abcdef0123456789abcdef01234567",
                "sha256": "ab".repeat(32),
                "dirty": false,
                "epoch": 1_761_696_000,
            },
            "targets": ["linux-amd64", "windows-amd64"],
            "artifacts": [
                { "name": "stogas-0.1.0.crate", "sha256": "cd".repeat(32), "size": 1 },
                { "name": "stogas_cli-0.1.0-linux-amd64.tar.gz", "sha256": "ef".repeat(32), "size": 2 },
            ],
        })
    }

    fn parse(value: &Value) -> Manifest {
        serde_json::from_value(value.clone()).unwrap()
    }

    #[test]
    fn accepts_a_well_formed_production_manifest() {
        validate_manifest(&parse(&manifest())).unwrap();
    }

    #[test]
    fn rejects_each_malformed_manifest_field() {
        let cases = [
            ("/schema", json!("stogas.sdk-release.v2")),
            ("/source/dirty", json!(true)),
            (
                "/source/commit",
                json!("0123456789ABCDEF0123456789abcdef01234567"),
            ),
            ("/source/commit", json!("0123456789abcdef")),
            ("/source/sha256", json!("ab".repeat(31))),
            ("/source/epoch", json!(0x1_0000_0000_u64)),
            ("/version", json!("")),
            ("/version", json!("../0.1.0")),
            ("/targets", json!([])),
            ("/targets", json!(["windows-amd64", "linux-amd64"])),
            ("/targets", json!(["linux-amd64", "linux-amd64"])),
            ("/targets/0", json!("linux amd64")),
            ("/artifacts", json!([])),
            ("/artifacts/1/name", json!("stogas-0.1.0.crate")),
            // A release file may not pose as an artifact.
            ("/artifacts/0/name", json!(MANIFEST)),
            ("/artifacts/0/name", json!(".stogas-0.1.0.crate")),
            ("/artifacts/0/sha256", json!("CD".repeat(32))),
            ("/artifacts/0/size", json!(0)),
            ("/artifacts/0/size", json!(2_u64 * 1024 * 1024 * 1024 + 1)),
        ];
        for (pointer, replacement) in cases {
            let mut value = manifest();
            *value.pointer_mut(pointer).unwrap() = replacement.clone();
            assert!(
                validate_manifest(&parse(&value)).is_err(),
                "{pointer} = {replacement} was accepted"
            );
        }
    }

    #[test]
    fn refuses_oversized_unknown_and_staging_releases_before_any_signature() {
        let sigstore = &authority::sigstore_fixture().1;
        let oversized = vec![b' '; MAX_INPUT_BYTES + 1];
        for inputs in [
            [oversized.as_slice(), b"", b"", b""],
            [b"", oversized.as_slice(), b"", b""],
            [b"", b"", oversized.as_slice(), b""],
            [b"", b"", b"", oversized.as_slice()],
        ] {
            assert!(matches!(
                verify(inputs[0], inputs[1], inputs[2], inputs[3], sigstore),
                Err(authority::Error::TooLarge)
            ));
        }
        let mut unknown = manifest();
        unknown["notes"] = json!("unsigned");
        let mut staging = manifest();
        staging["environment"] = json!("staging");
        for value in [unknown, staging] {
            let bytes = serde_json::to_vec(&value).unwrap();
            assert!(matches!(
                verify(&bytes, b"", b"", b"{}", sigstore),
                Err(authority::Error::Invalid(_))
            ));
        }
    }
}

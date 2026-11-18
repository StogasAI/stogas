//! SDK release signatures under the normal Stogas root hierarchy.

use std::cmp::Ordering;

use serde::{Deserialize, Serialize};
use serde_json::Value;
use sha2::{Digest as _, Sha256};
use stogas_sigstore::{BuildPolicy, Subject, verify_build_attestation};

use crate::{
    MAX_INPUT_BYTES, StogasSignature,
    authority::{self, Authority, Environment, SignedKeyManifest, VerifiedSigstore},
    format, strict_json,
};

const REPOSITORY: &str = "https://github.com/StogasAI/stogas";
/// The GitLab.com mirror whose hosted runners rebuild each release.
const GITLAB_REPOSITORY: &str = "https://gitlab.com/stogasai/stogas";
/// The first release that GitLab rebuilt: it and every later release must carry GitLab's proof.
const FIRST_GITLAB_VERSION: &str = "0.1.0-alpha.6";
pub const SCHEMA: &str = "stogas.sdk-release.v1";
pub const MANIFEST: &str = "release-manifest.json";
pub const ATTESTATION: &str = "github-attestation.jsonl";
pub const GITLAB_ATTESTATION: &str = "gitlab-attestation.jsonl";
pub const SIGNATURE: &str = "stogas-signature.json";
pub const QUALIFICATION: &str = "qualification.json";
/// The release files besides its artifacts; no artifact may share these names.
pub const METADATA: [&str; 5] = [
    MANIFEST,
    ATTESTATION,
    GITLAB_ATTESTATION,
    SIGNATURE,
    QUALIFICATION,
];

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
///
/// Stogas signs only after every test passed and GitLab's rebuild matched GitHub's bytes; before
/// GitLab rebuilt releases, Stogas rebuilt them itself.
#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Signature {
    pub keys: SignedKeyManifest,
    pub signature: StogasSignature,
    pub inclusion: Value,
}

/// Verify the Stogas signature and both build proofs of a production SDK release, as
/// [`verify_builds`] does.
///
/// This authenticates historical publication, without granting current gateway authority. The
/// caller must also compare artifact bytes with the returned manifest. Sigstore keeps a replaced key
/// with its validity ended, so current Sigstore keys also verify older releases.
///
/// # Errors
/// Rejects what [`verify_builds`] rejects, unsigned releases, and signing keys that a key manifest
/// had not yet authorized, or no longer authorized, when Rekor logged the signature. A later key
/// expiry does not invalidate old software.
pub fn verify(
    manifest_bytes: &[u8],
    github_attestation: &[u8],
    gitlab_attestation: Option<&[u8]>,
    qualification: &[u8],
    signature_bytes: &[u8],
    sigstore: &VerifiedSigstore,
) -> Result<Manifest, authority::Error> {
    if signature_bytes.len() > MAX_INPUT_BYTES {
        return Err(authority::Error::TooLarge);
    }
    let manifest = verify_builds(
        manifest_bytes,
        github_attestation,
        gitlab_attestation,
        qualification,
        sigstore,
    )?;
    let signed: Signature =
        serde_json::from_value(strict_json::from_slice(signature_bytes).map_err(invalid)?)
            .map_err(invalid)?;
    let document = serde_json::to_value(&manifest).map_err(invalid)?;
    let trust = sigstore.trusted_root();
    let authority = Authority::new(
        Environment::Production,
        Environment::Production.stogas_root()?,
    )?;
    // The root signature over this key manifest, checked next, authenticates its Rekor key.
    let published = authority::verify_document_inclusion(
        &document,
        &signed.signature,
        &signed.inclusion,
        trust,
        &signed.keys.document.active_key.rekor_public_key,
        authority.rekor_v2(),
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
    Ok(manifest)
}

/// Verify the build proofs of GitHub and GitLab for a production SDK release, which Stogas does
/// before it signs one.
///
/// GitHub's one proof names every artifact, the manifest and the test report, so it exists only
/// for files that passed every test in the same workflow run. GitLab's proof names every artifact
/// and the manifest again: GitLab's hosted runners rebuilt them from the same commit and made the
/// same bytes, with only the Apple compiler outputs taken from GitHub's build, as its predicate
/// lists. Releases before [`FIRST_GITLAB_VERSION`] have no GitLab proof.
///
/// # Errors
/// Rejects altered, staging or dirty releases, a proof from another builder, repository, commit or
/// tag, and a release from 0.1.0-alpha.6 on without GitLab's proof.
pub fn verify_builds(
    manifest_bytes: &[u8],
    github_attestation: &[u8],
    gitlab_attestation: Option<&[u8]>,
    qualification: &[u8],
    sigstore: &VerifiedSigstore,
) -> Result<Manifest, authority::Error> {
    if [
        manifest_bytes.len(),
        github_attestation.len(),
        gitlab_attestation.map_or(0, <[u8]>::len),
        qualification.len(),
    ]
    .into_iter()
    .any(|length| length > MAX_INPUT_BYTES)
    {
        return Err(authority::Error::TooLarge);
    }
    let manifest = strict_json::from_slice(manifest_bytes).map_err(invalid)?;
    format::check(&manifest, SCHEMA)?;
    let manifest: Manifest = serde_json::from_value(manifest).map_err(invalid)?;
    validate_manifest(&manifest)?;
    let trust = sigstore.trusted_root();
    let reference = format!("refs/tags/v{}", manifest.version);
    let manifest_sha256 = hex::encode(Sha256::digest(manifest_bytes));
    let qualification_sha256 = hex::encode(Sha256::digest(qualification));
    // GitLab builds and tests nothing else, so its proof names the files without the test report.
    let mut subjects: Vec<_> = manifest
        .artifacts
        .iter()
        .map(|artifact| Subject {
            name: &artifact.name,
            sha256: &artifact.sha256,
        })
        .chain([Subject {
            name: MANIFEST,
            sha256: &manifest_sha256,
        }])
        .collect();
    let built = |repository: &str, workflow_identity: String| BuildPolicy {
        repository: repository.into(),
        workflow_identity,
        source_ref: reference.clone(),
        source_commit: manifest.source.commit.clone(),
        predicate_type: "https://slsa.dev/provenance/v1".into(),
    };
    match gitlab_attestation {
        Some(bundle) => {
            verify_build_attestation(
                trust,
                bundle,
                &subjects,
                &built(
                    GITLAB_REPOSITORY,
                    format!("{GITLAB_REPOSITORY}//.gitlab-ci.yml@{reference}"),
                ),
            )
            .map_err(invalid)?;
        }
        None if gitlab_required(&manifest.version) => {
            return Err(invalid(format!(
                "SDK {} has no GitLab build proof",
                manifest.version
            )));
        }
        None => {}
    }
    subjects.push(Subject {
        name: QUALIFICATION,
        sha256: &qualification_sha256,
    });
    verify_build_attestation(
        trust,
        github_attestation,
        &subjects,
        &built(
            REPOSITORY,
            format!("{REPOSITORY}/.github/workflows/release.yml@{reference}"),
        ),
    )
    .map_err(invalid)?;
    Ok(manifest)
}

/// Whether a release must carry GitLab's proof: every version from [`FIRST_GITLAB_VERSION`] on,
/// and any version that is not Semantic Versioning, which the release gate never produces.
fn gitlab_required(version: &str) -> bool {
    precedence(version, FIRST_GITLAB_VERSION).is_none_or(Ordering::is_ge)
}

/// Semantic Versioning 2.0 precedence: build metadata is ignored, a pre-release precedes its
/// release, and numeric identifiers compare as numbers and precede alphanumeric ones.
fn precedence(left: &str, right: &str) -> Option<Ordering> {
    fn parts(version: &str) -> Option<([u64; 3], Vec<&str>)> {
        let version = version.split('+').next()?;
        let (core, pre) = match version.split_once('-') {
            Some((core, pre)) => (core, pre.split('.').collect()),
            None => (version, Vec::new()),
        };
        let mut numbers = core.split('.').map(|number| {
            (!number.is_empty() && (number == "0" || !number.starts_with('0')))
                .then(|| number.parse::<u64>().ok())
                .flatten()
        });
        let core = [numbers.next()??, numbers.next()??, numbers.next()??];
        (numbers.next().is_none() && pre.iter().all(|part| !part.is_empty())).then_some((core, pre))
    }
    let (left_core, left_pre) = parts(left)?;
    let (right_core, right_pre) = parts(right)?;
    Some(left_core.cmp(&right_core).then_with(|| {
        match (left_pre.is_empty(), right_pre.is_empty()) {
            (true, true) => Ordering::Equal,
            (true, false) => Ordering::Greater,
            (false, true) => Ordering::Less,
            (false, false) => left_pre
                .iter()
                .zip(&right_pre)
                .map(
                    |(left, right)| match (left.parse::<u64>(), right.parse::<u64>()) {
                        (Ok(left), Ok(right)) => left.cmp(&right),
                        (Ok(_), Err(_)) => Ordering::Less,
                        (Err(_), Ok(_)) => Ordering::Greater,
                        (Err(_), Err(_)) => left.cmp(right),
                    },
                )
                .find(|order| order.is_ne())
                .unwrap_or_else(|| left_pre.len().cmp(&right_pre.len())),
        }
    }))
}

fn validate_manifest(manifest: &Manifest) -> Result<(), authority::Error> {
    if manifest.schema != SCHEMA
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
    fn a_manifest_in_another_version_of_its_format_is_newer() {
        let mut newer = manifest();
        newer["schema"] = json!("stogas.sdk-release.v2");
        newer["notes"] = json!("a field that version 1 does not have");
        let sigstore = &crate::authority::sigstore_fixture().1;
        let error = verify(
            &serde_json::to_vec(&newer).unwrap(),
            b"",
            None,
            b"",
            b"",
            sigstore,
        );
        assert!(matches!(error, Err(authority::Error::Format(error)) if error.newer));
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
            [oversized.as_slice(), b"", b"", b"", b""],
            [b"", oversized.as_slice(), b"", b"", b""],
            [b"", b"", oversized.as_slice(), b"", b""],
            [b"", b"", b"", oversized.as_slice(), b""],
            [b"", b"", b"", b"", oversized.as_slice()],
        ] {
            assert!(matches!(
                verify(
                    inputs[0],
                    inputs[1],
                    Some(inputs[2]),
                    inputs[3],
                    inputs[4],
                    sigstore
                ),
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
                verify(&bytes, b"", None, b"", b"{}", sigstore),
                Err(authority::Error::Invalid(_))
            ));
        }
    }

    #[test]
    fn orders_versions_by_semantic_versioning_precedence() {
        // The order that Semantic Versioning 2.0 gives as its example, and numeric fields.
        let ordered = [
            "0.1.0-alpha.5",
            "0.1.0-alpha.6",
            "0.1.0-alpha.10",
            "1.0.0-alpha",
            "1.0.0-alpha.1",
            "1.0.0-alpha.beta",
            "1.0.0-beta",
            "1.0.0-beta.2",
            "1.0.0-beta.11",
            "1.0.0-rc.1",
            "1.0.0",
            "1.0.1",
            "1.2.0",
            "1.10.0",
            "10.0.0",
        ];
        for (index, left) in ordered.iter().enumerate() {
            for (other, right) in ordered.iter().enumerate() {
                assert_eq!(
                    precedence(left, right),
                    Some(index.cmp(&other)),
                    "{left} against {right}"
                );
            }
        }
        assert_eq!(precedence("1.0.0+build.1", "1.0.0"), Some(Ordering::Equal));
        for invalid in [
            "1.0",
            "1.0.0.0",
            "01.0.0",
            "1.0.0-",
            "1.0.0-alpha..1",
            "v1.0.0",
            "",
        ] {
            assert_eq!(precedence(invalid, "1.0.0"), None, "{invalid}");
        }
    }

    #[test]
    fn requires_gitlab_from_its_first_release_and_for_unknown_versions() {
        for version in ["0.1.0-alpha.1", "0.1.0-alpha.5"] {
            assert!(!gitlab_required(version), "{version}");
        }
        for version in [
            "0.1.0-alpha.6",
            "0.1.0-alpha.10",
            "0.1.0-beta",
            "0.1.0",
            "1.0.0",
            "1.0",
        ] {
            assert!(gitlab_required(version), "{version}");
        }
    }
}

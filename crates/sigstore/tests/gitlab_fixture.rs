//! A build proof that a GitLab.com hosted runner signed with cosign 3.1.4 on November 18, 2026:
//! a Rekor v1 DSSE entry and an RFC 3161 timestamp, the form that cosign takes from Sigstore's
//! signing configuration.
use serde_json::Value;
use sha2::{Digest, Sha256};
use stogas_sigstore::{BuildPolicy, Subject, verify_build_attestation};

const BUNDLE: &[u8] = include_bytes!("../../../tests/fixtures/gitlab-smoke-attestation.jsonl");
const PROBE_DIGEST: &str = "a7ee3efe2a79ce827100f526e16979b4e00115a5d58e98a9ac7a99f88952e364";
const MANIFEST_DIGEST: &str = "3bc693e58109924b7b236a462a0c91772f0a9c0f58a865cbc03ccf3656266d30";

fn production() -> &'static stogas_sigstore::TrustedRoot {
    static ROOT: std::sync::LazyLock<stogas_sigstore::TrustedRoot> =
        std::sync::LazyLock::new(|| {
            stogas_sigstore::TrustedRoot::from_json(include_str!(
                "../../../tests/fixtures/sigstore-tuf/trusted_root.json"
            ))
            .unwrap()
        });
    &ROOT
}

fn policy() -> BuildPolicy {
    BuildPolicy {
        repository: "https://gitlab.com/stogasai/stogas".into(),
        workflow_identity:
            "https://gitlab.com/stogasai/stogas//.gitlab-ci.yml@refs/tags/v0.0.0-smoke.1".into(),
        source_ref: "refs/tags/v0.0.0-smoke.1".into(),
        source_commit: "18e55c517c7c7a6bc51792bd396c73cf54e39221".into(),
        predicate_type: "https://slsa.dev/provenance/v1".into(),
    }
}

const fn subjects() -> [Subject<'static>; 2] {
    [
        Subject {
            name: "probe.txt",
            sha256: PROBE_DIGEST,
        },
        Subject {
            name: "release-manifest.json",
            sha256: MANIFEST_DIGEST,
        },
    ]
}

#[test]
fn verifies_real_gitlab_build_attestation() {
    let manifest = include_bytes!("../../../tests/fixtures/gitlab-smoke-release-manifest.json");
    assert_eq!(hex::encode(Sha256::digest(manifest)), MANIFEST_DIGEST);
    let result = verify_build_attestation(production(), BUNDLE, &subjects(), &policy()).unwrap();
    assert_eq!(
        result.predicate["buildDefinition"]["externalParameters"]["ref"],
        "refs/tags/v0.0.0-smoke.1"
    );
}

#[test]
fn rejects_each_gitlab_identity_mismatch_and_a_github_policy() {
    let policies = [
        BuildPolicy {
            repository: "https://gitlab.com/stogasai/gateway".into(),
            ..policy()
        },
        // The same path on GitHub needs GitHub's OIDC issuer and hosted runner.
        BuildPolicy {
            repository: "https://github.com/stogasai/stogas".into(),
            ..policy()
        },
        BuildPolicy {
            workflow_identity:
                "https://gitlab.com/stogasai/stogas//ci/other.yml@refs/tags/v0.0.0-smoke.1".into(),
            ..policy()
        },
        BuildPolicy {
            source_ref: "refs/tags/v0.0.0-smoke.2".into(),
            ..policy()
        },
        BuildPolicy {
            source_commit: "0000000000000000000000000000000000000000".into(),
            ..policy()
        },
        BuildPolicy {
            predicate_type: "https://example.invalid/predicate".into(),
            ..policy()
        },
    ];
    for changed_policy in policies {
        assert!(
            verify_build_attestation(production(), BUNDLE, &subjects(), &changed_policy).is_err(),
            "{changed_policy:?} was accepted"
        );
    }
}

#[test]
fn rejects_a_changed_timestamp_or_subject() {
    let mut value: Value = serde_json::from_slice(BUNDLE).unwrap();
    let pointer =
        "/verificationMaterial/timestampVerificationData/rfc3161Timestamps/0/signedTimestamp";
    let timestamp = value.pointer(pointer).and_then(Value::as_str).unwrap();
    let mut changed = timestamp.to_owned();
    changed.replace_range(..1, if timestamp.starts_with('A') { "B" } else { "A" });
    *value.pointer_mut(pointer).unwrap() = Value::String(changed);
    let bytes = serde_json::to_vec(&value).unwrap();
    assert!(verify_build_attestation(production(), &bytes, &subjects(), &policy()).is_err());

    let [probe, _] = subjects();
    assert!(verify_build_attestation(production(), BUNDLE, &[probe], &policy()).is_err());
}

#![cfg(not(target_arch = "wasm32"))]

use serde_json::Value;
use sigstore_trust_root::{SIGSTORE_PRODUCTION_TRUSTED_ROOT, TrustedRoot};
use sigstore_types::{Bundle, Sha256Hash};
use sigstore_verify::{VerificationPolicy, Verifier};
use stogas_sigstore::{BuildPolicy, Subject, verify_build_attestation};

const MUTATIONS: [&str; 9] = [
    "/dsseEnvelope/signatures/0/sig",
    "/dsseEnvelope/payload",
    "/verificationMaterial/certificate/rawBytes",
    "/verificationMaterial/tlogEntries/0/logId/keyId",
    "/verificationMaterial/tlogEntries/0/inclusionPromise/signedEntryTimestamp",
    "/verificationMaterial/tlogEntries/0/inclusionProof/rootHash",
    "/verificationMaterial/tlogEntries/0/inclusionProof/hashes/0",
    "/verificationMaterial/tlogEntries/0/inclusionProof/checkpoint/envelope",
    "/verificationMaterial/tlogEntries/0/canonicalizedBody",
];

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

fn native_accepts(bytes: &[u8], policy: &BuildPolicy, issuer: &str, subjects: &[Subject]) -> bool {
    let Ok(text) = std::str::from_utf8(bytes) else {
        return false;
    };
    let Ok(bundle) = Bundle::from_json(text) else {
        return false;
    };
    let Ok(root) = TrustedRoot::from_json(SIGSTORE_PRODUCTION_TRUSTED_ROOT) else {
        return false;
    };
    let verifier = Verifier::new(&root);
    let verification_policy = VerificationPolicy::default()
        .require_identity(&policy.workflow_identity)
        .require_issuer(issuer);
    subjects.iter().all(|subject| {
        Sha256Hash::from_hex(subject.sha256).is_ok_and(|digest| {
            verifier
                .verify(digest, &bundle, &verification_policy)
                .is_ok()
        })
    })
}

fn flip(value: &mut Value, pointer: &str) {
    let original = value
        .pointer(pointer)
        .and_then(Value::as_str)
        .expect("mutation pointer must be a string");
    let mut changed = original.to_owned();
    changed.replace_range(..1, if original.starts_with('A') { "B" } else { "A" });
    *value.pointer_mut(pointer).unwrap() = Value::String(changed);
}

/// Both verifiers accept the real proof and reject each mutation of it.
fn assert_both_verifiers_agree(
    fixture: &[u8],
    policy: &BuildPolicy,
    issuer: &str,
    subjects: &[Subject],
    mutations: &[&str],
) {
    assert!(native_accepts(fixture, policy, issuer, subjects));
    assert!(verify_build_attestation(production(), fixture, subjects, policy).is_ok());
    for pointer in mutations {
        let mut value: Value = serde_json::from_slice(fixture).unwrap();
        flip(&mut value, pointer);
        let bytes = serde_json::to_vec(&value).unwrap();
        assert!(
            !native_accepts(&bytes, policy, issuer, subjects),
            "native verifier accepted {pointer}"
        );
        assert!(
            verify_build_attestation(production(), &bytes, subjects, policy).is_err(),
            "RustCrypto verifier accepted {pointer}"
        );
    }
}

#[test]
fn rustcrypto_matches_sigstore_rust_for_github_proofs() {
    assert_both_verifiers_agree(
        include_bytes!("../../../tests/fixtures/gateway-v0.0.1-attestation.jsonl"),
        &BuildPolicy {
            repository: "https://github.com/StogasAI/gateway".into(),
            workflow_identity: "https://github.com/StogasAI/gateway/.github/workflows/gateway-igvm-release.yml@refs/tags/v0.0.1".into(),
            source_ref: "refs/tags/v0.0.1".into(),
            source_commit: "27eb4b954a372975c9e7c5dbc77fbf0d0ca53b3f".into(),
            predicate_type: "https://slsa.dev/provenance/v1".into(),
        },
        "https://token.actions.githubusercontent.com",
        &[
            Subject {
                name: "gateway.igvm",
                sha256: "1b75d0ea7f94bc5f5a21080dd30e21370e14278a5b90eb19858c90dcc83a1bc6",
            },
            Subject {
                name: "gateway-launch-policy.json",
                sha256: "8cc8926592b179283c8cab267a27dfb3df4d1086dff2504e51df5fa12b8ff008",
            },
        ],
        &MUTATIONS,
    );
}

#[test]
fn rustcrypto_matches_sigstore_rust_for_gitlab_proofs() {
    let mut mutations = MUTATIONS.to_vec();
    mutations.push(
        "/verificationMaterial/timestampVerificationData/rfc3161Timestamps/0/signedTimestamp",
    );
    assert_both_verifiers_agree(
        include_bytes!("../../../tests/fixtures/gitlab-smoke-attestation.jsonl"),
        &BuildPolicy {
            repository: "https://gitlab.com/stogasai/stogas".into(),
            workflow_identity:
                "https://gitlab.com/stogasai/stogas//.gitlab-ci.yml@refs/tags/v0.0.0-smoke.1".into(),
            source_ref: "refs/tags/v0.0.0-smoke.1".into(),
            source_commit: "18e55c517c7c7a6bc51792bd396c73cf54e39221".into(),
            predicate_type: "https://slsa.dev/provenance/v1".into(),
        },
        "https://gitlab.com",
        &[
            Subject {
                name: "probe.txt",
                sha256: "a7ee3efe2a79ce827100f526e16979b4e00115a5d58e98a9ac7a99f88952e364",
            },
            Subject {
                name: "release-manifest.json",
                sha256: "3bc693e58109924b7b236a462a0c91772f0a9c0f58a865cbc03ccf3656266d30",
            },
        ],
        &mutations,
    );
}

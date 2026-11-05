# stogas-sigstore

Networkless verification of Sigstore v0.3 bundles in the profile that GitHub artifact attestations use: a DSSE envelope over an in-toto statement, signed with a Fulcio certificate and logged in Rekor v1 or v2. It checks the certificate chain, SCTs, Rekor inclusion proofs and checkpoints, RFC 3161 timestamps, the signature, and the exact subjects and signer identity. It makes no network requests, never reads the system clock, needs no random numbers, and builds for `wasm32-unknown-unknown` without setup. Other bundle versions and profiles fail closed.

## Verify a GitHub artifact attestation

```rust,no_run
use stogas_sigstore::{GithubPolicy, Subject, TrustedRoot, verify_github_attestation};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let root = TrustedRoot::from_json(&std::fs::read_to_string("trusted_root.json")?)?;
    let bundles = std::fs::read("app.tar.gz.jsonl")?;
    let policy = GithubPolicy {
        repository: "https://github.com/OWNER/REPO".into(),
        workflow_identity: "https://github.com/OWNER/REPO/.github/workflows/release.yml@refs/tags/v1.2.3".into(),
        source_ref: "refs/tags/v1.2.3".into(),
        source_commit: "0123456789abcdef0123456789abcdef01234567".into(),
        predicate_type: "https://slsa.dev/provenance/v1".into(),
    };
    let subjects = [Subject { name: "app.tar.gz", sha256: "<the file's lowercase SHA-256>" }];
    let verified = verify_github_attestation(&root, &bundles, &subjects, &policy)?;
    println!("logged at {}", verified.integrated_time);
    Ok(())
}
```

`gh attestation download app.tar.gz --repo OWNER/REPO` saves a file's bundles as JSON Lines. Pass one bundle or the whole file; exactly one bundle must match. The repository, ref, commit and GitHub-hosted runner come from the Fulcio certificate, as `gh attestation verify` checks them, because the workflow writes the provenance predicate itself.

`verify_dsse_attestation` takes any signer's exact certificate identity and OIDC issuer instead. Both return the statement's predicate, as its signer wrote it, for your own policy. `verify_rekor_document_inclusion` checks that a given Ed25519 key logged exact document bytes as a Rekor hashedrekord entry signed with Ed25519ph over SHA-512.

## Trusted root

Each check takes Sigstore's keys from a `trusted_root.json` that you vouch for. `verify_trust_update` authenticates one from the TUF files at <https://tuf-repo-cdn.sigstore.dev>, starting from the Sigstore TUF root compiled into this crate, without a clock; `verify_current_trust_update` also checks freshness at a time you give. Sigstore ends a replaced key's validity instead of removing it, so the current root also verifies older bundles.

## Other languages

[`@stogas/sigstore`](https://www.npmjs.com/package/@stogas/sigstore) is this crate as a WebAssembly package for browsers, Node, Bun, Deno and Workers.

## License

Apache-2.0. Requires Rust 1.94.1 or later.

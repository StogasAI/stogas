# Stogas SDK

Verify Stogas confidential gateways before sending credentials or inference content. One Rust core powers native clients, WebAssembly, and offline verification.

[Documentation](https://stogas.ai/docs/sdk-overview) · [Examples](https://github.com/StogasAI/stogas/tree/main/examples) · [Security](https://github.com/StogasAI/stogas/blob/main/SECURITY.md)

## What it does

- Verifies hardware attestation, approved builds, and session keys.
- Connects through attested TLS or end-to-end encryption over HTTPS.
- Verifies signed request receipts and downloaded evidence, online or offline.
- Encrypts provider credentials and plugin settings locally with your organization key.

Use the verifier transport with your language's OpenAI-compatible client or HTTP library. Bindings cover Rust, Python, Go, C, Java, .NET, Ruby, and Swift; JavaScript uses WebAssembly with Fetch-compatible runtimes. This project is pre-1.0, so APIs may change.

## Get started

Choose a [language guide](https://stogas.ai/docs/sdk-overview) or a runnable [example](https://github.com/StogasAI/stogas/tree/main/examples). Rust source builds require Rust 1.94.1 or later.

The optional CLI provides a local verified endpoint for an existing client. These install a release archive after checking its SHA-256:

```console
curl -fsSL https://raw.githubusercontent.com/StogasAI/stogas/main/install.sh | sh   # macOS and Linux
irm https://raw.githubusercontent.com/StogasAI/stogas/main/install.ps1 | iex       # Windows PowerShell
brew install stogasai/tap/stogas                                                    # Homebrew
scoop bucket add stogas https://github.com/StogasAI/homebrew-tap                    # Scoop
scoop install stogas/stogas
```

`pipx install stogas` and `uvx stogas` run it from the Python package, `cargo binstall stogas-cli` installs the release archive for your platform, and `ghcr.io/stogasai/stogas` is its container image. `cargo install stogas-cli --locked` and Nix, as `nix run github:StogasAI/stogas -- <command>`, build it from source. Then run:

```console
stogas serve --security tls
```

Use the printed URL as your client's base URL and keep it private. The transport sends a request again only when the gateway refused it before starting it, so a client retry after any other interruption may run the request again. Use `--security e2ee` for encrypted transport over HTTPS.

Other commands:

```console
stogas register                      # create an account and save its access token in the keychain
stogas login                         # approve this machine in your browser, or with --device-code
stogas topup 20 BTC                  # add credit with BTC, XMR, a token, or card
stogas api {org}/keys --paginate     # call the dashboard API with the saved token, as gh api does
stogas policy edit key <key-id>      # edit a policy in $VISUAL or $EDITOR and save it on close
stogas byok check <credential-id>    # check a provider credential, with your key if you encrypted it
stogas probe --security tls          # check a fresh verified connection without an API key
stogas verify evidence.json --json   # verify saved evidence offline
stogas encryption-key create --organization <org-id> --label prod
stogas verify-release ./release      # verify downloaded release assets
```

Streamed content can arrive before final verification. Treat a response as complete only after verified completion. See the [CLI guide](https://stogas.ai/docs/cli) for sign-in, top-ups, policy editing, credential checks, customer encryption and proofs.

## Standalone verifiers

Two parts of the core also work without Stogas, as crates and as WebAssembly packages for browsers, Node, Bun, Deno and Workers:

| Verifies | Rust | npm |
|---|---|---|
| AMD SEV-SNP attestation reports | [`stogas-sev-snp`](https://github.com/StogasAI/stogas/tree/main/crates/sev-snp) | [`@stogas/sev-snp`](https://github.com/StogasAI/stogas/tree/main/packages/sev-snp) |
| GitHub and Sigstore in-toto attestations | [`stogas-sigstore`](https://github.com/StogasAI/stogas/tree/main/crates/sigstore) | [`@stogas/sigstore`](https://github.com/StogasAI/stogas/tree/main/packages/sigstore) |

## Releases

Every file of a [release](https://github.com/StogasAI/stogas/releases), and the container image as `oci://ghcr.io/stogasai/stogas:<version>`, has a GitHub build attestation:

```console
gh attestation verify <file> --repo StogasAI/stogas --signer-workflow StogasAI/stogas/.github/workflows/release.yml --source-ref refs/tags/v<version> --deny-self-hosted-runners
```

Some package managers install a pre-release only when asked:

```console
pip install --pre stogas
gem install stogas --pre
dotnet add package Stogas --prerelease
cargo add stogas@<version>
```

Maven and Swift take the exact version. On npm, `stogas@next` names a pre-release that is newer than the newest full release.

## Contributing

```console
cargo test --locked --workspace --all-targets
```

[CI](https://github.com/StogasAI/stogas/blob/main/.github/workflows/ci.yml) covers the core, transports, and language bindings; [fuzzing](https://github.com/StogasAI/stogas/blob/main/.github/workflows/fuzz.yml) covers parsers and verification boundaries. [`scripts/live-test.py`](https://github.com/StogasAI/stogas/blob/main/scripts/live-test.py) runs every language's tests against the live gateway. Report vulnerabilities through the [security policy](https://github.com/StogasAI/stogas/blob/main/SECURITY.md).

## License

[Apache-2.0](https://github.com/StogasAI/stogas/blob/main/LICENSE).

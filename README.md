# Stogas SDK

Verify a Stogas confidential gateway before you send it credentials or prompts. One Rust core serves the CLI and the SDKs for Rust, Python, JavaScript, Go, C, Java, .NET, Ruby, and Swift.

[Documentation](https://stogas.ai/docs/sdk-overview) · [Examples](https://github.com/StogasAI/stogas/tree/main/examples) · [Security](https://github.com/StogasAI/stogas/blob/main/SECURITY.md)

## Use the CLI

Install the CLI. Each command installs a release archive after it checks the SHA-256:

```console
curl -fsSL https://raw.githubusercontent.com/StogasAI/stogas/main/install.sh | sh   # macOS and Linux
irm https://raw.githubusercontent.com/StogasAI/stogas/main/install.ps1 | iex       # Windows PowerShell
brew install stogasai/tap/stogas                                                    # Homebrew
```

Then start a local endpoint:

```console
stogas serve --security tls
```

`stogas serve` checks the gateway's hardware attestation and build, and then prints a base URL for OpenAI clients and one for Anthropic clients, such as Claude Code. Use the one that fits your client, and keep it private. `--security e2ee` encrypts end to end over HTTPS instead.

The [CLI guide](https://stogas.ai/docs/cli) lists every command and the other ways to install, such as Scoop, pipx, cargo-binstall, and Docker. `cargo install stogas-cli --locked` and `nix run github:StogasAI/stogas` build the CLI from source.

## Use an SDK

Choose a [language guide](https://stogas.ai/docs/sdk-overview) or a runnable [example](https://github.com/StogasAI/stogas/tree/main/examples). The SDK gives your OpenAI-compatible client or HTTP library a transport that verifies the gateway. It also verifies signed receipts and saved evidence offline.

The project is pre-1.0, so APIs can change. Some package managers install a pre-release only when you ask:

```console
pip install --pre stogas
gem install stogas --pre
dotnet add package Stogas --prerelease
cargo add stogas@<version>
npm install stogas@<version>
```

Maven and Swift also take the exact version.

## Standalone verifiers

Two parts of the core also work without Stogas, as crates and as WebAssembly packages for browsers, Node, Bun, Deno, and Workers:

| Verifies                             | Rust                                                                              | npm                                                                                  |
| ------------------------------------ | --------------------------------------------------------------------------------- | ------------------------------------------------------------------------------------ |
| AMD SEV-SNP attestation reports      | [`stogas-sev-snp`](https://github.com/StogasAI/stogas/tree/main/crates/sev-snp)   | [`@stogas/sev-snp`](https://github.com/StogasAI/stogas/tree/main/packages/sev-snp)   |
| GitHub and GitLab build attestations | [`stogas-sigstore`](https://github.com/StogasAI/stogas/tree/main/crates/sigstore) | [`@stogas/sigstore`](https://github.com/StogasAI/stogas/tree/main/packages/sigstore) |

## Verify a release

Every file of a [release](https://github.com/StogasAI/stogas/releases) has a GitHub build attestation, and so does the container image, as `oci://ghcr.io/stogasai/stogas:<version>`:

```console
gh attestation verify <file> --repo StogasAI/stogas --signer-workflow StogasAI/stogas/.github/workflows/release.yml --source-ref refs/tags/v<version> --deny-self-hosted-runners
```

GitLab.com's hosted runners also rebuild each full release from the same tag, and `gitlab-attestation.jsonl` covers every file they built. A preview, such as an alpha version, has that file only when GitLab rebuilt it. Only Apple hardware runs Xcode, so GitLab packages the macOS and iOS compiler outputs of GitHub's build:

```console
cosign verify-blob-attestation <file> --bundle gitlab-attestation.jsonl --type https://slsa.dev/provenance/v1 --certificate-oidc-issuer https://gitlab.com --certificate-identity https://gitlab.com/stogasai/stogas//.gitlab-ci.yml@refs/tags/v<version>
```

## Develop

Rust 1.94.1 or later builds the workspace:

```console
cargo test --locked --workspace --all-targets
```

[CI](https://github.com/StogasAI/stogas/blob/main/.github/workflows/ci.yml) tests the core, the transports, and every language binding on each push. A nightly [fuzz campaign](https://github.com/StogasAI/stogas/blob/main/.github/workflows/fuzz.yml) covers the parsers and the verification code.

## License

[Apache-2.0](https://github.com/StogasAI/stogas/blob/main/LICENSE).

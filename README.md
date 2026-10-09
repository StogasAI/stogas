# Stogas SDK

Verify Stogas confidential gateways before sending credentials or inference content. One Rust core powers native clients, WebAssembly, and offline verification.

[Documentation](https://stogas.ai/docs/sdk-overview) · [Examples](examples/) · [Security](SECURITY.md)

## What it does

- Verifies hardware attestation, approved builds, and session keys.
- Connects through attested TLS or end-to-end encryption over HTTPS.
- Verifies signed request receipts and downloaded evidence, online or offline.
- Encrypts provider credentials and plugin settings locally with your organization key.

Use the verifier transport with your language's OpenAI-compatible client or HTTP library. Bindings cover Rust, Python, Go, C, Java, .NET, Ruby, and Swift; JavaScript uses WebAssembly with Fetch-compatible runtimes. This project is pre-1.0, so APIs may change.

## Get started

Choose a [language guide](https://stogas.ai/docs/sdk-overview) or a runnable [example](examples/). Rust source builds require Rust 1.97.1 or later.

The optional CLI provides a local verified endpoint for an existing client. Install it with `cargo install stogas --locked --features cli` or a native release archive, then run:

```console
stogas serve --security tls
```

Use the printed URL as your client's base URL and keep it private. The transport never replays inference, so a retry after an interruption may run the request again. Use `--security e2ee` for encrypted transport over HTTPS.

Other commands:

```console
stogas probe --security tls          # check a fresh verified connection without an API key
stogas verify evidence.json --json   # verify saved evidence offline
stogas encryption-key --output org.key
stogas verify-release ./release      # verify downloaded release assets offline
```

Streamed content can arrive before final verification. Treat a response as complete only after verified completion. See the [CLI guide](https://stogas.ai/docs/cli) for customer encryption and proofs.

## Contributing

```console
cargo test --locked --workspace --all-targets --features stogas/cli
```

[CI](.github/workflows/ci.yml) covers the core, transports, and language bindings; [fuzzing](.github/workflows/fuzz.yml) covers parsers and verification boundaries. Report vulnerabilities through the [security policy](SECURITY.md).

## License

[Apache-2.0](LICENSE).

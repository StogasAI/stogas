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

Choose a [language guide](https://stogas.ai/docs/sdk-overview) or a runnable [example](examples/). Rust source builds require Rust 1.94.1 or later.

The optional CLI provides a local verified endpoint for an existing client. Install it with `cargo install stogas-cli --locked` or a native release archive, then run:

```console
stogas serve --security tls
```

Use the printed URL as your client's base URL and keep it private. The transport sends a request again only when the gateway refused it before starting it, so a client retry after any other interruption may run the request again. Use `--security e2ee` for encrypted transport over HTTPS.

Other commands:

```console
stogas signup                        # create an account and save its access token in the keychain
stogas topup 20 BTC                  # add credit with a cryptocurrency payment
stogas api GET /api/account          # send a dashboard API request with the saved access token
stogas probe --security tls          # check a fresh verified connection without an API key
stogas verify evidence.json --json   # verify saved evidence offline
stogas encryption-key --output org.key
stogas verify-release ./release      # verify downloaded release assets
```

Streamed content can arrive before final verification. Treat a response as complete only after verified completion. See the [CLI guide](https://stogas.ai/docs/cli) for sign-in, top-ups, customer encryption and proofs.

## Contributing

```console
cargo test --locked --workspace --all-targets
```

[CI](.github/workflows/ci.yml) covers the core, transports, and language bindings; [fuzzing](.github/workflows/fuzz.yml) covers parsers and verification boundaries. [`scripts/live-test.py`](scripts/live-test.py) runs every language's tests against the live gateway. Report vulnerabilities through the [security policy](SECURITY.md).

## License

[Apache-2.0](LICENSE).

# stogas-core

Networkless verification for Stogas confidential gateways: AMD SEV-SNP attestation, the approved gateway and catalog releases, their Sigstore build proofs, signed receipts and SDK release signatures. It also holds the end-to-end encrypted channel that the SDKs use. It performs no I/O: the caller supplies the bytes and the time.

Most applications use [`stogas`](https://crates.io/crates/stogas), which fetches the evidence and connects through attested TLS or end-to-end encryption. Use this crate to check saved evidence, receipts or releases yourself.

```rust,no_run
use stogas_core::{authority::Environment, evidence::Verifier};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Saved evidence, or the bytes that Environment::evidence_origins serve.
    let evidence = std::fs::read("evidence.json")?;
    let now_unix_ms = i64::try_from(std::time::UNIX_EPOCH.elapsed()?.as_millis())?;
    let mut verifier = Verifier::stogas(Environment::Production)?;
    let snapshot = verifier.refresh(&evidence, now_unix_ms)?;
    println!("{}", snapshot.summary());
    Ok(())
}
```

## Features

- `snp` (default): AMD SEV-SNP appraisal, receipts and log batches.
- `staging`: Stogas's staging environment.
- `gateway`: the gateway's producers of these formats; clients never need it.

## WebAssembly

The crate builds for `wasm32-unknown-unknown`. It takes random numbers from `getrandom` 0.4, so the application selects that crate's browser backend:

```toml
getrandom = { version = "0.4", features = ["wasm_js"] }
```

## License

Apache-2.0. Requires Rust 1.94.1 or later.

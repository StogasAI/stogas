# stogas-sev-snp

Networkless verification of AMD SEV-SNP attestation reports, for `no_std`, native and WebAssembly builds. It parses a report strictly, verifies its VCEK or VLEK certificate up to AMD's root for Milan, Genoa or Turin, which it pins, binds the certificate to the report's processor, chip and TCB, checks the report signature and an optional AMD CRL, and checks the result against your policy. It makes no network requests, never reads the system clock and needs no random numbers. Reports from other processors, such as Venice, fail closed.

## Verify a report

```rust,no_run
use stogas_sev_snp::{CertificateTable, PlatformRule, Policy, Product, Report, TcbVersion, verify};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    // A report and certificate table from configfs-tsm: outblob and auxblob.
    let report = std::fs::read("outblob")?;
    let table = std::fs::read("auxblob")?;
    let signing_key = Report::parse(&report)?.signing_key();
    let endorsements = CertificateTable::parse(&table)?.endorsements(signing_key)?;
    let policy = Policy {
        report_data: Some([0; 64]),
        vmpl: Some(0),
        platforms: vec![PlatformRule {
            product: Some(Product::Milan),
            minimum_tcb: Some(TcbVersion { fmc: None, bootloader: 4, tee: 0, snp: 29, microcode: 222 }),
            ..PlatformRule::default()
        }],
        ..Policy::default()
    };
    let now = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH)?.as_secs();
    let verified = verify(&report, &endorsements, &policy, now)?;
    println!("{} report signed with a {:?}", verified.product(), verified.signing_key());
    Ok(())
}
```

A host that returns no certificate table leaves you to fetch the VCEK: `kds::vcek_path` gives its path on AMD's Key Distribution Service. Cloud providers that sign with a VLEK, such as AWS, return it in the table. Pass AMD's CRL from `kds::crl_path` in `Endorsements::crl`, and set `require_crl` to refuse a report without one.

## What verification checks

| Step | Rejects |
|---|---|
| Report | A wrong size, report versions other than 2 to 6, set reserved bytes and bits, an unsigned report, an unsupported processor and a TCB outside its product's layout |
| Certificates | Anything but AMD's exact RSASSA-PSS SHA-384 encoding, names and extensions, and an intermediate that the pinned root did not sign |
| Binding | A certificate for another product, TCB, chip, or kind of key |
| Signature | An invalid ECDSA P-384 signature over the report |
| Time | A certificate or CRL that is not valid at the time you give |
| Policy | Report values and guest policy flags that differ from the policy, and a platform that meets none of its platform rules |

A `PlatformRule` names a product or CPUID, and optionally chips. Its TCB minimums apply to the reported, committed and current TCB, and its launch minimum to the launch TCB. It rejects firmware that the host updated but did not commit, which could roll back, unless `permit_provisional_firmware` is set. The guest policy rule forbids debugging and migration agents unless you change `forbid`.

## Policies in JSON

With the `serde` feature, `Policy`, `PlatformFacts` and `Validity` read and write JSON, and `Report` writes it. Byte fields are lowercase hexadecimal, and masks are `0x` followed by 16 lowercase digits, so that JavaScript keeps every bit.

```json
{
  "measurements": ["<96 lowercase hexadecimal digits>"],
  "vmpl": 0,
  "guest_policy": { "minimum_abi": [1, 55], "forbid": "0x00000000000c0000" },
  "platforms": [
    {
      "product": "Milan",
      "minimum_tcb": { "bootloader": 4, "tee": 0, "snp": 29, "microcode": 222 },
      "required_platform_info_mask": "0x0000000000000004"
    }
  ],
  "require_crl": true
}
```

## Verify many reports from one platform

`Endorsement::verify` checks a certificate chain once, and `Endorsement::verify_report` then checks each report it signs. `Crl::verify` authenticates a CRL. AMD numbers its CRLs in order, so keep the highest `Crl::number` for each product and refuse a lower one, which an attacker could replay to hide a revocation.

## Targets without an operating system

The crate needs only `alloc`. On `x86_64-unknown-none`, LLVM cannot compile `sha2` without optimization, so give debug builds `[profile.dev.package.sha2] opt-level = 1`, or `RUSTFLAGS='--cfg sha2_backend="soft"'`.

## Other languages

[`@stogas/sev-snp`](https://www.npmjs.com/package/@stogas/sev-snp) is this crate as a WebAssembly package for browsers, Node, Bun, Deno and Workers.

## License

Apache-2.0. Requires Rust 1.94.1 or later.

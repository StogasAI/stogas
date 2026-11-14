# `@stogas/sev-snp`

Networkless WebAssembly verification of AMD SEV-SNP attestation reports, for Node, Bun, Deno, browsers and Cloudflare Workers. It parses a report strictly, verifies its VCEK or VLEK certificate up to AMD's root for Milan, Genoa or Turin, which it pins, binds the certificate to the report's processor, chip and TCB, checks the report signature and an optional AMD CRL, and checks the result against your policy. Reports from other processors, such as Venice, fail closed.

```js
import { readFileSync } from 'node:fs';
import { certificate_table_endorsements, verify } from '@stogas/sev-snp';

// A report and certificate table from configfs-tsm: outblob and auxblob.
const report = readFileSync('outblob');
const endorsements = certificate_table_endorsements(readFileSync('auxblob'), report);
const verified = verify(report, endorsements, {
	report_data: expectedReportData,
	measurements: [expectedMeasurement],
	vmpl: 0,
	platforms: [
		{ product: 'Milan', minimum_tcb: { bootloader: 4, tee: 0, snp: 29, microcode: 222 } }
	]
});
```

`verify` checks the certificates at the current time, or at the time you pass in seconds since the UNIX epoch. It returns the parsed report with its product, signing key, the cloud provider that a VLEK names, and when the certificates and CRL are valid.

A host that returns no certificate table leaves you to fetch the VCEK from `vcek_url(report)` and pass it as `{ leaf }`. Cloud providers that sign with a VLEK, such as AWS, return it in the table. Pass AMD's CRL from `crl_url(product)` as `crl`, and set `require_crl` to refuse a report without one. `verify_crl` returns a CRL's number: keep the highest for each product and refuse a lower one, which an attacker could replay to hide a revocation.

## Policies

The policy is the JSON form of the Rust crate's `Policy`: byte fields are lowercase hexadecimal, and masks are `0x` followed by 16 lowercase digits, so that JavaScript keeps every bit. An absent value or empty list requires nothing, except that the guest policy forbids debugging and a migration agent unless you set `forbid`. Unknown fields throw, so that a misspelled requirement cannot go unchecked. The [stogas-sev-snp README](https://github.com/StogasAI/stogas/tree/main/crates/sev-snp#readme) describes each check.

## Errors

A failed check throws a `SevSnpError` whose `code` names it: `report`, `unsupported_product`, `unsigned`, `certificate`, `signature`, `expired`, `revoked`, `binding`, `missing_endorsement`, `invalid_policy` or `policy`. Arguments of the wrong type throw a `TypeError`.

## Entry points

The default entry initializes the WebAssembly synchronously in Node, Bun and Deno. In a browser, call the default export of `@stogas/sev-snp/browser` once before using it. Cloudflare Workers and other runtimes that import `.wasm` files as modules use `@stogas/sev-snp/worker`.

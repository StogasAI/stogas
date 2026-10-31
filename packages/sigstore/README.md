# `@stogas/sigstore`

Small, networkless WebAssembly verifier for the standard GitHub/Sigstore v0.3 DSSE and in-toto
profile supported by Stogas. It verifies embedded Fulcio, SCT, Rekor v1 and v2, RFC 3161, subject,
identity, and GitHub Actions provenance material without fetching TUF or calling Sigstore
services.

Pass Sigstore's current `trusted_root.json`, which you vouch for: fetch it through a TUF client
from Sigstore's repository, or take it from current Stogas evidence after `stogas` verified it.
Sigstore ends a replaced key's validity instead of removing it, so the current root also verifies
older attestations.

Use `stogas` to verify the complete Stogas confidential-gateway evidence and transport.

```js
import { verify_github_attestation } from '@stogas/sigstore';

const verified = verify_github_attestation(
	attestationBytes,
	JSON.stringify(subjects),
	JSON.stringify(policy),
	trustedRootJson
);
```

The default Node/Bun export initializes WebAssembly synchronously. Browser consumers initialize
the `/browser` module once with its default initializer; compatible Workers use `/worker`.

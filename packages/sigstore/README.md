# `@stogas/sigstore`

Small, networkless WebAssembly verifier for the Sigstore v0.3 DSSE and in-toto profile of build
attestations from GitHub Actions and GitLab.com. It verifies embedded Fulcio, SCT, Rekor v1 and v2,
RFC 3161, subject, identity and CI provenance material without fetching TUF or calling Sigstore
services.

Pass Sigstore's current `trusted_root.json`, which you vouch for: fetch it through a TUF client
from Sigstore's repository, or take it from current Stogas evidence after `stogas` verified it.
Sigstore ends a replaced key's validity instead of removing it, so the current root also verifies
older attestations.

Use `stogas` to verify the complete Stogas confidential-gateway evidence and transport.

```js
import { verify_build_attestation } from '@stogas/sigstore';

const verified = verify_build_attestation(
	attestationBytes,
	[{ name: 'gateway.igvm', sha256: '1b75d0ea…' }],
	{
		repository: 'https://github.com/StogasAI/gateway',
		workflow_identity:
			'https://github.com/StogasAI/gateway/.github/workflows/gateway-igvm-release.yml@refs/tags/v0.0.1',
		source_ref: 'refs/tags/v0.0.1',
		source_commit: '27eb4b954a372975c9e7c5dbc77fbf0d0ca53b3f',
		predicate_type: 'https://slsa.dev/provenance/v1'
	},
	trustedRootJson
);
```

It returns the authenticated log time, the subjects and the statement's predicate. The
repository's host selects the provider: a GitLab.com project such as
`https://gitlab.com/stogasai/gateway` takes the identity
`https://gitlab.com/stogasai/gateway//.gitlab-ci.yml@refs/tags/v0.0.1`. The job writes the
predicate, so the policy's repository, ref, commit, workflow and hosted runner come from the Fulcio
certificate instead. `verify_dsse_attestation` takes the same arguments with
any signer's identity, `{ certificate_identity, certificate_oidc_issuer, predicate_type }`, and
leaves the predicate to your own policy. Unknown fields in subjects and policies throw, so that a
misspelled requirement cannot go unchecked.

The default Node, Bun and Deno export initializes WebAssembly synchronously. Browser consumers initialize
the `/browser` module once with its default initializer; compatible Workers use `/worker`.

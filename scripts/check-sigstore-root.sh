#!/usr/bin/env bash
# Fails when Sigstore's public-good trusted root differs from the copy compiled
# into the verifier. gh downloads the root through TUF and verifies it from the
# TUF root built into gh.
set -euo pipefail
embedded="$(dirname "$0")/../crates/sigstore/src/trusted_root.json"
current=$(mktemp)
trap 'rm -f "$current"' EXIT
gh attestation trusted-root |
	jq -S 'select(any(.tlogs[]?; .baseUrl == "https://rekor.sigstore.dev"))' >"$current"
if ! diff -u <(jq -S . "$embedded") "$current"; then
	echo "::error::Sigstore's trusted root differs from the embedded copy"
	exit 1
fi

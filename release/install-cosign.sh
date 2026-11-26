#!/bin/sh
# Installs the cosign that releases sign and check Sigstore bundles with as DIR/cosign.
set -eu
curl --fail --location --silent --show-error --retry 5 --retry-all-errors --output "$1/cosign" \
	https://github.com/sigstore/cosign/releases/download/v3.1.4/cosign-linux-amd64
echo "424e2c97d0b45fd7a6b608a87f090f35633f4c23ece5f092d48bba11aaf4bbfa  $1/cosign" | sha256sum -c -
chmod 755 "$1/cosign"

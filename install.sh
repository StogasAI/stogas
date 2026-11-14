#!/bin/sh
# Install the stogas CLI on Linux or macOS:
#
#   curl -fsSL https://raw.githubusercontent.com/StogasAI/stogas/main/install.sh | sh
#
# Options: --version <version> installs that release instead of the newest, and --dir <directory>
# installs into that directory instead of ~/.local/bin. STOGAS_VERSION and STOGAS_INSTALL_DIR set
# the same. The archive must match the SHA-256 that the release manifest lists for it.
set -eu

REPOSITORY="StogasAI/stogas"

fail() {
	echo "stogas install: $*" >&2
	exit 1
}

fetch() {
	if command -v curl >/dev/null 2>&1; then
		curl --proto '=https' --tlsv1.2 -fsSL --retry 3 "$1"
	elif command -v wget >/dev/null 2>&1; then
		wget -qO- "$1"
	else
		fail "curl or wget is required"
	fi
}

download() {
	if command -v curl >/dev/null 2>&1; then
		curl --proto '=https' --tlsv1.2 -fsSL --retry 3 -o "$2" "$1"
	else
		wget -qO "$2" "$1"
	fi
}

sha256() {
	if command -v sha256sum >/dev/null 2>&1; then
		sha256sum "$1" | cut -d ' ' -f 1
	elif command -v shasum >/dev/null 2>&1; then
		shasum -a 256 "$1" | cut -d ' ' -f 1
	else
		fail "sha256sum or shasum is required"
	fi
}

# The newest full release, or before the first one, the newest preview.
newest() {
	tag=$(fetch "https://api.github.com/repos/$REPOSITORY/releases/latest" 2>/dev/null | sed -n 's/^ *"tag_name": *"v\([^"]*\)".*/\1/p' | head -n 1) || true
	if [ -z "$tag" ]; then
		tag=$(fetch "https://api.github.com/repos/$REPOSITORY/releases?per_page=1" | sed -n 's/^ *"tag_name": *"v\([^"]*\)".*/\1/p' | head -n 1)
	fi
	[ -n "$tag" ] || fail "cannot find a release of $REPOSITORY"
	echo "$tag"
}

platform() {
	case "$(uname -m)" in
		x86_64 | amd64) arch=amd64 ;;
		aarch64 | arm64) arch=arm64 ;;
		*) fail "no release for $(uname -m) processors" ;;
	esac
	case "$(uname -s)" in
		Darwin)
			# A shell under Rosetta reports x86_64 on an Apple silicon Mac.
			if [ "$arch" = amd64 ] && [ "$(sysctl -n hw.optional.arm64 2>/dev/null || echo 0)" = 1 ]; then
				arch=arm64
			fi
			echo "darwin-$arch"
			;;
		Linux)
			if ls /lib/ld-musl-* >/dev/null 2>&1; then
				echo "linux-musl-$arch"
			else
				echo "linux-$arch"
			fi
			;;
		*) fail "use install.ps1 on Windows, or a release archive on $(uname -s)" ;;
	esac
}

main() {
	version="${STOGAS_VERSION:-}"
	directory="${STOGAS_INSTALL_DIR:-${HOME:?}/.local/bin}"
	while [ $# -gt 0 ]; do
		case "$1" in
			--version) version="${2:?--version needs a value}"; shift 2 ;;
			--dir) directory="${2:?--dir needs a value}"; shift 2 ;;
			*) fail "unknown option $1" ;;
		esac
	done
	version="${version#v}"
	[ -n "$version" ] || version=$(newest)
	name="stogas-cli-v$version-$(platform)"
	base="https://github.com/$REPOSITORY/releases/download/v$version"

	work=$(mktemp -d)
	trap 'rm -rf "$work"' EXIT
	download "$base/$name.tar.gz" "$work/$name.tar.gz" || fail "cannot download $name.tar.gz from release v$version"
	download "$base/release-manifest.json" "$work/release-manifest.json" || fail "cannot download the manifest of release v$version"
	expected=$(grep -o "\"name\":\"$name\.tar\.gz\",\"sha256\":\"[0-9a-f]\{64\}\"" "$work/release-manifest.json" | sed 's/.*"sha256":"//; s/"$//')
	[ -n "$expected" ] || fail "the manifest of release v$version lists no $name.tar.gz"
	[ "$(sha256 "$work/$name.tar.gz")" = "$expected" ] || fail "$name.tar.gz does not match its SHA-256 in the release manifest"

	tar -xzf "$work/$name.tar.gz" -C "$work"
	mkdir -p "$directory"
	cp "$work/$name/stogas" "$directory/.stogas.$$"
	chmod 755 "$directory/.stogas.$$"
	mv -f "$directory/.stogas.$$" "$directory/stogas"
	echo "Installed stogas $version in $directory"
	case ":$PATH:" in
		*":$directory:"*) ;;
		*) echo "Add $directory to your PATH to run stogas." ;;
	esac
}

main "$@"

"""What package managers that install a release's own files receive: a Homebrew formula and a
Scoop manifest for the StogasAI/homebrew-tap repository, an Arch User Repository package and a
container image. Each takes the CLI from the checked release archives and names them by SHA-256,
so they install exactly the files that the release's build proof covers."""

import gzip
import hashlib
import io
import json
import re
import tarfile
import time

from artifacts import REPOSITORY

HOMEPAGE = "https://stogas.ai"
# Homebrew's limit is 80 characters, with no leading article and no final period.
DESCRIPTION = "Verified local endpoint, sign-up and offline checks for the Stogas AI gateway"
IMAGE = "ghcr.io/stogasai/stogas"
VERSION = re.compile(r"(0|[1-9]\d*)\.(0|[1-9]\d*)\.(0|[1-9]\d*)(?:-((?:0|[1-9]\d*|\d*[A-Za-z-][0-9A-Za-z-]*)(?:\.(?:0|[1-9]\d*|\d*[A-Za-z-][0-9A-Za-z-]*))*))?\Z")
# Every macOS that the release supports is Ventura or later.
MACOS = "ventura"
# A container's user when it names none: distroless's nonroot.
NONROOT = 65532
OCI_INDEX = "application/vnd.oci.image.index.v1+json"
OCI_MANIFEST = "application/vnd.oci.image.manifest.v1+json"
OCI_CONFIG = "application/vnd.oci.image.config.v1+json"
OCI_LAYER = "application/vnd.oci.image.layer.v1.tar+gzip"


def precedence(version):
    """Semantic Versioning's order: a pre-release comes before its release, numeric identifiers
    before others, and a longer list of equal identifiers last."""
    match = VERSION.fullmatch(version)
    if not match:
        raise ValueError(f"Not a release version: {version}")
    major, minor, patch, pre = match.groups()
    core = (int(major), int(minor), int(patch))
    if pre is None:
        return core, 1, ()
    return core, 0, tuple((0, int(part), "") if part.isdigit() else (1, 0, part) for part in pre.split("."))


def preview(version):
    return precedence(version)[1] == 0


def offered(releases):
    """The version that package managers offer, from GitHub's releases: the newest full release,
    or before the first one, the newest preview. A rerun for an older release changes nothing."""
    versions = [
        release["tag_name"][1:] for release in releases
        if not release["draft"] and release["tag_name"].startswith("v") and VERSION.fullmatch(release["tag_name"][1:])
    ]
    full = [version for version in versions if not preview(version)]
    return max(full or versions, key=precedence, default=None)


def archive(manifest, platform, extension):
    version = manifest["version"]
    name = f"stogas-v{version}-{platform}.{extension}"
    matches = [artifact for artifact in manifest["artifacts"] if artifact["name"] == name]
    if len(matches) != 1:
        raise ValueError(f"The release has no {name}")
    return f"{REPOSITORY}/releases/download/v{version}/{name}", matches[0]["sha256"]


def formula(manifest):
    """Homebrew unpacks the archive into its single directory, where the CLI is, and reads the
    version from the archive's name. The macOS requirement stays inside `on_macos`: Homebrew on
    Linux refuses a formula that names one anywhere else."""
    def files(platform):
        url, sha256 = archive(manifest, platform, "tar.gz")
        return f'      url "{url}"\n      sha256 "{sha256}"\n'
    return (
        f"# The publish workflow of {REPOSITORY} writes this file from each release's checked files.\n"
        "class Stogas < Formula\n"
        f'  desc "{DESCRIPTION}"\n'
        f'  homepage "{HOMEPAGE}"\n'
        '  license "Apache-2.0"\n'
        "\n"
        "  on_macos do\n"
        f"    depends_on macos: :{MACOS}\n"
        "\n"
        "    on_arm do\n"
        f"{files('darwin-arm64')}"
        "    end\n"
        "    on_intel do\n"
        f"{files('darwin-amd64')}"
        "    end\n"
        "  end\n"
        "\n"
        "  on_linux do\n"
        "    on_arm do\n"
        f"{files('linux-arm64')}"
        "    end\n"
        "    on_intel do\n"
        f"{files('linux-amd64')}"
        "    end\n"
        "  end\n"
        "\n"
        "  def install\n"
        '    bin.install "stogas"\n'
        "  end\n"
        "\n"
        "  test do\n"
        '    assert_match version.to_s, shell_output("#{bin}/stogas --version")\n'
        "  end\n"
        "end\n"
    )


def scoop(manifest):
    version = manifest["version"]
    def files(platform):
        url, sha256 = archive(manifest, platform, "zip")
        return {"url": url, "hash": sha256, "extract_dir": f"stogas-v{version}-{platform}"}
    return json.dumps({
        "version": version,
        "description": DESCRIPTION,
        "homepage": HOMEPAGE,
        "license": "Apache-2.0",
        "architecture": {"64bit": files("windows-amd64"), "arm64": files("windows-arm64")},
        "bin": "stogas.exe",
    }, indent=4) + "\n"


def aur_version(version):
    """pacman's pkgver allows no hyphen, and its order puts 0.1.0_alpha.1 before 0.1.0."""
    precedence(version)
    return version.replace("-", "_")


def pkgbuild(manifest, pkgrel=1):
    """An AUR package of the glibc CLI, kept byte for byte as released: makepkg neither strips it
    nor splits its debug information."""
    sources = {arch: archive(manifest, platform, "tar.gz") for arch, platform in (("x86_64", "linux-amd64"), ("aarch64", "linux-arm64"))}
    return (
        "# Maintainer: Stogas <devops@stogas.ai>\n"
        f"# The publish workflow of {REPOSITORY} writes this file from each release's checked files.\n"
        "pkgname=stogas-bin\n"
        f"pkgver={aur_version(manifest['version'])}\n"
        f"pkgrel={pkgrel}\n"
        f"pkgdesc='{DESCRIPTION}'\n"
        "arch=('x86_64' 'aarch64')\n"
        f"url='{HOMEPAGE}'\n"
        "license=('Apache-2.0')\n"
        "depends=('gcc-libs' 'glibc')\n"
        "provides=('stogas')\n"
        "conflicts=('stogas')\n"
        "options=('!strip' '!debug')\n"
        + "".join(f"source_{arch}=('{url}')\nsha256sums_{arch}=('{sha256}')\n" for arch, (url, sha256) in sources.items())
        + "\n"
        "package() {\n"
        '\tinstall -Dm755 stogas-v*/stogas "$pkgdir/usr/bin/stogas"\n'
        '\tinstall -Dm644 stogas-v*/LICENSE "$pkgdir/usr/share/licenses/$pkgname/LICENSE"\n'
        "}\n"
    )


def srcinfo(manifest, pkgrel=1):
    """The metadata that the AUR reads, as `makepkg --printsrcinfo` writes it for pkgbuild()."""
    lines = [
        "pkgbase = stogas-bin",
        f"\tpkgdesc = {DESCRIPTION}",
        f"\tpkgver = {aur_version(manifest['version'])}",
        f"\tpkgrel = {pkgrel}",
        f"\turl = {HOMEPAGE}",
        "\tarch = x86_64",
        "\tarch = aarch64",
        "\tlicense = Apache-2.0",
        "\tdepends = gcc-libs",
        "\tdepends = glibc",
        "\tprovides = stogas",
        "\tconflicts = stogas",
        "\toptions = !strip",
        "\toptions = !debug",
    ]
    for arch, platform in (("x86_64", "linux-amd64"), ("aarch64", "linux-arm64")):
        url, sha256 = archive(manifest, platform, "tar.gz")
        lines += [f"\tsource_{arch} = {url}", f"\tsha256sums_{arch} = {sha256}"]
    return "\n".join([*lines, "", "pkgname = stogas-bin", ""])


def pkgrel(current, manifest):
    """The pkgrel for this release: 1 for a new version, the same while nothing changes, and one
    more when the package changes without a new version."""
    fields = dict(line.strip().split(" = ", 1) for line in current.splitlines() if " = " in line) if current else {}
    if fields.get("pkgver") != aur_version(manifest["version"]):
        return 1
    release = int(fields["pkgrel"])
    return release if srcinfo(manifest, release) == current else release + 1


def _layer(cli, license_text, epoch):
    """One layer, written the same way every time: the CLI in /usr/local/bin, its license, and a
    /tmp that every user can write."""
    data = io.BytesIO()
    with tarfile.open(fileobj=data, mode="w", format=tarfile.PAX_FORMAT) as layer:
        def add(name, mode, content=None):
            entry = tarfile.TarInfo(name)
            entry.mtime = epoch
            entry.mode = mode
            entry.uname = entry.gname = ""
            if content is None:
                entry.type = tarfile.DIRTYPE
                layer.addfile(entry)
            else:
                entry.size = len(content)
                layer.addfile(entry, io.BytesIO(content))
        add("tmp/", 0o1777)
        for directory in ("usr/", "usr/local/", "usr/local/bin/", "usr/local/share/", "usr/local/share/doc/", "usr/local/share/doc/stogas/"):
            add(directory, 0o755)
        add("usr/local/bin/stogas", 0o755, cli)
        add("usr/local/share/doc/stogas/LICENSE", 0o644, license_text)
    tar = data.getvalue()
    compressed = io.BytesIO()
    with gzip.GzipFile(fileobj=compressed, filename="", mode="wb", mtime=0, compresslevel=9) as output:
        output.write(tar)
    return tar, compressed.getvalue()


def _blob(value):
    return f"sha256:{hashlib.sha256(value).hexdigest()}"


def _json(value):
    return json.dumps(value, separators=(",", ":"), sort_keys=True).encode()


def image(manifest, binaries, license_text):
    """An OCI image index for linux/amd64 and linux/arm64 from the static musl CLIs, built the same
    way every time, so anyone can rebuild it from the release and compare digests. Returns the
    index and every blob and manifest it names, by digest."""
    version = manifest["version"]
    source = manifest["source"]
    created = _created(source["epoch"])
    labels = {
        "org.opencontainers.image.created": created,
        "org.opencontainers.image.description": DESCRIPTION,
        "org.opencontainers.image.licenses": "Apache-2.0",
        "org.opencontainers.image.revision": source["commit"],
        "org.opencontainers.image.source": REPOSITORY,
        "org.opencontainers.image.title": "stogas",
        "org.opencontainers.image.url": HOMEPAGE,
        "org.opencontainers.image.version": version,
    }
    blobs = {}
    platforms = []
    for architecture, variant in (("amd64", None), ("arm64", "v8")):
        tar, layer = _layer(binaries[architecture], license_text, source["epoch"])
        platform = {"architecture": architecture, "os": "linux", **({"variant": variant} if variant else {})}
        config = _json({
            **platform,
            "config": {
                "Entrypoint": ["/usr/local/bin/stogas"],
                "Env": ["PATH=/usr/local/bin"],
                "Labels": labels,
                "User": f"{NONROOT}:{NONROOT}",
                "WorkingDir": "/tmp",
            },
            "created": created,
            "history": [{"created": created, "created_by": f"stogas release v{version}"}],
            "rootfs": {"diff_ids": [_blob(tar)], "type": "layers"},
        })
        image_manifest = _json({
            "config": {"digest": _blob(config), "mediaType": OCI_CONFIG, "size": len(config)},
            "layers": [{"digest": _blob(layer), "mediaType": OCI_LAYER, "size": len(layer)}],
            "mediaType": OCI_MANIFEST,
            "schemaVersion": 2,
        })
        blobs[_blob(config)] = config
        blobs[_blob(layer)] = layer
        platforms.append({"digest": _blob(image_manifest), "mediaType": OCI_MANIFEST, "platform": platform, "size": len(image_manifest), "manifest": image_manifest})
    index = _json({
        "annotations": labels,
        "manifests": [{key: value for key, value in item.items() if key != "manifest"} for item in platforms],
        "mediaType": OCI_INDEX,
        "schemaVersion": 2,
    })
    return {"index": index, "manifests": {item["digest"]: item["manifest"] for item in platforms}, "blobs": blobs}


def _created(epoch):
    return time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(epoch))

"""What package managers that install a release's own files receive: a Homebrew formula and a
Scoop manifest for the StogasAI/homebrew-tap repository, an Arch User Repository package and a
container image. Each takes the CLI from the release's CLI archives and names them by SHA-256, so
they install exactly the files that the release's build proof covers. The container image is a
release file itself, written here when the release is packaged."""

import argparse
import gzip
import hashlib
import io
import json
import re
import tarfile
import time
from pathlib import Path

from artifacts import REPOSITORY

HOMEPAGE = "https://stogas.ai"
# Homebrew's limit is 80 characters, with no leading article and no final period.
DESCRIPTION = "Verified local endpoint, sign-up and offline checks for the Stogas AI gateway"
IMAGE = "ghcr.io/stogasai/stogas"
VERSION = re.compile(
    r"(0|[1-9]\d*)\.(0|[1-9]\d*)\.(0|[1-9]\d*)(?:-((?:0|[1-9]\d*|\d*[A-Za-z-][0-9A-Za-z-]*)(?:\.(?:0|[1-9]\d*|\d*[A-Za-z-][0-9A-Za-z-]*))*))?\Z"
)
# Every macOS that the release supports is Ventura or later.
MACOS = "ventura"
# A container's user when it names none: distroless's nonroot.
NONROOT = 65532
OCI_INDEX = "application/vnd.oci.image.index.v1+json"
OCI_MANIFEST = "application/vnd.oci.image.manifest.v1+json"
OCI_CONFIG = "application/vnd.oci.image.config.v1+json"
OCI_LAYER = "application/vnd.oci.image.layer.v1.tar+gzip"
# The image's platforms, in its index's order: each runs that architecture's static musl CLI.
ARCHITECTURES = (("amd64", None), ("arm64", "v8"))
IMAGE_TARGETS = frozenset(f"linux-musl-{architecture}" for architecture, _ in ARCHITECTURES)


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
    return (
        core,
        0,
        tuple((0, int(part), "") if part.isdigit() else (1, 0, part) for part in pre.split(".")),
    )


def preview(version):
    return precedence(version)[1] == 0


def offered(releases):
    """The version that package managers offer, from GitHub's releases: the newest full release,
    or before the first one, the newest preview. A rerun for an older release changes nothing."""
    versions = [
        release["tag_name"][1:]
        for release in releases
        if not release["draft"]
        and release["tag_name"].startswith("v")
        and VERSION.fullmatch(release["tag_name"][1:])
    ]
    full = [version for version in versions if not preview(version)]
    return max(full or versions, key=precedence, default=None)


def archive(manifest, platform, extension):
    """The URL and SHA-256 of a platform's CLI archive."""
    version = manifest["version"]
    name = f"stogas-cli-v{version}-{platform}.{extension}"
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
        f"# Generated from each {REPOSITORY} release; edits here are overwritten.\n"
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
        return {"url": url, "hash": sha256, "extract_dir": f"stogas-cli-v{version}-{platform}"}

    return (
        json.dumps(
            {
                "version": version,
                "description": DESCRIPTION,
                "homepage": HOMEPAGE,
                "license": "Apache-2.0",
                "architecture": {"64bit": files("windows-amd64"), "arm64": files("windows-arm64")},
                "bin": "stogas.exe",
            },
            indent=4,
        )
        + "\n"
    )


# The release forms whose pkgver pacman orders as Semantic Versioning does. vercmp ranks a version
# followed by letters below the bare version (0.1.0alpha.1 < 0.1.0), but one followed by "_", "."
# or "~" above it, so the hyphen goes rather than becoming another separator.
AUR_FORM = re.compile(r"(\d+\.\d+\.\d+)(?:-((?:alpha|beta|rc)(?:\.\d+)?))?\Z")


def aur_version(version):
    """pacman's pkgver, which allows no hyphen."""
    precedence(version)
    match = AUR_FORM.match(version)
    if not match:
        raise ValueError(f"pacman orders no pkgver for {version} as Semantic Versioning does")
    return match[1] + (match[2] or "")


def pkgbuild(manifest, pkgrel=1):
    """An AUR package of the glibc CLI, kept byte for byte as released: makepkg neither strips it
    nor splits its debug information."""
    sources = {
        arch: archive(manifest, platform, "tar.gz")
        for arch, platform in (("x86_64", "linux-amd64"), ("aarch64", "linux-arm64"))
    }
    return (
        "# Maintainer: Stogas <devops@stogas.ai>\n"
        f"# Generated from each {REPOSITORY} release; edits here are overwritten.\n"
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
        + "".join(
            f"source_{arch}=('{url}')\nsha256sums_{arch}=('{sha256}')\n"
            for arch, (url, sha256) in sources.items()
        )
        + "\n"
        "package() {\n"
        '\tinstall -Dm755 stogas-cli-v*/stogas "$pkgdir/usr/bin/stogas"\n'
        '\tinstall -Dm644 stogas-cli-v*/LICENSE "$pkgdir/usr/share/licenses/$pkgname/LICENSE"\n'
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
    fields = (
        dict(line.strip().split(" = ", 1) for line in current.splitlines() if " = " in line)
        if current
        else {}
    )
    if fields.get("pkgver") != aur_version(manifest["version"]):
        return 1
    release = int(fields["pkgrel"])
    return release if srcinfo(manifest, release) == current else release + 1


def container_archive(version):
    return f"stogas-container-v{version}.tar"


def cli_files(packages, version, architecture):
    """The static musl CLI and its license from the release's CLI archive for `architecture`."""
    name = f"stogas-cli-v{version}-linux-musl-{architecture}"
    with tarfile.open(Path(packages) / f"{name}.tar.gz") as archive:

        def read(member):
            entry = archive.getmember(f"{name}/{member}")
            if not entry.isfile():
                raise ValueError(f"{name}/{member} is not a file")
            return archive.extractfile(entry).read()

        return read("stogas"), read("LICENSE")


def layer(cli, license_text, epoch):
    """The image's one layer, uncompressed and written the same way every time: the CLI in
    /usr/local/bin, its license, and a /tmp that every user can write."""
    data = io.BytesIO()
    with tarfile.open(fileobj=data, mode="w", format=tarfile.PAX_FORMAT) as tar:

        def add(name, mode, content=None):
            entry = tarfile.TarInfo(name)
            entry.mtime = epoch
            entry.mode = mode
            entry.uname = entry.gname = ""
            if content is None:
                entry.type = tarfile.DIRTYPE
                tar.addfile(entry)
            else:
                entry.size = len(content)
                tar.addfile(entry, io.BytesIO(content))

        add("tmp/", 0o1777)
        for directory in (
            "usr/",
            "usr/local/",
            "usr/local/bin/",
            "usr/local/share/",
            "usr/local/share/doc/",
            "usr/local/share/doc/stogas/",
        ):
            add(directory, 0o755)
        add("usr/local/bin/stogas", 0o755, cli)
        add("usr/local/share/doc/stogas/LICENSE", 0o644, license_text)
    return data.getvalue()


def compress(tar):
    compressed = io.BytesIO()
    with gzip.GzipFile(
        fileobj=compressed, filename="", mode="wb", mtime=0, compresslevel=9
    ) as output:
        output.write(tar)
    return compressed.getvalue()


def _blob(value):
    return f"sha256:{hashlib.sha256(value).hexdigest()}"


def _json(value):
    return json.dumps(value, separators=(",", ":"), sort_keys=True).encode()


def image(version, source, layers):
    """An OCI image index for linux/amd64 and linux/arm64, the same every time for the same layers.
    `layers` maps each architecture to its layer and that layer compressed. Returns the index and
    every manifest and blob it names, by digest."""
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
    for architecture, variant in ARCHITECTURES:
        tar, compressed = layers[architecture]
        platform = {
            "architecture": architecture,
            "os": "linux",
            **({"variant": variant} if variant else {}),
        }
        config = _json(
            {
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
            }
        )
        image_manifest = _json(
            {
                "config": {"digest": _blob(config), "mediaType": OCI_CONFIG, "size": len(config)},
                "layers": [
                    {"digest": _blob(compressed), "mediaType": OCI_LAYER, "size": len(compressed)}
                ],
                "mediaType": OCI_MANIFEST,
                "schemaVersion": 2,
            }
        )
        blobs[_blob(config)] = config
        blobs[_blob(compressed)] = compressed
        platforms.append(
            {
                "digest": _blob(image_manifest),
                "mediaType": OCI_MANIFEST,
                "platform": platform,
                "size": len(image_manifest),
                "manifest": image_manifest,
            }
        )
    index = _json(
        {
            "annotations": labels,
            "manifests": [
                {key: value for key, value in item.items() if key != "manifest"}
                for item in platforms
            ],
            "mediaType": OCI_INDEX,
            "schemaVersion": 2,
        }
    )
    return {
        "index": index,
        "manifests": {item["digest"]: item["manifest"] for item in platforms},
        "blobs": blobs,
    }


def oci_archive(version, built, epoch):
    """The image as an OCI image layout in one tar, which `skopeo copy oci-archive:`, `crane push`,
    `podman load` and `docker load` read. Its index names the image index, which is the digest that
    the registry serves."""
    layout = _json(
        {
            "manifests": [
                {
                    "annotations": {
                        "io.containerd.image.name": f"{IMAGE}:{version}",
                        "org.opencontainers.image.ref.name": version,
                    },
                    "digest": _blob(built["index"]),
                    "mediaType": OCI_INDEX,
                    "size": len(built["index"]),
                }
            ],
            "mediaType": OCI_INDEX,
            "schemaVersion": 2,
        }
    )
    blobs = {_blob(built["index"]): built["index"], **built["manifests"], **built["blobs"]}
    data = io.BytesIO()
    with tarfile.open(fileobj=data, mode="w", format=tarfile.PAX_FORMAT) as tar:

        def add(name, content=None):
            entry = tarfile.TarInfo(name)
            entry.mtime = epoch
            entry.uname = entry.gname = ""
            if content is None:
                entry.type, entry.mode = tarfile.DIRTYPE, 0o755
                tar.addfile(entry)
            else:
                entry.size, entry.mode = len(content), 0o644
                tar.addfile(entry, io.BytesIO(content))

        add("blobs/")
        add("blobs/sha256/")
        for name in sorted(blobs):
            add(f"blobs/sha256/{name.removeprefix('sha256:')}", blobs[name])
        add("index.json", layout)
        add("oci-layout", _json({"imageLayoutVersion": "1.0.0"}))
    return data.getvalue()


def read_oci_archive(data):
    """The image in an OCI image layout archive: its index, and every manifest and blob that the
    index names, each checked against its digest."""
    files = {}
    with tarfile.open(fileobj=io.BytesIO(data)) as tar:
        for entry in tar:
            if entry.isfile():
                files[entry.name] = tar.extractfile(entry).read()
            elif not entry.isdir():
                raise ValueError(f"The image archive holds {entry.name}, which is not a file")

    def blob(descriptor, media_type):
        content = files.get(f"blobs/sha256/{descriptor['digest'].removeprefix('sha256:')}")
        if (
            descriptor.get("mediaType") != media_type
            or content is None
            or _blob(content) != descriptor["digest"]
            or len(content) != descriptor["size"]
        ):
            raise ValueError(f"The image archive lacks the {media_type} {descriptor['digest']}")
        return content

    (top,) = json.loads(files["index.json"])["manifests"]
    index = blob(top, OCI_INDEX)
    manifests, blobs = {}, {}
    for item in json.loads(index)["manifests"]:
        manifests[item["digest"]] = blob(item, OCI_MANIFEST)
        image_manifest = json.loads(manifests[item["digest"]])
        for descriptor, media_type in (
            (image_manifest["config"], OCI_CONFIG),
            *((layer_descriptor, OCI_LAYER) for layer_descriptor in image_manifest["layers"]),
        ):
            blobs[descriptor["digest"]] = blob(descriptor, media_type)
    return {"index": index, "manifests": manifests, "blobs": blobs}


def _created(epoch):
    return time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(epoch))


if __name__ == "__main__":
    # Packaging writes the image in its pinned packer image, so every machine compresses the
    # layers with the same zlib.
    parser = argparse.ArgumentParser(
        description="Write the container image of a release's static musl CLIs"
    )
    parser.add_argument(
        "packages", type=Path, help="A directory that holds both linux-musl CLI archives"
    )
    parser.add_argument("destination", type=Path)
    parser.add_argument("--version", required=True)
    parser.add_argument("--commit", required=True)
    parser.add_argument("--epoch", type=int, required=True)
    args = parser.parse_args()
    layers = {}
    for architecture, _ in ARCHITECTURES:
        tar = layer(*cli_files(args.packages, args.version, architecture), args.epoch)
        layers[architecture] = (tar, compress(tar))
    built = image(args.version, {"commit": args.commit, "epoch": args.epoch}, layers)
    with args.destination.open("xb") as output:
        output.write(oci_archive(args.version, built, args.epoch))

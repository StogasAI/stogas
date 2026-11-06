"""Deterministic release containers and strict artifact inventory checks."""

import gzip
import hashlib
import json
import os
import re
import stat
import tarfile
import tempfile
import time
import zipfile
from contextlib import contextmanager
from pathlib import Path, PurePosixPath


REPOSITORY = "https://github.com/StogasAI/stogas"
MANIFEST = "release-manifest.json"
NAME = re.compile(r"[A-Za-z0-9][A-Za-z0-9._+-]{0,199}\Z")


def canonical(value):
    # Release schemas permit ASCII keys, integers and strings, with no floats.
    # This subset has the same encoding as RFC 8785.
    def validate(item):
        if item is None or isinstance(item, (bool, str)):
            return
        if isinstance(item, int) and abs(item) <= 9007199254740991:
            return
        if isinstance(item, list):
            for child in item:
                validate(child)
            return
        if isinstance(item, dict) and all(isinstance(key, str) and key.isascii() for key in item):
            for child in item.values():
                validate(child)
            return
        raise ValueError("Release JSON requires ASCII keys, strings and safe integers; floats are forbidden")
    validate(value)
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False, allow_nan=False).encode()


def wheel_tag(target):
    machine = {"amd64": "x86_64", "arm64": "aarch64"}[target["arch"]]
    if target["os"] == "linux":
        return f"manylinux_2_17_{machine}.manylinux2014_{machine}" if target["libc"] == "glibc" else f"musllinux_1_2_{machine}"
    if target["os"] == "windows":
        return {"amd64": "win_amd64", "arm64": "win_arm64"}[target["arch"]]
    return f"macosx_{target['minimum'].replace('.', '_')}_{'arm64' if target['arch'] == 'arm64' else 'x86_64'}"


def wheel(names, target):
    """Return the one abi3 wheel built for a target."""
    matching = [name for name in names if re.fullmatch(r"stogas-[0-9A-Za-z.]+-cp310-abi3-" + re.escape(wheel_tag(target)) + r"\.whl", name)]
    if len(matching) != 1:
        raise ValueError(f"Release requires exactly one wheel for {wheel_tag(target)}")
    return matching[0]


def digest(path):
    with Path(path).open("rb") as source:
        return hashlib.file_digest(source, "sha256").hexdigest()


def write_json(path, value):
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    with tempfile.NamedTemporaryFile(dir=path.parent, prefix=path.name + ".", delete=False) as output:
        temporary = Path(output.name)
        try:
            output.write(canonical(value) + b"\n")
            output.flush()
            os.fsync(output.fileno())
        except BaseException:
            temporary.unlink(missing_ok=True)
            raise
    try:
        temporary.chmod(0o644)
        temporary.replace(path)
    finally:
        temporary.unlink(missing_ok=True)


def regular_files(root):
    root = Path(root)
    for path in sorted(root.rglob("*"), key=lambda item: item.relative_to(root).as_posix()):
        if path.is_symlink():
            raise ValueError(f"Symlinks are not release inputs: {path}")
        if path.is_file():
            yield path
        elif not path.is_dir():
            raise ValueError(f"Non-regular release input: {path}")


def source_digest(root):
    """Identify a source tree by its paths, executable bits and file bytes."""
    files = [{"path": path.relative_to(root).as_posix(), "mode": 0o755 if path.stat().st_mode & 0o111 else 0o644, "sha256": digest(path)} for path in regular_files(root)]
    return hashlib.sha256(canonical(files)).hexdigest()


def verify_source(source, archive, expected, prefix):
    """Bind consumer fixtures to source bytes, preserving tar modes on Windows."""
    actual = {path.relative_to(source).as_posix(): path for path in regular_files(source)}
    entries = []
    seen = set()
    total = 0
    with tarfile.open(archive, "r:gz") as packed:
        for member in packed:
            if not member.isfile() or not member.name.startswith(prefix + "/") or member.mode not in (0o644, 0o755):
                raise ValueError("Invalid source archive entry")
            name = member.name[len(prefix) + 1:]
            total += member.size
            if name not in actual or name in seen or member.size < 0 or total > 2 * 1024**3:
                raise ValueError("Source archive inventory differs")
            seen.add(name)
            with packed.extractfile(member) as stream:
                sha256 = hashlib.file_digest(stream, "sha256").hexdigest()
            if actual[name].stat().st_size != member.size or digest(actual[name]) != sha256:
                raise ValueError(f"Source bytes differ: {name}")
            entries.append({"path": name, "mode": member.mode, "sha256": sha256})
    if seen != set(actual) or hashlib.sha256(canonical(sorted(entries, key=lambda entry: entry["path"]))).hexdigest() != expected:
        raise ValueError("Source differs from its recorded identity")


@contextmanager
def release_source(directory, manifest):
    """Unpack and authenticate the source snapshot a release records."""
    version = manifest["version"]
    archive = Path(directory) / f"stogas-source-v{version}.tar.gz"
    with tempfile.TemporaryDirectory(prefix="stogas-release-source-") as temporary:
        unpack(archive, Path(temporary) / "source")
        source = Path(temporary) / "source" / f"stogas-v{version}"
        verify_source(source, archive, manifest["source"]["sha256"], f"stogas-v{version}")
        yield source


def tar_gz(destination, root, epoch, prefix=""):
    """Normalize ordering, owners, modes and both tar/gzip timestamps."""
    root = Path(root)
    with Path(destination).open("xb") as output:
        with gzip.GzipFile(fileobj=output, filename="", mode="wb", mtime=epoch, compresslevel=9) as compressed:
            with tarfile.open(fileobj=compressed, mode="w", format=tarfile.PAX_FORMAT) as archive:
                for path in regular_files(root):
                    name = str(PurePosixPath(prefix) / path.relative_to(root).as_posix())
                    entry = tarfile.TarInfo(name)
                    entry.size = path.stat().st_size
                    entry.mode = 0o755 if path.stat().st_mode & 0o111 else 0o644
                    entry.mtime = epoch
                    with path.open("rb") as source:
                        archive.addfile(entry, source)


def zip_archive(destination, root, epoch, prefix=""):
    root = Path(root)
    date = time.gmtime(max(epoch, 315532800))[:6]
    with zipfile.ZipFile(destination, "x", compression=zipfile.ZIP_DEFLATED, compresslevel=9) as archive:
        for path in regular_files(root):
            name = str(PurePosixPath(prefix) / path.relative_to(root).as_posix())
            entry = zipfile.ZipInfo(name, date_time=date)
            entry.create_system = 3
            entry.compress_type = zipfile.ZIP_DEFLATED
            entry.external_attr = (stat.S_IFREG | (0o755 if path.stat().st_mode & 0o111 else 0o644)) << 16
            archive.writestr(entry, path.read_bytes(), compresslevel=9)


def unpack(source, destination, max_bytes=2 * 1024**3):
    """Extract only unique regular files; never links, devices or traversal paths."""
    destination = Path(destination)
    seen = set()
    total = 0

    def save(name, stream, size, mode):
        nonlocal total
        parts = PurePosixPath(name).parts
        if not parts or "/".join(parts) != name or name.startswith("/") or "\\" in name or any(p in {".", ".."} or ":" in p for p in parts):
            raise ValueError(f"Unsafe archive name: {name}")
        total += size
        if name in seen or size < 0 or total > max_bytes:
            raise ValueError(f"Duplicate or oversized archive entry: {name}")
        seen.add(name)
        path = destination.joinpath(*parts)
        path.parent.mkdir(parents=True, exist_ok=True)
        # The destination must be new and owned by this extraction.
        with path.open("xb") as output:
            remaining = size
            while remaining:
                chunk = stream.read(min(remaining, 1024 * 1024))
                if not chunk:
                    raise ValueError(f"Truncated archive entry: {name}")
                output.write(chunk)
                remaining -= len(chunk)
        path.chmod(0o755 if mode & 0o111 else 0o644)

    if destination.exists():
        raise ValueError("Archive extraction requires a new destination")
    destination.mkdir(parents=True)
    if zipfile.is_zipfile(source):
        with zipfile.ZipFile(source) as archive:
            for entry in archive.infolist():
                if entry.is_dir():
                    continue
                mode = entry.external_attr >> 16
                if stat.S_IFMT(mode) not in (0, stat.S_IFREG):
                    raise ValueError(f"Non-regular archive entry: {entry.filename}")
                with archive.open(entry) as stream:
                    save(entry.filename, stream, entry.file_size, mode)
    else:
        with tarfile.open(source, "r:gz") as archive:
            for entry in archive:
                if entry.isdir():
                    continue
                if not entry.isfile():
                    raise ValueError(f"Non-regular archive entry: {entry.name}")
                with archive.extractfile(entry) as stream:
                    save(entry.name, stream, entry.size, entry.mode)


def inventory(directory, expected):
    directory = Path(directory)
    actual = {p.name for p in directory.iterdir()}
    if actual != set(expected):
        raise ValueError(f"Release inventory differs: missing={sorted(set(expected) - actual)}, extra={sorted(actual - set(expected))}")
    files = []
    for name in sorted(expected):
        path = directory / name
        if not NAME.fullmatch(name) or not path.is_file() or path.is_symlink():
            raise ValueError(f"Not a regular release artifact: {name}")
        files.append({"name": name, "sha256": digest(path), "size": path.stat().st_size})
    return files


def leb128(data, offset):
    """Read the unsigned 32-bit LEB128 integer at `offset`; return it and the offset after it."""
    value = 0
    for index in range(5):
        if offset + index >= len(data):
            raise ValueError("Truncated WebAssembly integer")
        byte = data[offset + index]
        value |= (byte & 0x7F) << (7 * index)
        if not byte & 0x80:
            if value > 0xFFFFFFFF:
                raise ValueError("WebAssembly integer exceeds 32 bits")
            return value, offset + index + 1
    raise ValueError("WebAssembly integer exceeds 32 bits")


def wasm_sections(module):
    """Each section of a WebAssembly module as (id, custom section name or None, start, payload
    start, end), with offsets into the module."""
    if module[:8] != b"\0asm\x01\0\0\0":
        raise ValueError("Not a WebAssembly 1.0 module")
    sections, offset = [], 8
    while offset < len(module):
        identifier = module[offset]
        size, payload = leb128(module, offset + 1)
        end = payload + size
        if end > len(module):
            raise ValueError("Truncated WebAssembly section")
        name = None
        if identifier == 0:
            length, start = leb128(module, payload)
            if start + length > end:
                raise ValueError("Malformed WebAssembly custom section")
            name, payload = module[start:start + length].decode(), start + length
        sections.append((identifier, name, offset, payload, end))
        offset = end
    return sections


def without_names(module):
    """The module without its function names and DWARF debug information. Stack traces and
    debuggers read only those sections, which follow the code, so every function keeps its index
    and byte offset and the names still describe the result."""
    kept, removed = [module[:8]], False
    for identifier, name, start, _, end in wasm_sections(module):
        if name == "name" or (name or "").startswith(".debug"):
            removed = True
        elif removed and identifier:
            raise ValueError("WebAssembly debug information precedes the module's code")
        else:
            kept.append(module[start:end])
    return b"".join(kept)


def function_names(module):
    """The function names of a module's name section as the `index:name` lines that Emscripten's
    `--emit-symbol-map` writes, which name the `wasm-function[index]` frames of a stack trace."""
    lines = []
    for _, name, _, offset, end in wasm_sections(module):
        if name != "name":
            continue
        while offset < end:
            kind = module[offset]
            size, offset = leb128(module, offset + 1)
            stop = offset + size
            if stop > end:
                raise ValueError("Truncated WebAssembly name subsection")
            if kind == 1:
                count, cursor = leb128(module, offset)
                for _ in range(count):
                    index, cursor = leb128(module, cursor)
                    length, cursor = leb128(module, cursor)
                    text = module[cursor:cursor + length].decode()
                    if "\n" in text:
                        raise ValueError("WebAssembly function name holds a line break")
                    lines.append(f"{index}:{text}\n")
                    cursor += length
                if cursor != stop:
                    raise ValueError("Malformed WebAssembly function names")
            offset = stop
    return "".join(lines).encode()


def verify_inventory(directory, manifest, metadata=()):
    expected = manifest["artifacts"]
    names = [entry["name"] for entry in expected]
    if names != sorted(set(names)):
        raise ValueError("Release artifact names must be unique and sorted")
    actual = inventory(directory, [*names, MANIFEST, *metadata])
    payload = [entry for entry in actual if entry["name"] in names]
    if payload != expected:
        raise ValueError("Release artifact bytes differ from the manifest")
    if (Path(directory) / MANIFEST).read_bytes() != canonical(manifest) + b"\n":
        raise ValueError("Release manifest is not canonical")
    return digest(Path(directory) / MANIFEST)


if __name__ == "__main__":
    import argparse
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("format", choices=["zip", "tar.gz"])
    parser.add_argument("source", type=Path)
    parser.add_argument("destination", type=Path)
    parser.add_argument("--epoch", type=int, required=True)
    parser.add_argument("--prefix", default="")
    args = parser.parse_args()
    pack = zip_archive if args.format == "zip" else tar_gz
    pack(args.destination, args.source, args.epoch, args.prefix)

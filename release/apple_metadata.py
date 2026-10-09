"""Portable paths and stable ordering in Apple package metadata."""

import base64
import csv
import hashlib
import json
import plistlib

from artifacts import regular_files


def normalize_dsym(bundle):
    for path in sorted(bundle.glob("Contents/Resources/Relocations/*/*.yml")):
        lines = path.read_text().splitlines(keepends=True)
        locations = [index for index, line in enumerate(lines) if line.startswith("binary-path:")]
        if len(locations) != 1:
            raise ValueError("Unexpected dSYM relocation metadata")
        # This identifies the binary, not an object or source file. Keep every
        # relocation and the complete DWARF companion unchanged.
        lines[locations[0]] = "binary-path: " + json.dumps(path.stem) + "\n"
        path.write_text("".join(lines))


def normalize_wheel(tree, source):
    for bundle in sorted(tree.rglob("*.dSYM")):
        normalize_dsym(bundle)
    prefix = "path+" + source.as_uri() + "/"

    def portable_refs(value):
        if isinstance(value, str) and value.startswith(prefix):
            return "path+file:///stogas/" + value[len(prefix):]
        if isinstance(value, list):
            return [portable_refs(item) for item in value]
        if isinstance(value, dict):
            return {key: portable_refs(item) for key, item in value.items()}
        return value

    for path in tree.glob("*.dist-info/sboms/*.cyclonedx.json"):
        value = portable_refs(json.loads(path.read_text()))
        path.write_text(json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False, allow_nan=False) + "\n")
    records = list(tree.glob("*.dist-info/RECORD"))
    if len(records) != 1:
        raise ValueError("Expected one wheel RECORD")
    record = records[0]
    with record.open(newline="") as stream:
        rows = list(csv.reader(stream))
    names = {path.relative_to(tree).as_posix() for path in regular_files(tree)}
    if any(len(row) != 3 for row in rows) or len(rows) != len(names) or {row[0] for row in rows} != names:
        raise ValueError("Wheel RECORD does not match its file inventory")
    for row in rows:
        path = tree / row[0]
        if path == record:
            row[1:] = ["", ""]
        else:
            with path.open("rb") as stream:
                checksum = hashlib.file_digest(stream, "sha256").digest()
            row[1:] = ["sha256=" + base64.urlsafe_b64encode(checksum).rstrip(b"=").decode(), str(path.stat().st_size)]
    with record.open("w", newline="") as stream:
        csv.writer(stream).writerows(rows)


def normalize_xcframework(framework):
    path = framework / "Info.plist"
    info = plistlib.loads(path.read_bytes())
    info["AvailableLibraries"].sort(key=lambda library: library["LibraryIdentifier"])
    path.write_bytes(plistlib.dumps(info, sort_keys=True))

#!/usr/bin/env python3
"""Check that every package states the release version, or write it there.

`check <version>` fails unless every place below states the version. `set <version>` writes it to
each place and then checks. The places are patterns, not a replacement of the old version's text:
a version such as 0.1.0 is also the version of other packages in the lock files.
"""

import re
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
CRATE = r"stogas(?:-[a-z-]+)?"
MAVEN = r"<groupId>ai\.stogas</groupId><artifactId>stogas</artifactId><version>([^<]+)</version>"
# Each entry: the files, as `git ls-files` patterns; the pattern, whose one group is the version;
# and whether every file must state the version, which a lock file or an example may not.
PLACES = [
    (
        ["package.json", "packages/*/package.json"],
        r'\A\{\n\t"name": "[^"]+",\n\t"version": "([^"]+)"',
        True,
    ),
    (["package-lock.json"], r'"name": "stogas",\n\t+"version": "([^"]+)"', True),
    (["Cargo.toml"], r'^\[workspace\.package\]\nversion = "([^"]+)"', True),
    (["Cargo.toml"], rf'^{CRATE} = \{{ path = "[^"]+", version = "=([^"]+)" \}}', True),
    (["Cargo.lock", "*/Cargo.lock"], rf'^name = "{CRATE}"\nversion = "([^"]+)"', True),
    (["bindings/java/pom.xml"], MAVEN, True),
    (["*pom.xml"], MAVEN, False),
    (["bindings/dotnet/Stogas/Stogas.csproj"], r"<Version>([^<]+)</Version>", True),
    (["*.csproj"], r'<PackageReference Include="Stogas" Version="([^"]+)"', False),
    (["bindings/ruby/stogas.gemspec"], r"s\.version = '([^']+)'", True),
]


def places(version):
    """Each place as its file, the span of its version and the text it must hold."""
    for patterns, pattern, required in PLACES:
        listed = subprocess.run(
            ["git", "ls-files", "--", *patterns], cwd=ROOT, check=True, capture_output=True
        )
        files = listed.stdout.decode().split()
        if not files:
            raise SystemExit(f"No file matches {patterns}")
        for name in files:
            # RubyGems writes a pre-release with a dot where the others have a hyphen.
            wanted = version.replace("-", ".") if name.endswith(".gemspec") else version
            # A package that is never published stays at 0.0.0, and a pom may take the version
            # from a property.
            spans = [
                match.span(1)
                for match in re.finditer(pattern, (ROOT / name).read_text(), re.MULTILINE)
                if match[1] != "0.0.0" and not match[1].startswith("$")
            ]
            if required and not spans:
                raise SystemExit(f"{name} states no version where {pattern} expects one")
            for span in spans:
                yield name, span, wanted


def main():
    if len(sys.argv) != 3 or sys.argv[1] not in ("check", "set"):
        raise SystemExit("Usage: package-versions.py <check|set> <version>")
    action, version = sys.argv[1:]
    # pacman, PEP 440, RubyGems and Maven order alpha, beta and rc as Semantic Versioning does,
    # and other pre-release forms differently.
    if not re.fullmatch(
        r"(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)(-(alpha|beta|rc)(\.(0|[1-9][0-9]*))?)?",
        version,
    ):
        raise SystemExit("Invalid release version: use X.Y.Z, or X.Y.Z-alpha.N, -beta.N or -rc.N")
    if action == "set":
        # A set, because two entries can name one place.
        edits = {}
        for name, span, wanted in places(version):
            edits.setdefault(name, set()).add((span, wanted))
        for name, spans in edits.items():
            text = (ROOT / name).read_text()
            # From the end, so that an earlier span keeps its position.
            for (start, end), wanted in sorted(spans, reverse=True):
                text = text[:start] + wanted + text[end:]
            (ROOT / name).write_text(text)
    wrong = [
        f"{name}: {(ROOT / name).read_text()[span[0] : span[1]]}"
        for name, span, wanted in places(version)
        if (ROOT / name).read_text()[span[0] : span[1]] != wanted
    ]
    if wrong:
        raise SystemExit(f"These places do not state {version}:\n" + "\n".join(wrong))
    # Maturin takes the Python package's version from the workspace.
    if re.search(r"^version = ", (ROOT / "bindings/python/Cargo.toml").read_text(), re.MULTILINE):
        raise SystemExit("bindings/python/Cargo.toml must inherit the workspace version")


if __name__ == "__main__":
    main()

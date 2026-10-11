#!/usr/bin/env python3
"""Give Rust's temporary MSVC linker inputs stable names in the release image.

Remove when rust-lang/rust#71714 is fixed and two clean builds, including PDBs,
match without this shim. Object bytes and linker options are left intact.
"""

import hashlib
from pathlib import Path
import re
import shutil
import subprocess
import sys


TEMP = re.compile(r"/build/target/[^\s\"<>]*?/rustc[A-Za-z0-9]{6,}(?=/)")
OUTPUT = re.compile(r"(?i)[/-]out:(/build/target/[^\s\"]+)")


def link(arguments):
    # rustc can switch to a Windows-quoted UTF-16 response file at ARG_MAX.
    # Rewrite its text without reinterpreting quoting or argument boundaries.
    responses = {}
    for argument in arguments:
        if argument.startswith("@"):
            data = Path(argument[1:]).read_bytes()
            encoding = "utf-16" if data.startswith((b"\xff\xfe", b"\xfe\xff")) else "utf-8"
            content = data.decode(encoding)
            if "@" in content:
                raise ValueError("Nested response files are outside the release linker contract")
            responses[argument] = (content, encoding)
    texts = [responses[arg][0] if arg in responses else arg for arg in arguments]
    directories = list(dict.fromkeys(match.group() for text in texts for match in TEMP.finditer(text)))
    if not directories:
        return subprocess.call(["lld-link", *arguments])
    outputs = [match.group(1) for text in texts for match in OUTPUT.finditer(text)]
    if len(outputs) != 1:
        raise ValueError("Release linker requires one output under /build/target")
    # Output identity separates concurrent Cargo links. Exclusive creation fails
    # on collisions or stale state rather than sharing or deleting another link.
    identity = hashlib.sha256(outputs[0].encode()).hexdigest()
    work = Path("/build/target") / (".link-" + identity)
    work.mkdir(mode=0o700)
    try:
        replacements = {}
        for index, directory in enumerate(directories):
            destination = work / str(index)
            shutil.copytree(directory, destination)
            replacements[directory] = str(destination)

        def rewrite(text):
            return TEMP.sub(lambda match: replacements[match.group()], text)

        rewritten = []
        for index, argument in enumerate(arguments):
            if argument in responses:
                content, encoding = responses[argument]
                response = work / f"arguments-{index}.rsp"
                response.write_bytes(rewrite(content).encode(encoding))
                rewritten.append("@" + str(response))
            else:
                rewritten.append(rewrite(argument))
        return subprocess.call(["lld-link", *rewritten])
    finally:
        shutil.rmtree(work)


if __name__ == "__main__":
    sys.exit(link(sys.argv[1:]))

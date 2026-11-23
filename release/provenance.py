#!/usr/bin/env python3
"""Write the in-toto statement that GitLab's rebuild signs: every release file that it packaged,
and the Apple compiler outputs, which only Apple hardware builds, that it took from GitHub's build."""

import argparse
import json
import os
import sys
from datetime import datetime, timezone
from pathlib import Path

sys.dont_write_bytecode = True

from artifacts import MANIFEST, digest


def statement(packages, apple, environment):
    manifest = json.loads((packages / MANIFEST).read_text())
    project, tag = environment["CI_PROJECT_URL"], environment["CI_COMMIT_TAG"]
    return {
        "_type": "https://in-toto.io/Statement/v1",
        "subject": [
            *(
                {"name": artifact["name"], "digest": {"sha256": artifact["sha256"]}}
                for artifact in manifest["artifacts"]
            ),
            {"name": MANIFEST, "digest": {"sha256": digest(packages / MANIFEST)}},
        ],
        "predicateType": "https://slsa.dev/provenance/v1",
        "predicate": {
            "buildDefinition": {
                "buildType": "https://stogas.ai/docs/reproducible-builds#rebuild-an-sdk-release",
                "externalParameters": {
                    "source": project,
                    "ref": f"refs/tags/{tag}",
                    "configuration": ".gitlab-ci.yml",
                },
                "resolvedDependencies": [
                    {
                        "uri": f"git+{project}@refs/tags/{tag}",
                        "digest": {"gitCommit": environment["CI_COMMIT_SHA"]},
                    },
                    *(
                        {"name": path.name, "digest": {"sha256": digest(path)}}
                        for path in sorted(apple.iterdir())
                    ),
                ],
            },
            "runDetails": {
                "builder": {"id": f"{project}/-/runners/{environment['CI_RUNNER_ID']}"},
                "metadata": {
                    # Several jobs of one pipeline build the files.
                    "invocationId": environment["CI_PIPELINE_URL"],
                    "startedOn": environment["CI_PIPELINE_CREATED_AT"],
                    "finishedOn": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
                },
            },
        },
    }


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("packages", type=Path, help="The packages that release.py rebuild wrote")
    parser.add_argument("apple", type=Path, help="The Apple compiler outputs that the rebuild took")
    args = parser.parse_args()
    print(json.dumps(statement(args.packages, args.apple, os.environ), indent=2))

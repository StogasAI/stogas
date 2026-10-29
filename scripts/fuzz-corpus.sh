#!/usr/bin/env bash
# Adds to DIR the newest corpus that a fuzz campaign kept for TARGET. Campaigns
# keep their corpora as artifacts for 90 days, because GitHub drops the least
# recently used caches once a repository's caches pass 10 GB.
set -euo pipefail
shopt -s nullglob
dir=$1
target=$2
mkdir -p "$dir"
# Only this repository's own runs count, so a pull request from a fork that
# changed the workflow cannot supply a corpus.
run=$(gh api "repos/$GITHUB_REPOSITORY/actions/artifacts?name=fuzz-corpus-$target&per_page=100" \
	--jq '[.artifacts[] | select((.expired | not) and .workflow_run.head_repository_id == .workflow_run.repository_id)]
		| max_by(.created_at) | .workflow_run.id // empty')
if [ -z "$run" ]; then
	echo "No campaign kept a corpus for $target; only its committed seeds run." >&2
	exit 0
fi
kept=$(mktemp -d)
trap 'rm -rf "$kept"' EXIT
gh run download "$run" --repo "$GITHUB_REPOSITORY" --name "fuzz-corpus-$target" --dir "$kept"
count=0
for file in "$kept"/*; do
	# The checkout's named seeds stay as they are.
	[ -e "$dir/${file##*/}" ] || { mv "$file" "$dir/" && count=$((count + 1)); }
done
echo "Added $count inputs that run $run kept for $target."

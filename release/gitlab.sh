# GitLab's rebuild of a release tag, which .gitlab-ci.yml runs with only the variables it names:
# `build <os>` builds the platforms of one operating system, and `attest` packages every release
# file with the Apple compiler outputs of GitHub's build and signs a build proof for every file.
set -eu
apk add --no-cache curl python3
test "$(git rev-parse HEAD)" = "$CI_COMMIT_SHA"
# The attest job's checkout also holds the build jobs' archives.
test -z "$(git status --porcelain --untracked-files=no)"

dockerd-entrypoint.sh dockerd --host=unix:///var/run/docker.sock > /builds/dockerd.log 2>&1 &
for _ in $(seq 60); do
	docker info > /dev/null 2>&1 && break
	sleep 1
done
docker info --format 'Docker {{.ServerVersion}} on {{.Driver}}: {{.NCPU}} CPUs, {{.MemTotal}} bytes'
df -h /builds /var/lib/docker

if [ "$1" = build ]; then
	os=$2
	# targets.json names the operating system of each platform, and the portable package is its own.
	# shellcheck disable=SC2046 # Platform names hold no spaces.
	set -- $(python3 -B -c 'import json, sys
targets = {**json.load(open("release/targets.json"))["targets"], "portable": {"os": "portable"}}
print(*(f"--platform={name}" for name, target in targets.items() if target["os"] == sys.argv[1]))' "$os")
	mkdir native
	python3 -B release/release.py build "$@" --out /builds/native --archive "native/$os.tar.gz"
	df -h /builds
	exit
fi

test "$1" = attest
curl --fail --location --silent --show-error --header "JOB-TOKEN: $CI_JOB_TOKEN" \
	--output /builds/apple.tar \
	"$CI_API_V4_URL/projects/$CI_PROJECT_ID/packages/generic/inputs/${CI_COMMIT_TAG#v}/apple.tar"
# Stogas uploads these files, so they extract only inside their own directory.
python3 -B -c 'import sys, tarfile; tarfile.open(sys.argv[1]).extractall(sys.argv[2], filter="data")' \
	/builds/apple.tar /builds/apple
python3 -B release/release.py rebuild /builds/apple --out /builds/rebuild --builds native/*.tar.gz
python3 -B release/provenance.py /builds/rebuild/release/packages /builds/apple > /builds/statement.json

curl --fail --location --silent --show-error --output /usr/local/bin/cosign \
	https://github.com/sigstore/cosign/releases/download/v3.1.4/cosign-linux-amd64
echo '424e2c97d0b45fd7a6b608a87f090f35633f4c23ece5f092d48bba11aaf4bbfa  /usr/local/bin/cosign' |
	sha256sum -c
chmod 755 /usr/local/bin/cosign
# Cosign signs with a Fulcio certificate for the job's ID token and logs the proof in Rekor.
cosign attest-blob --statement /builds/statement.json --bundle gitlab-attestation.jsonl --yes

#!/bin/bash
# agent-prep.sh ARM: the last steps before an agent arm is isolated. Needs CODEX_AUTH_KEY (for the seed),
# GITHUB_REF_NAME, SAMPLE and sudo. It draws this sample's app, serves it as the user `nobody` from a
# folder only that user can read, checks that every flaw of its key reproduces, restarts it fresh, captures
# the journey, puts the two HAR files and the brief where the review expects them ($HOME/trial/har,
# $HOME/ci/brief.md) and deletes the key and the generated files from this machine. The key is drawn again
# after the review (agent-post.sh) to grade it, so it is never on disk while the agent works.
set -euo pipefail
here=$(cd "$(dirname "$0")" && pwd)
arm=${1:?usage: agent-prep.sh usual|azhaq}
port=8090
. "$here/appctl.sh"
seed=$("$here/seed.sh" "$GITHUB_REF_NAME" "${SAMPLE:?}")
echo "::add-mask::$seed"
gen=$(mktemp -d)
har=$(mktemp -d)
python3 "$here/gen.py" "$seed" --out "$gen"
sudo install -d -o nobody -g nogroup -m 700 /opt/azq
sudo install -m 600 -o nobody -g nogroup "$gen/app.json" "$here/server.py" "$here/authzlib.py" /opt/azq/
sudo install -d -o nobody -g nogroup -m 755 /opt/azq-count
url=http://127.0.0.1:$port
app_start /opt/azq "$port" /opt/azq-count/count nobody /opt/azq
python3 "$here/selfcheck.py" "$gen" "$url"
app_stop "$port" nobody
app_start /opt/azq "$port" /opt/azq-count/count nobody /opt/azq
python3 "$here/journey.py" "$gen" "$url" --out "$har"
mkdir -p "$HOME/trial/har" "$HOME/ci"
u1=$(jq -r '.accounts.alice.user' "$gen/vars.json")
cp "$har/alice.har" "$HOME/trial/har/$u1.har"
cp "$har/admin.har" "$HOME/trial/har/admin.har"
python3 "$here/brief.py" "$arm" "$gen/vars.json" "$url" > "$HOME/ci/brief.md"
cat /opt/azq-count/count > "$HOME/ci/count.before"
find "$gen" "$har" -type f -exec shred -u {} + 2> /dev/null || true
rm -rf "$gen" "$har"
echo "agent-prep: app up, captures and brief in place"

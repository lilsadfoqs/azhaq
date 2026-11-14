#!/bin/bash
# agent-post.sh ARM: after an agent arm ended (a fresh checkout, the source was removed before the review).
# Draws the sample's app again for its key, collects what the review wrote, grades it, encrypts the lot to
# $AGE_RECIPIENT and publishes it under exp-authz/TAG/sN/. Needs CODEX_AUTH_KEY, GITHUB_TOKEN,
# GITHUB_REF_NAME, SAMPLE, AGE_RECIPIENT. stdout holds counts only.
set -uo pipefail
here=$(cd "$(dirname "$0")" && pwd)
arm=${1:?usage: agent-post.sh usual|azhaq}
seed=$("$here/seed.sh" "$GITHUB_REF_NAME" "${SAMPLE:?}")
echo "::add-mask::$seed"
work=$(mktemp -d)
out=$work/$arm
mkdir -p "$out"
python3 "$here/gen.py" "$seed" --out "$work/gen" > /dev/null
cp "$work/gen/key.json" "$out/key.json"
t=$HOME/trial
ci=$HOME/ci
for f in findings.jsonl REPORT.md; do [ -f "$t/$f" ] && [ ! -L "$t/$f" ] && head -c 4194304 "$t/$f" > "$out/$f"; done
cp /var/tmp/azq-watch/watch.jsonl "$out/watch.jsonl" 2> /dev/null || true
for f in start.epoch end.epoch stderr.txt; do [ -f "$ci/$f" ] && cp "$ci/$f" "$out/$f"; done
[ -f "$ci/stream.ts.jsonl" ] && gzip -9 -c "$ci/stream.ts.jsonl" > "$out/stream.ts.jsonl.gz"
[ -d "$t/notes" ] && tar czf "$out/notes.tgz" -C "$t" --exclude='*.db' notes 2> /dev/null
before=$(cat "$ci/count.before" 2> /dev/null || echo 0)
after=$(cat /opt/azq-count/count 2> /dev/null || echo 0)
printf '{"server_requests": %d}\n' "$((after - before))" > "$out/meta.json"
python3 "$here/grade.py" "$out/key.json" "$out" --arm agent || echo "agent-post: grading failed"
dest=$work/pub
mkdir -p "$dest"
tar czf "$dest/$arm.tgz" -C "$work" "$arm"
age -r "$AGE_RECIPIENT" -o "$dest/$arm.tgz.age" "$dest/$arm.tgz"
rm -f "$dest/$arm.tgz"
files=("$dest/$arm.tgz.age")
if [ -s "$HOME/.codex/auth.json" ] && [ "$(sha256sum "$HOME/.codex/auth.json" | cut -d' ' -f1)" != "$(cat "$RUNNER_TEMP/auth.sum" 2> /dev/null)" ]; then
  age -r "$AGE_RECIPIENT" -o "$dest/$arm.codex-auth.json.age" "$HOME/.codex/auth.json"
  files+=("$dest/$arm.codex-auth.json.age")
fi
"$here/../../publish.sh" "exp-authz/$GITHUB_REF_NAME/s$SAMPLE" "${files[@]}"

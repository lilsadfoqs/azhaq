#!/bin/bash
# fetch.sh bench|hunt|gate|trial|range-smoke NAME DIR: copies what the CI run
# KIND-NAME put on the ci-results branch into DIR, decrypts and unpacks it,
# and puts back a Codex session the run refreshed, when it is newer than
# this machine's. A research or hunter trial's answer key comes back as
# DIR/key.json (grade it: python3 .github/ci/range/grade.py DIR/key.json DIR).
# Then usage.py counts which commands and flags the run used and writes
# DIR/usage.json (skipped without python3 or azhaq); to count every run
# fetched into one folder: usage.py FOLDER <(azhaq help -json).
# A gate (run.sh gate NAME) is two runs on one commit, bench/gate-NAME and
# hunt/gate-NAME: they are fetched into DIR/bench and DIR/hunt.
# A trial's gate or baseline kind publishes under a part instead of flat
# (trial/trial-NAME/a, /b, or /a1../a4 and /b1../b4 for samples=N -
# .github/ci/trial/README.md): fetch.sh trial NAME DIR brings every part back
# into DIR/a, DIR/b (and so on), each decrypted and unpacked the same way:
# trial.tgz.age is unpacked, key.json.age and scores.json.age are decrypted
# to key.json and scores.json. One part alone: FETCH_TAG=trial-NAME/PART
# fetch.sh trial NAME DIR.
set -euo pipefail
here=$(cd "$(dirname "$0")" && pwd)
kind=${1:?usage: fetch.sh bench|hunt|gate|trial|range-smoke NAME DIR}
name=${2:?usage: fetch.sh bench|hunt|gate|trial|range-smoke NAME DIR}
dir=${3:?usage: fetch.sh bench|hunt|gate|trial|range-smoke NAME DIR}
if [ "$kind" = gate ]; then
  rc=0
  for part in bench hunt; do
    FETCH_TAG=gate-$name "$0" "$part" "$name" "$dir/$part" || rc=1
  done
  exit $rc
fi
tag=${FETCH_TAG:-$kind-$name} # the tag, and the folder under $kind/
key=${AZHAQ_AGE_KEY:-$HOME/.config/azhaq/age.key}
age=$(command -v age || echo "$HOME/go/bin/age")
repo=lilsadfoqs/azhaq
mkdir -p "$dir"
dir=$(cd "$dir" && pwd) # absolute: a part's folder is DIR/PART whatever the working directory
cd "$dir"
listing=$(curl -fsS "https://api.github.com/repos/$repo/contents/$kind/$tag?ref=ci-results")
if [ "$kind" = trial ]; then
  parts=$(printf '%s' "$listing" | python3 -I -c 'import sys, json
d = json.load(sys.stdin)
print("\n".join(f["name"] for f in d if isinstance(d, list) and f.get("type") == "dir"))' 2>/dev/null || true)
  if [ -n "$parts" ]; then
    rc=0
    while IFS= read -r part; do
      [ -n "$part" ] || continue
      FETCH_TAG="$tag/$part" "$here/fetch.sh" "$kind" "$name" "$dir/$part" || rc=1
    done <<<"$parts"
    exit $rc
  fi
fi
printf '%s' "$listing" |
  python3 -I -c 'import sys, json; [print(f["name"]) for f in json.load(sys.stdin)]' |
  while read -r f; do
    curl -fsSL -o "$f" "https://raw.githubusercontent.com/$repo/ci-results/$kind/$tag/$f"
  done
for f in *.age; do
  [ -e "$f" ] || continue
  case $f in
  *codex-auth.json.age) ;;
  key.json.age) "$age" -d -i "$key" -o key.json "$f" ;;
  scores.json.age) "$age" -d -i "$key" -o scores.json "$f" ;; # .github/ci/history.sh reads these
  *) "$age" -d -i "$key" -o "${f%.age}" "$f" && tar -xzf "${f%.age}" ;;
  esac
done
# The newest session any job refreshed replaces this machine's older one.
local_auth=${CODEX_HOME:-$HOME/.codex}/auth.json
for f in *codex-auth.json.age; do
  [ -e "$f" ] || continue
  (umask 077 && "$age" -d -i "$key" -o "$f.json" "$f")
  if python3 -I -c 'import sys, json; a = json.load(open(sys.argv[1])).get("last_refresh", ""); b = json.load(open(sys.argv[2])).get("last_refresh", ""); sys.exit(0 if a > b else 1)' "$f.json" "$local_auth"; then
    cp -p "$local_auth" "$local_auth.before-ci"
    (umask 077 && cp "$f.json" "$local_auth")
    echo "fetch.sh: the run refreshed the Codex session; $local_auth now holds it (the old one is $local_auth.before-ci)"
  fi
  rm -f "$f.json"
done
ls -la
if command -v python3 >/dev/null 2>&1 && command -v azhaq >/dev/null 2>&1; then
  if azhaq help -json >.usage-help.json 2>/dev/null; then
    python3 -I "$here/usage.py" -1 . .usage-help.json || echo "fetch.sh: usage.py failed; the results are fetched" >&2
  fi
  rm -f .usage-help.json
fi

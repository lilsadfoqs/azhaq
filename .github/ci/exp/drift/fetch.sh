#!/bin/bash
# fetch.sh TAG DIR: copies what the run exp-drift-NAME (TAG, with or without the
# prefix) put on the ci-results branch (exp-drift/TAG/sN/) into DIR/sN, decrypts
# it with this machine's age key and unpacks it: DIR/sN holds the answer key,
# every arm's raw output per epoch, grade.json and grade.md. Prints only the
# folders. Put a Codex session the run refreshed back, when it is newer than
# this machine's, as fetch.sh of the trial does. Read only: nothing is pushed.
# AZHAQ_AGE_KEY names another age key; the key is never printed.
# Then: python3 .github/ci/exp/drift/summary.py DIR
set -euo pipefail
tag=${1:?usage: fetch.sh TAG DIR}
tag=exp-drift-${tag#exp-drift-}
dir=${2:?usage: fetch.sh TAG DIR}
key=${AZHAQ_AGE_KEY:-$HOME/.config/azhaq/age.key}
age=$(command -v age || echo "$HOME/go/bin/age")
repo=lilsadfoqs/azhaq
mkdir -p "$dir"
dir=$(cd "$dir" && pwd)
listing=$(curl -fsS "https://api.github.com/repos/$repo/contents/exp-drift/$tag?ref=ci-results")
samples=$(printf '%s' "$listing" | python3 -I -c 'import sys, json
d = json.load(sys.stdin)
print("\n".join(f["name"] for f in d if isinstance(d, list) and f.get("type") == "dir"))')
[ -n "$samples" ] || { echo "fetch.sh: no samples under exp-drift/$tag (the run may still be going)" >&2; exit 1; }
local_auth=${CODEX_HOME:-$HOME/.codex}/auth.json
while IFS= read -r s; do
  [ -n "$s" ] || continue
  mkdir -p "$dir/$s"
  curl -fsS "https://api.github.com/repos/$repo/contents/exp-drift/$tag/$s?ref=ci-results" |
    python3 -I -c 'import sys, json; [print(f["name"]) for f in json.load(sys.stdin)]' |
    while IFS= read -r f; do
      curl -fsSL -o "$dir/$s/$f" "https://raw.githubusercontent.com/$repo/ci-results/exp-drift/$tag/$s/$f"
    done
  (
    cd "$dir/$s"
    for f in *.age; do
      [ -e "$f" ] || continue
      case $f in
      *codex-auth.json.age) ;;
      results.tgz.age) "$age" -d -i "$key" -o results.tgz "$f" && tar -xzf results.tgz ;;
      *) "$age" -d -i "$key" -o "${f%.age}" "$f" ;;
      esac
    done
    # The newest session any job refreshed replaces this machine's older one.
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
  )
  echo "$dir/$s"
done <<<"$samples"

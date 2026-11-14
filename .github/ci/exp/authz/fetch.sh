#!/bin/bash
# fetch.sh TAG DIR: brings back what the CI run exp-authz-TAG (or TAG when it already starts with exp-authz-)
# put on the ci-results branch under exp-authz/TAG/sN/, decrypts it with the maintainer's age key and unpacks it:
# DIR/sN/{key.json,app.json,vars.json,har,b1,b2} from the toolfree job, DIR/sN/usual and DIR/sN/azhaq from the
# agent jobs. A Codex session an agent job refreshed replaces this machine's when it is newer. The key is read
# from $AZHAQ_AGE_KEY (default ~/.config/azhaq/age.key) and never printed. Then python3 summary.py DIR.
set -euo pipefail
tag=${1:?usage: fetch.sh TAG DIR}
dir=${2:?usage: fetch.sh TAG DIR}
case $tag in exp-authz-*) ;; *) tag=exp-authz-$tag ;; esac
key=${AZHAQ_AGE_KEY:-$HOME/.config/azhaq/age.key}
age=$(command -v age || echo "$HOME/go/bin/age")
repo=lilsadfoqs/azhaq
mkdir -p "$dir"
dir=$(cd "$dir" && pwd)
list() { curl -fsS "https://api.github.com/repos/$repo/contents/$1?ref=ci-results"; }
names() { python3 -I -c 'import sys, json
d = json.load(sys.stdin)
for f in d:
    if f.get("type") == sys.argv[1]:
        print(f["name"])' "$1"; }
samples=$(list "exp-authz/$tag" | names dir)
[ -n "$samples" ] || { echo "fetch.sh: nothing under exp-authz/$tag on ci-results" >&2; exit 1; }
local_auth=${CODEX_HOME:-$HOME/.codex}/auth.json
for s in $samples; do
  d=$dir/$s
  mkdir -p "$d"
  for f in $(list "exp-authz/$tag/$s" | names file); do
    curl -fsSL -o "$d/$f" "https://raw.githubusercontent.com/$repo/ci-results/exp-authz/$tag/$s/$f"
    case $f in
    *codex-auth.json.age)
      (umask 077 && "$age" -d -i "$key" -o "$d/$f.json" "$d/$f")
      if python3 -I -c 'import sys, json; a = json.load(open(sys.argv[1])).get("last_refresh", ""); b = json.load(open(sys.argv[2])).get("last_refresh", ""); sys.exit(0 if a > b else 1)' "$d/$f.json" "$local_auth"; then
        cp -p "$local_auth" "$local_auth.before-ci"
        (umask 077 && cp "$d/$f.json" "$local_auth")
        echo "fetch.sh: the run refreshed the Codex session; $local_auth now holds it (the old one is $local_auth.before-ci)"
      fi
      rm -f "$d/$f.json" "$d/$f"
      ;;
    *.tgz.age)
      "$age" -d -i "$key" -o "$d/${f%.age}" "$d/$f" && tar -xzf "$d/${f%.age}" -C "$d" && rm -f "$d/${f%.age}"
      ;;
    esac
  done
  echo "fetched $s: $(ls "$d" | grep -v '\.age$' | tr '\n' ' ')"
done
echo "now: python3 $(cd "$(dirname "$0")" && pwd)/summary.py $dir"

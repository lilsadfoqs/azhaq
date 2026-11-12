#!/bin/bash
# fetch.sh NAME DIR: copies what the parity run parity-NAME put on the ci-results
# branch (parity/NAME/sK/) into DIR/sK, decrypts it with this machine's age key
# and prints the aggregate table of all samples: summary.py's, nothing else; then
# the same table for the worklist view (hunt's default rows as the only leads).
# What the maintainer reads stays in DIR: the answer key, azhaq's raw outputs,
# the leads and grade.py's full grade, per sample (DIR/sK/graded/grade.md).
# Read only: nothing is pushed or deleted. AZHAQ_AGE_KEY names another age key.
set -euo pipefail
here=$(cd "$(dirname "$0")" && pwd)
name=${1:?usage: fetch.sh NAME DIR}
dir=${2:?usage: fetch.sh NAME DIR}
key=${AZHAQ_AGE_KEY:-$HOME/.config/azhaq/age.key}
age=$(command -v age || echo "$HOME/go/bin/age")
repo=lilsadfoqs/azhaq
mkdir -p "$dir"
dir=$(cd "$dir" && pwd)
listing=$(curl -fsS "https://api.github.com/repos/$repo/contents/parity/$name?ref=ci-results")
samples=$(printf '%s' "$listing" | python3 -I -c 'import sys, json
d = json.load(sys.stdin)
print("\n".join(f["name"] for f in d if isinstance(d, list) and f.get("type") == "dir"))')
[ -n "$samples" ] || { echo "fetch.sh: no samples under parity/$name (the run may still be going)" >&2; exit 1; }
summaries=()
worklists=()
while IFS= read -r s; do
  [ -n "$s" ] || continue
  mkdir -p "$dir/$s"
  files=$(curl -fsS "https://api.github.com/repos/$repo/contents/parity/$name/$s?ref=ci-results" |
    python3 -I -c 'import sys, json; [print(f["name"]) for f in json.load(sys.stdin)]')
  while IFS= read -r f; do
    curl -fsSL -o "$dir/$s/$f" "https://raw.githubusercontent.com/$repo/ci-results/parity/$name/$s/$f"
  done <<<"$files"
  cd "$dir/$s"
  for f in *.age; do
    [ -e "$f" ] || continue
    case $f in
    key.json.age | summary.json.age | summary-worklist.json.age) "$age" -d -i "$key" -o "${f%.age}" "$f" ;;
    *) "$age" -d -i "$key" -o "${f%.age}" "$f" && tar -xzf "${f%.age}" ;;
    esac
  done
  [ -s summary.json ] && summaries+=("$dir/$s/summary.json") || echo "fetch.sh: $s has no summary (its replay failed; see $dir/$s)" >&2
  [ -s summary-worklist.json ] && worklists+=("$dir/$s/summary-worklist.json")
done <<<"$samples"
[ "${#summaries[@]}" -gt 0 ] || { echo "fetch.sh: no sample has a summary" >&2; exit 1; }
python3 -I "$here/summary.py" agg "${summaries[@]}"
if [ "${#worklists[@]}" -gt 0 ]; then
  echo
  echo "worklist view (hunt's default rows as the only leads):"
  python3 -I "$here/summary.py" agg "${worklists[@]}"
fi

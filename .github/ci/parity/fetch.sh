#!/bin/bash
# fetch.sh NAME DIR: copies what the parity run parity-NAME put on the ci-results
# branch (parity/NAME/sK/) into DIR/sK, decrypts it with this machine's age key
# and prints the aggregate table of all samples: summary.py's, nothing else; then
# the same table for the worklist view (hunt's default rows as the only leads),
# and ident.py's: how often the product and version of a found service are named.
# What the maintainer reads stays in DIR: the answer key, azhaq's raw outputs,
# the leads and grade.py's full grade, per sample (DIR/sK/graded/grade.md).
# A sample made with pairs=1 also has DIR/sK/pair/ (export-run1.jsonl and
# export-run2.jsonl: the exports of the two runs of its workspace, watch.json:
# what watch reported between them); fetch.sh counts them and says how to replay
# them: AZHAQ_REPLAY_DIR=DIR, as README.md ("Run pairs") gives.
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
idents=()
stacks=()
pairs=0
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
    key.json.age | summary.json.age | summary-worklist.json.age | ident.json.age | ident-stack.json.age) "$age" -d -i "$key" -o "${f%.age}" "$f" ;;
    *) "$age" -d -i "$key" -o "${f%.age}" "$f" && tar -xzf "${f%.age}" ;;
    esac
  done
  [ -s summary.json ] && summaries+=("$dir/$s/summary.json") || echo "fetch.sh: $s has no summary (its replay failed; see $dir/$s)" >&2
  [ -s summary-worklist.json ] && worklists+=("$dir/$s/summary-worklist.json")
  [ -s ident.json ] && idents+=("$dir/$s/ident.json")
  [ -s ident-stack.json ] && stacks+=("$dir/$s/ident-stack.json")
  if [ -e pair/pair.json ]; then
    if [ -s pair/export-run1.jsonl ] && [ -s pair/export-run2.jsonl ]; then
      pairs=$((pairs + 1))
    else
      echo "fetch.sh: $s has a pair folder with an empty export (see $dir/$s/pair/pair.json)" >&2
    fi
  fi
done <<<"$samples"
[ "${#summaries[@]}" -gt 0 ] || { echo "fetch.sh: no sample has a summary" >&2; exit 1; }
python3 -I "$here/summary.py" agg "${summaries[@]}"
if [ "${#worklists[@]}" -gt 0 ]; then
  echo
  echo "worklist view (hunt's default rows as the only leads):"
  python3 -I "$here/summary.py" agg "${worklists[@]}"
fi
if [ "${#idents[@]}" -gt 0 ]; then
  echo
  echo "product and version named (ident.py; the misses are in DIR/sK/graded/ident-misses.jsonl):"
  python3 -I "$here/ident.py" agg "${idents[@]}"
fi
if [ "${#stacks[@]}" -gt 0 ]; then
  echo
  echo "the same services named by nmap -sV, httpx -td and nuclei's tech and panel templates (stack.sh):"
  python3 -I "$here/ident.py" agg "${stacks[@]}"
fi
if [ "$pairs" -gt 0 ]; then
  echo
  echo "run pairs: $pairs of ${#summaries[@]} samples; replay them with"
  echo "  AZHAQ_REPLAY_DIR=$dir go test ./cmd/azhaq ./internal/portscan ./internal/httprow -run 'TestReplay(ed|Recorded|ANewPort|RunPairs)'"
fi

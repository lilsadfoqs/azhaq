#!/bin/bash
# history.sh [N]: prints the history of the review scores: each item across the
# last N reviews (default 10), with the spread between the samples of a review.
# The records are the scores.json.age files the trial workflow puts beside a
# review's results on ci-results, encrypted to the maintainer's key (AZHAQ_AGE_KEY,
# default ~/.config/azhaq/age.key); only they are fetched, not the reviews' archives.
# Reviews from before the records have none: fetch.sh brings one back, and
# `python3 .github/ci/range/scores.py history DIR` reads its REPORT.md.
set -euo pipefail
here=$(cd "$(dirname "$0")" && pwd)
last=${1:-10}
key=${AZHAQ_AGE_KEY:-$HOME/.config/azhaq/age.key}
age=$(command -v age || echo "$HOME/go/bin/age")
repo=${AZHAQ_REPO:-lilsadfoqs/azhaq}
tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT
# One request lists every path of the branch's trial/ folder, with no blobs.
git clone -q --depth 1 --filter=blob:none --no-checkout --branch ci-results "https://github.com/$repo.git" "$tmp/tree"
n=0
while IFS= read -r path; do
  dir=${path%/scores.json.age}
  mkdir -p "$tmp/records/$dir"
  curl -fsSL -o "$tmp/records/$dir/scores.json.age" "https://raw.githubusercontent.com/$repo/ci-results/$path"
  "$age" -d -i "$key" -o "$tmp/records/$dir/scores.json" "$tmp/records/$dir/scores.json.age"
  n=$((n + 1))
done < <(git -C "$tmp/tree" ls-tree -r --name-only HEAD trial | grep '/scores\.json\.age$')
[ "$n" -gt 0 ] || { echo "history.sh: no scores record on ci-results yet (the review workflow writes one for each part)" >&2; exit 1; }
python3 -I "$here/range/scores.py" history "$tmp/records" --last "$last"

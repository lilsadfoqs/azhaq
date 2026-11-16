#!/bin/bash
# pair.sh OUT DOMAIN NET DNS [MINUTES]: the second run of a run pair (parity's
# pairs=1), after replay.sh has run and exported the first. It asks what a
# watch cycle asks: `azhaq watch -db DB -json -- RUN OPTIONS`, which is the run
# options plus -db DB -quiet and then the comparison of the last two runs, into
# the workspace replay.sh made (OUT/work/workspace.db), against the network as
# it stands. The options are replay.sh's, with the same cap.
#
# Files, all under OUT/pair, none printed:
#   watch.json         the change set watch reported between the two runs
#   watch.err          the second run's report and any error
#   export-run1.jsonl  azhaq export -format jsonl -run ID, for the first run
#   export-run2.jsonl  the same for the second
#   pair.json          exit codes, row counts and the number of change lines
# The workspace holds exactly these two runs, or pair.sh fails. The exports are
# what cmd/azhaq/replay_test.go reads as a run pair (AZHAQ_REPLAY_DIR).
set -uo pipefail
out=${1:?usage: pair.sh OUT DOMAIN NET DNS [MINUTES]}
domain=${2:?usage: pair.sh OUT DOMAIN NET DNS [MINUTES]}
net=${3:?usage: pair.sh OUT DOMAIN NET DNS [MINUTES]}
dns=${4:?usage: pair.sh OUT DOMAIN NET DNS [MINUTES]}
minutes=${5:-30}
azhaq=${AZHAQ:-azhaq}
case $minutes in '' | *[!0-9]*) echo "pair.sh: MINUTES must be a whole number" >&2; exit 2 ;; esac
[ "$minutes" -ge 1 ] || { echo "pair.sh: MINUTES must be at least 1" >&2; exit 2; }
cap=$((minutes * 60))
out=$(cd "$out" && pwd)
db=$out/work/workspace.db
[ -s "$db" ] || { echo "pair.sh: no workspace at OUT/work/workspace.db: run replay.sh first" >&2; exit 1; }
pair=$out/pair
mkdir -p "$pair"
cd "$out/work" # the folder replay.sh ran in

# The same options as replay.sh's, with no flag chosen for the network.
flags=(-domain "$domain" -cidr "$net" -allow "$domain" -allow "$net" -resolvers "$dns" -ports default -verify)

timeout -k 30 $((cap + 180)) "$azhaq" watch -db "$db" -json -- "${flags[@]}" -max-time "${cap}s" > "$pair/watch.json" 2> "$pair/watch.err"
watch_rc=$?

# Newest first: the second run, then the first.
ids=$(timeout 300 "$azhaq" query -db "$db" -runs -json 2> "$pair/runs.err" | jq -r 'select(.run_id) | .run_id')
rm -f "$pair/runs.err"
if [ "$(printf '%s\n' "$ids" | grep -c .)" -ne 2 ]; then
  echo "pair.sh: the workspace holds $(printf '%s\n' "$ids" | grep -c .) runs, not 2" >&2
  exit 1
fi
run2=$(printf '%s\n' "$ids" | sed -n 1p)
run1=$(printf '%s\n' "$ids" | sed -n 2p)
timeout 300 "$azhaq" export -db "$db" -format jsonl -run "$run1" > "$pair/export-run1.jsonl" 2> "$pair/export1.err"
export1_rc=$?
timeout 300 "$azhaq" export -db "$db" -format jsonl -run "$run2" > "$pair/export-run2.jsonl" 2> "$pair/export2.err"
export2_rc=$?

rows1=$(wc -l < "$pair/export-run1.jsonl")
rows2=$(wc -l < "$pair/export-run2.jsonl")
# The change set is one JSON object; the lines it lists are the strings in its arrays.
changes=$(jq -s '[.[] | select(type == "object" and has("db")) | [.[] | arrays | length] | add // 0] | add // 0' "$pair/watch.json" 2> /dev/null || echo 0)
printf '{"watch_exit":%d,"export1_exit":%d,"export2_exit":%d,"rows1":%d,"rows2":%d,"change_lines":%d}\n' \
  "$watch_rc" "$export1_rc" "$export2_rc" "$rows1" "$rows2" "${changes:-0}" > "$pair/pair.json"
# Exit 0 and 4 are a finished second run and one the cap stopped; a change set is no failure.
[ "$export1_rc" -eq 0 ] && [ "$export2_rc" -eq 0 ] && [ "$rows1" -gt 0 ] && [ "$rows2" -gt 0 ]

#!/bin/bash
# replay.sh OUT DOMAIN NET DNS [MINUTES]: the flow azhaq's docs give for an
# external assessment of a domain and an address range, with a resolver, run
# unattended and with no flag chosen for the estate. AZHAQ names the binary
# (default: azhaq on the path). Everything goes to OUT; OUT/replay.json says
# when it started and ended and how each command exited. The caller grades.
#
# The commands, and where the docs give them:
#   plan    README "One workflow" and docs/RECIPES.md "Make a first map": plan first, sends nothing
#   run     README "One workflow" (run, then hunt), docs/commands/run.md and docs/START.md:
#             -domain D -cidr NET   the seeds: a domain and an address range
#             -allow D -allow NET   the fence START.md puts on every run
#             -resolvers DNS        the resolver the client gave (run.md: named resolvers answer .test too)
#             -ports default        run.md: "default (the top 100 and the usual ports of the services azhaq names
#                                   and checks)"; with no -ports a run scans none
#             -verify               run.md and docs/CONCEPTS.md "Read-only verification": the read-only checks of
#                                   the services found; no payload, no credential
#             -max-time             the cap on the whole replay (run.md: stops in any phase, exit 4)
#             -db                   a workspace, as every example has
#           No -rate or -max-requests: the docs' examples set them for a program's scope, and the default is
#           unpaced. -advisories is left out: it needs OSV records the user downloads (START.md job 3), and
#           azhaq ships none.
#   hunt    README "One workflow": where to look first
#   export  docs/commands/export.md: the whole workspace (jsonl) and the findings records
set -uo pipefail
out=${1:?usage: replay.sh OUT DOMAIN NET DNS [MINUTES]}
domain=${2:?usage: replay.sh OUT DOMAIN NET DNS [MINUTES]}
net=${3:?usage: replay.sh OUT DOMAIN NET DNS [MINUTES]}
dns=${4:?usage: replay.sh OUT DOMAIN NET DNS [MINUTES]}
minutes=${5:-30}
azhaq=${AZHAQ:-azhaq}
case $minutes in '' | *[!0-9]*) echo "replay.sh: MINUTES must be a whole number" >&2; exit 2 ;; esac
[ "$minutes" -ge 1 ] || { echo "replay.sh: MINUTES must be at least 1" >&2; exit 2; }
cap=$((minutes * 60))
mkdir -p "$out/work"
out=$(cd "$out" && pwd)
cd "$out/work" # azhaq keeps its run folder and name history in the folder it starts in
db=$out/work/workspace.db

now() { date -u +%FT%TZ; }
flags=(-domain "$domain" -cidr "$net" -allow "$domain" -allow "$net" -resolvers "$dns" -ports default -verify)

start=$(now)
"$azhaq" plan "${flags[@]}" > "$out/plan.txt" 2>&1
plan_rc=$?
# The cap is azhaq's own (-max-time keeps what it found); timeout is the backstop.
timeout -k 30 $((cap + 180)) "$azhaq" run "${flags[@]}" -max-time "${cap}s" -db "$db" > "$out/run.out" 2> "$out/run.err"
run_rc=$?
end=$(now)

timeout 300 "$azhaq" hunt -db "$db" -json -limit 1000 > "$out/hunt.jsonl" 2> "$out/hunt.err"
hunt_rc=$?
timeout 300 "$azhaq" export -db "$db" -format jsonl > "$out/export.jsonl" 2> "$out/export.err"
export_rc=$?
timeout 300 "$azhaq" export -db "$db" -format findings > "$out/findings.jsonl" 2> "$out/findings.err"
findings_rc=$?

printf '{"start":"%s","end":"%s","cap_seconds":%d,"plan_exit":%d,"run_exit":%d,"hunt_exit":%d,"export_exit":%d,"findings_exit":%d}\n' \
  "$start" "$end" "$cap" "$plan_rc" "$run_rc" "$hunt_rc" "$export_rc" "$findings_rc" > "$out/replay.json"
# Exit 0 and 4 are a finished run and a run the cap stopped; the caller reads replay.json for the rest.
[ "$export_rc" -eq 0 ] || exit 1

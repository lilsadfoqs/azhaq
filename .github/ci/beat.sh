#!/bin/bash
# beat.sh trial NAME: prints the heartbeat of the trial tag trial-NAME from
# the ci-results branch (written every 10 minutes by heartbeat.sh while a
# research or hunter trial's review runs).
set -euo pipefail
kind=${1:?usage: beat.sh trial NAME}
name=${2:?usage: beat.sh trial NAME}
[ "$kind" = trial ] || { echo "beat.sh: only a trial has a heartbeat" >&2; exit 2; }
repo=trannghiach/azhaq
curl -fsS "https://raw.githubusercontent.com/$repo/ci-results/trial/trial-$name/heartbeat.txt" ||
  { echo "beat.sh: no heartbeat for trial-$name yet (it starts when the work job isolates the estates)" >&2; exit 1; }

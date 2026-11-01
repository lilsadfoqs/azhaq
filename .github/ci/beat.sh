#!/bin/bash
# beat.sh trial NAME [PART]: prints the heartbeat of the trial tag trial-NAME
# from the ci-results branch (written every 10 minutes by heartbeat.sh while
# a trial's review runs). The gate and baseline kinds publish under a part
# (a, b, or a1/a2/b1/b2 for samples=2 - .github/ci/trial/README.md); give
# PART to read one of them.
set -euo pipefail
kind=${1:?usage: beat.sh trial NAME [PART]}
name=${2:?usage: beat.sh trial NAME [PART]}
part=${3:-}
[ "$kind" = trial ] || { echo "beat.sh: only a trial has a heartbeat" >&2; exit 2; }
repo=lilsadfoqs/azhaq
path="trial/trial-$name${part:+/$part}/heartbeat.txt"
curl -fsS --max-time 30 "https://raw.githubusercontent.com/$repo/ci-results/$path" ||
  { echo "beat.sh: no heartbeat at $path yet (it starts when the job isolates the reviewer; a gate or baseline needs a PART: a, b, a1, a2, b1 or b2)" >&2; exit 1; }

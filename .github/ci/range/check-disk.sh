#!/bin/bash
# check-disk.sh [GB]: fails when / has less free disk than the jobs need
# (default 40 GB). The runners have 88 GB free, so nothing is deleted; a
# smaller runner stops here instead of in the middle of a docker pull.
set -uo pipefail
need=${1:-40}
free=$(df --output=avail -BG / | tail -1 | tr -dc '0-9')
df -h / | tail -1
if [ "${free:-0}" -lt "$need" ]; then
  echo "::error::only ${free:-0} GB free on /, the job needs $need GB; use a runner with a larger disk" >&2
  exit 1
fi

#!/bin/bash
# deploy v1|v2: the deploy lab (labs.sh starts it on 127.0.0.1:5040) serves
# that version from its next request on. v1 is how it starts and what
# `deploy v1` puts back; v2 is the deploy `watch` must report.
set -euo pipefail
case "${1:-}" in
v1 | v2) ;;
*)
  echo "usage: deploy v1|v2" >&2
  exit 2
  ;;
esac
state=${AZQ_DEPLOY_STATE:-$HOME/lab/deploy-app/state}
echo "$1" > "$state"
echo "deployed $1 on http://127.0.0.1:${AZQ_DEPLOY_PORT:-5040}/"

#!/bin/bash
# seed.sh TAG SAMPLE: prints the estate seed of one parity sample, the HMAC-SHA256
# of "TAG:SAMPLE" keyed by CODEX_AUTH_KEY (the secret that keeps trial estates
# private; here it is only a key). Fails when the key is empty, and when the seed
# is the estate of any pool entry (.github/ci/range/pool.json), which the gate
# derives the same way: a parity estate is never one the gate or its baselines use.
set -euo pipefail
here=$(cd "$(dirname "$0")" && pwd)
tag=${1:?usage: seed.sh TAG SAMPLE}
sample=${2:?usage: seed.sh TAG SAMPLE}
key=${CODEX_AUTH_KEY:-}
[ -n "$key" ] || { echo "seed.sh: CODEX_AUTH_KEY is empty, so the seed would not be secret" >&2; exit 1; }
hm() { printf '%s' "$1" | openssl dgst -sha256 -hmac "$key" | sed 's/.* //'; }
seed=$(hm "$tag:$sample")
while IFS= read -r entry; do
  [ -n "$entry" ] || continue
  if [ "$(hm "$entry")" = "$seed" ]; then
    echo "seed.sh: the seed is a pool estate's" >&2
    exit 1
  fi
done < <(python3 -I -c 'import json, sys; print("\n".join(json.load(open(sys.argv[1]))))' "${POOL:-$here/../range/pool.json}")
printf '%s\n' "$seed"

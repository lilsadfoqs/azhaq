#!/bin/bash
# seed.sh TAG SAMPLE: this sample's seed, a keyed hash of the tag name and the sample number. The key is
# the secret CODEX_AUTH_KEY (as range's draw is), so a public tag name does not reveal the app.
set -euo pipefail
printf '%s' "${1:?usage: seed.sh TAG SAMPLE}:${2:?}" | openssl dgst -sha256 -hmac "${CODEX_AUTH_KEY:-none}" | sed 's/.* //' | cut -c1-16

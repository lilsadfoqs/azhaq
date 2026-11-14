#!/bin/bash
# launch.sh NAME [full|dryrun] [samples=N]: starts experiment A by pushing the
# annotated tag exp-drift-NAME on HEAD, as .github/ci/run.sh does for a trial.
# The tag's first line is the mode and the samples (1 to 4, default 4); a full run
# opens Codex sessions, so it also carries this machine's Codex session, encrypted
# to the CI's key (the private half is the secret CODEX_AUTH_KEY), exactly as
# run.sh puts it. A dryrun carries none and runs arms A1 and A2 only.
# fetch.sh TAG DIR brings the results back; summary.py DIR reads them.
set -euo pipefail
usage="usage: launch.sh NAME [full|dryrun] [samples=N]"
name=${1:?$usage}
name=${name#exp-drift-}
mode=${2:-dryrun}
samples=${3:-samples=4}
case $mode in full | dryrun) ;; *) echo "launch.sh: the mode is full or dryrun, not $mode" >&2; exit 2 ;; esac
case $samples in
samples=[1-4]) ;;
*) echo "launch.sh: $samples is not samples=N with N from 1 to 4" >&2; exit 2 ;;
esac
ci_recipient=age1s5k75wkcjwpps44lup59t048lxtsmc48l2lkg42mly922kj6g3ks3flrqj
age=$(command -v age || echo "$HOME/go/bin/age")
msg=$(mktemp)
trap 'rm -f "$msg"' EXIT
if [ "$mode" = full ]; then
  printf '%s %s\n\n' "$mode" "$samples" > "$msg"
  "$age" -a -r "$ci_recipient" "${CODEX_HOME:-$HOME/.codex}/auth.json" >> "$msg"
else
  printf '%s %s\n' "$mode" "$samples" > "$msg"
fi
git tag -a "exp-drift-$name" -F "$msg"
git push --no-verify -q origin "exp-drift-$name"
echo "exp-drift-$name: https://github.com/lilsadfoqs/azhaq/actions"

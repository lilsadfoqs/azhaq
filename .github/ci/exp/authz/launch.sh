#!/bin/bash
# launch.sh NAME [full|dryrun] [WORDS...]: starts the access-control experiment by pushing the annotated tag
# exp-authz-NAME on HEAD. The first line of the message is the mode and its words:
#   dryrun             the agent-free arms only; needs no Codex session
#   dryrun agents      also the agent jobs up to and including isolation, with a stub in place of Codex
#   full               every arm; carries this machine's Codex session, age-encrypted to the CI's key, exactly as
#                      .github/ci/run.sh does for a trial
#   samples=N          N from 1 to 4 (default 4): the number of generated apps
# fetch.sh TAG DIR brings the results back; summary.py DIR prints the table and the three rules.
set -euo pipefail
name=${1:?usage: launch.sh NAME [full|dryrun] [WORDS...]}
mode=${2:-dryrun}
shift $(($# > 1 ? 2 : 1))
case $mode in full | dryrun) ;; *)
  echo "launch.sh: the mode is full or dryrun, not $mode" >&2
  exit 2
  ;;
esac
ci_recipient=age1s5k75wkcjwpps44lup59t048lxtsmc48l2lkg42mly922kj6g3ks3flrqj
age=$(command -v age || echo "$HOME/go/bin/age")
msg=$(mktemp)
trap 'rm -f "$msg"' EXIT
printf '%s' "$mode" > "$msg"
[ $# -gt 0 ] && printf ' %s' "$*" >> "$msg"
printf '\n' >> "$msg"
if [ "$mode" = full ]; then
  printf '\n' >> "$msg"
  "$age" -a -r "$ci_recipient" "${CODEX_HOME:-$HOME/.codex}/auth.json" >> "$msg"
fi
git tag -a "exp-authz-$name" -F "$msg"
git push --no-verify -q origin "exp-authz-$name"
echo "exp-authz-$name: https://github.com/lilsadfoqs/azhaq/actions"

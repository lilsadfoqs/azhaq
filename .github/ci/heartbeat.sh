#!/bin/bash
# heartbeat.sh TAG STREAM PHASES USER REPO: runs as root beside a trial's
# review and, every 10 minutes for at most 6 hours, publishes counts to
# ci-results under trial/TAG/heartbeat.txt (.github/ci/beat.sh reads it):
# the time, minutes since the stream file was created, whether codex runs,
# the stream's lines, the seconds since its last line, the commands done,
# phases.log, the load and the free disk. Nothing else: no command, no text
# from the stream, no estate data (the repository and its log are public).
#
# The token is in /root/beat.token (0600, root), put there by the trial
# workflow before isolate.sh hides root's processes. Files of the review are
# read as USER, so a link planted in its folder cannot make this read a root
# file, and phases.log is cut to the lines it is documented to hold.
# Nothing here may fail the job.
set -u
tag=$1 stream=$2 phases=$3 user=$4
export GITHUB_REPOSITORY=$5
here=$(dirname "$0")
cd /root || exit 0
exec > /root/beat.log 2>&1
uid=$(id -u "$user") gid=$(id -g "$user")
as_user() { setpriv --reuid="$uid" --regid="$gid" --clear-groups "$@"; }

counts() { # prints: lines last-epoch commands (or "none"), read as the user
  as_user bash -c '
    f=$1
    if [ ! -f "$f" ] || [ -L "$f" ]; then echo none; exit 0; fi
    echo "$(wc -l < "$f") $(tail -n 1 "$f" | cut -d" " -f1) $(grep -cE "\"type\": ?\"item.completed\".*\"type\": ?\"command_execution\"" "$f")"
  ' _ "$1" 2> /dev/null || echo none
}
phase_lines() { # only lines of the shape the brief asks for
  as_user bash -c '[ -f "$1" ] && [ ! -L "$1" ] && head -c 4096 "$1"' _ "$1" 2> /dev/null |
    grep -E '^phase [0-9]+ (start|end) [0-9TZ:+-]{10,30}$' | head -n 40
}

seen=
end=$((SECONDS + 21600))
while [ "$SECONDS" -lt "$end" ]; do
  now=$(date +%s)
  born=$(stat -c %W "$stream" 2> /dev/null || echo 0)
  case $born in '' | *[!0-9]*) born=0 ;; esac
  if [ "$born" = 0 ] && [ -e "$stream" ]; then
    [ -n "$seen" ] || seen=$now
    born=$seen
  fi
  if [ "$born" -gt 0 ]; then mins=$(((now - born) / 60)); else mins="not started"; fi
  if pgrep -f '[c]odex exec' > /dev/null 2>&1; then alive=yes; else alive=no; fi
  read -r lines last cmds < <(counts "$stream")
  case ${lines:-none} in
  none | *[!0-9]*) lines=0 age="-" cmds=0 ;;
  *)
    case ${last:-} in '' | *[!0-9]*) age="-" ;; *) age=$((now - last)) ;; esac
    case ${cmds:-} in '' | *[!0-9]*) cmds=0 ;; esac
    ;;
  esac
  {
    echo "time $(date -u +%FT%TZ)"
    echo "review_minutes $mins"
    echo "codex_alive $alive"
    echo "stream_lines $lines"
    echo "last_line_age_seconds $age"
    echo "commands_completed $cmds"
    echo "load $(cut -d' ' -f1-3 /proc/loadavg)"
    echo "disk_free_gb $(df --output=avail -BG / | tail -1 | tr -dc '0-9')"
    echo "phases.log:"
    phase_lines "$phases"
  } > /root/heartbeat.txt
  GITHUB_TOKEN=$(cat /root/beat.token) timeout 300 "$here/publish.sh" "trial/$tag" /root/heartbeat.txt || echo "publish failed at $(date -u +%T)"
  sleep 600
done
exit 0

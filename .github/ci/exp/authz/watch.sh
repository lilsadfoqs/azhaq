#!/bin/bash
# watch.sh USER FILE DEST: runs as root beside an agent arm (started before isolate.sh hides it). Every 3
# seconds, for at most 6 hours, it reads FILE as USER and writes each line it has not seen before to
# DEST/watch.jsonl as {"t": epoch seconds, "line": the line}: when each finding first appeared. DEST is
# root's and world-readable, so the review's user can neither change it nor need to.
set -u
user=$1 file=$2 dest=$3
uid=$(id -u "$user") gid=$(id -g "$user")
mkdir -p "$dest"
chmod 755 "$dest"
: > "$dest/watch.jsonl"
chmod 644 "$dest/watch.jsonl"
declare -A seen
end=$((SECONDS + 21600))
while [ "$SECONDS" -lt "$end" ]; do
  now=$(date +%s)
  while IFS= read -r line; do
    line=${line%$'\r'}
    [ -n "$line" ] || continue
    [ -z "${seen[$line]+x}" ] || continue
    seen[$line]=1
    jq -nc --arg l "$line" --argjson t "$now" '{t: $t, line: $l}' >> "$dest/watch.jsonl"
  done < <(setpriv --reuid="$uid" --regid="$gid" --clear-groups bash -c '[ -f "$1" ] && [ ! -L "$1" ] && head -c 1048576 "$1"' _ "$file" 2> /dev/null)
  sleep 3
done

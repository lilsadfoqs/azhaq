#!/bin/bash
# watch.sh RUN...: watches one or more trial tags (trial-NAME) on ci-results
# until every one is done or looks stuck, then prints one line per run and
# exits: 0 when every run is done, 1 when the deadline passed with a run
# still going, or a run never started by the deadline. Checks every POLL
# seconds (default 60) for at most DEADLINE seconds (default 21600, 6h);
# every network call is time bounded (curl --max-time), so this never hangs.
#
# A gate or baseline publishes under a part (trial/RUN/a, /b, or /a1 /a2 /b1
# /b2 for samples=2); the other kinds publish flat (trial/RUN). This checks
# every possible part and the flat path, and reports on whichever answer.
#
#   done   every part that ever had a heartbeat now also has trial.tgz.age
#          (the job's publish step ran)
#   stuck  a part's heartbeat shows no new stream line in STUCK_AFTER seconds
#          (default 1800) and codex is not running
#   running   a heartbeat exists and neither of the above holds, or no part
#             has started yet
set -uo pipefail
STUCK_AFTER=${STUCK_AFTER:-1800}
POLL=${POLL:-60}
DEADLINE=${DEADLINE:-21600}
repo=${WATCH_REPO:-lilsadfoqs/azhaq}
[ $# -ge 1 ] || { echo "usage: watch.sh RUN..." >&2; exit 2; }
runs=("$@")
parts=("" a b a1 a2 b1 b2)

exists() { # exists PATH: a file on ci-results
  curl -fsS --max-time 20 -o /dev/null "https://raw.githubusercontent.com/$repo/ci-results/$1" 2>/dev/null
}

fetch() { # fetch PATH: its text, or nothing
  curl -fsS --max-time 20 "https://raw.githubusercontent.com/$repo/ci-results/$1" 2>/dev/null
}

field() { # field TEXT NAME
  printf '%s\n' "$1" | sed -n "s/^$2 //p" | head -n1
}

state_of() { # state_of RUN: one line, "done", "stuck: reason" or "running: ..."
  local run=$1 p dir hb age alive any_hb=0 any_done=0 missing_tgz=0 stuck=""
  for p in "${parts[@]}"; do
    dir="trial/$run${p:+/$p}"
    if exists "$dir/trial.tgz.age"; then any_done=1; continue; fi
    hb=$(fetch "$dir/heartbeat.txt")
    [ -n "$hb" ] || continue
    any_hb=1
    missing_tgz=1
    age=$(field "$hb" last_line_age_seconds)
    alive=$(field "$hb" codex_alive)
    case $age in
    '' | '-' | *[!0-9]*) ;;
    *) [ "$age" -gt "$STUCK_AFTER" ] && [ "$alive" = no ] && stuck="$dir: no stream line in ${age}s and codex is not running" ;;
    esac
  done
  if [ -n "$stuck" ]; then
    echo "stuck: $stuck"
  elif [ "$any_hb" = 0 ] && [ "$any_done" = 0 ]; then
    echo "running: not started yet (no heartbeat and no result on ci-results)"
  elif [ "$missing_tgz" = 0 ]; then
    echo "done"
  else
    echo "running"
  fi
}

end=$((SECONDS + DEADLINE))
while :; do
  all_terminal=1
  for run in "${runs[@]}"; do
    s=$(state_of "$run")
    echo "$run: $s"
    case $s in
    done | stuck*) ;;
    *) all_terminal=0 ;;
    esac
  done
  [ "$all_terminal" = 1 ] && exit 0
  [ "$SECONDS" -ge "$end" ] && { echo "watch.sh: deadline reached with a run still going" >&2; exit 1; }
  sleep "$POLL"
done

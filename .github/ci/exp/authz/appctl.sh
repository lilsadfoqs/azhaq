#!/bin/bash
# Source this: app_start DIR PORT COUNTFILE [USER], app_stop PORT [USER].
# The app runs as USER (sudo -u) when one is given, so the review's user cannot read it.
authz_dir=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)

app_stop() {
  local port=$1 user=${2:-}
  if [ -n "$user" ]; then
    sudo -n pkill -u "$user" -f "server.py .* --port $port" 2>/dev/null || true
  else
    pkill -f "server.py .* --port $port" 2>/dev/null || true
  fi
  for _ in $(seq 1 50); do
    curl -s -o /dev/null -m 1 "http://127.0.0.1:$port/" || return 0
    sleep 0.2
  done
  echo "appctl: the app on port $port did not stop" >&2
  return 1
}

app_start() {
  local dir=$1 port=$2 count=$3 user=${4:-} code=${5:-$authz_dir}
  rm -f "$count" 2>/dev/null || sudo -n rm -f "$count"
  if [ -n "$user" ]; then
    sudo -n -u "$user" setsid python3 "$code/server.py" "$dir" --port "$port" --count-file "$count" > /dev/null 2>&1 < /dev/null &
  else
    setsid python3 "$code/server.py" "$dir" --port "$port" --count-file "$count" > /dev/null 2>&1 < /dev/null &
  fi
  for _ in $(seq 1 100); do
    curl -s -o /dev/null -m 1 "http://127.0.0.1:$port/" && return 0
    sleep 0.2
  done
  echo "appctl: the app did not start on port $port" >&2
  return 1
}

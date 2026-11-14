#!/bin/bash
# agent-user.sh setup|check: the user arm A3's agent runs as, kept from the
# estate as trial's isolate.sh keeps its reviewer, but without taking the
# runner's own docker and sudo away (apply.py needs them between the epochs).
#
#   setup   creates the user `analyst` (no docker group, no sudo), its folder
#           (./trial/notes, which lives across the checks), remounts /proc with
#           hidepid=2 (the user sees only its own processes), and closes this
#           user's home (700): the checkout, the answer key and the arms'
#           outputs are in it.
#   check   verifies each of those as the user; exit 1 when one fails, so the
#           job stops before the agent starts.
# Not hidden, as in the trial: the kernel's table of listening sockets.
set -uo pipefail
agent=analyst
me=$(id -un)
mode=${1:?usage: agent-user.sh setup|check}
fail=0
# Runs the command as the agent in a clean environment; its exit code is the command's.
as_agent() { sudo -n -u "$agent" env -i HOME="/home/$agent" PATH=/opt/tools/bin:/usr/local/bin:/usr/bin:/bin "$@"; }
check() { # check LABEL COMMAND...: the command must succeed
  local label=$1
  shift
  if "$@" > /dev/null 2>&1; then echo "ok: $label"; else echo "FAILED: $label"; fail=1; fi
}
check_not() { # check_not LABEL COMMAND...: the command must fail
  local label=$1
  shift
  if "$@" > /dev/null 2>&1; then echo "FAILED: $label"; fail=1; else echo "ok: $label"; fi
}
others_visible() {
  as_agent bash -c 'u=$(id -u); find /proc -maxdepth 1 -name "[0-9]*" -printf "%U\n" 2>/dev/null | sort -u | grep -qv "^${u}$"'
}

case $mode in
setup)
  id "$agent" > /dev/null 2>&1 || sudo -n useradd -m -s /bin/bash "$agent"
  sudo -n chmod 755 "/home/$agent"
  sudo -n install -d -o "$agent" -g "$agent" -m 750 "/home/$agent/trial" "/home/$agent/trial/notes" "/home/$agent/.codex"
  # The stream the heartbeat reads: this user's file, in a folder only it can write.
  sudo -n install -d -o "$me" -g "$me" -m 755 "/home/$agent/ci"
  sudo -n install -d -m 755 /opt/tools /opt/srv
  sudo -n install -d -o "$me" -m 755 /opt/tools/bin
  sudo -n mount -o remount,hidepid=2 /proc
  chmod 700 "$HOME"
  echo "agent-user.sh: user $agent ready"
  ;;
check)
  check "the user runs commands" as_agent true
  check_not "processes of other users are hidden in /proc" others_visible
  check_not "docker is unusable" as_agent docker ps
  check_not "sudo is not available" as_agent sudo -n true
  check_not "the runner's home cannot be listed" as_agent ls "$HOME"
  check_not "the answer key cannot be read" as_agent cat "$HOME/drift/est/key.json"
  check_not "the deploy fixture cannot be listed" as_agent ls /opt/srv/app
  check_not "azhaq is not on the user's path" as_agent sh -c 'command -v azhaq'
  check_not "the heartbeat token cannot be read" as_agent sh -c 'exec 3< /root/beat.token'
  check "the user can write its folder" as_agent sh -c 'touch /home/analyst/trial/.w && rm /home/analyst/trial/.w'
  check "the stack is on the user's path" as_agent sh -c 'command -v dnsx && command -v naabu && command -v httpx && command -v nuclei && command -v nmap && command -v dig'
  [ "$fail" -eq 0 ] || { echo "agent-user.sh: a check failed; the agent must not start" >&2; exit 1; }
  echo "agent-user.sh: all checks passed"
  ;;
*)
  echo "usage: agent-user.sh setup|check" >&2
  exit 2
  ;;
esac

#!/bin/bash
# bench-tools.sh key | list | pack OUT_DIR: the reference tools the bench
# keeps between runs, in bench/.work (WORK): the binaries without azhaq (built
# each run), the arjun virtualenv and the pinned wordlists.
#   key   the artifact's name: the hash of bench/tools.go (it pins the tools,
#         arjun and the wordlists) and the Go version
#   list  the files kept, one a line (a run that changes the list has
#         something new to hand on)
#   pack  OUT_DIR/artifact.tar, for latest-artifact.sh
set -euo pipefail
work=${WORK:-bench/.work}
case ${1:-} in
key)
  echo "bench-tools-$(sha256sum bench/tools.go | cut -c1-16)-$(go env GOVERSION)"
  ;;
list | pack)
  out=
  if [ "$1" = pack ]; then
    mkdir -p "${2:?usage: bench-tools.sh pack OUT_DIR}"
    out=$(cd "$2" && pwd)
  fi
  cd "$work" 2>/dev/null || exit 0
  items=()
  for p in bin arjun-* subdomains-top1million-5000.txt common.txt burp-parameter-names.txt; do
    [ -e "$p" ] && items+=("$p")
  done
  [ ${#items[@]} -gt 0 ] || exit 0
  if [ "$1" = list ]; then
    find "${items[@]}" -not -path bin/azhaq \( -type f -o -type l \) | LC_ALL=C sort
  else
    tar -cf "$out/artifact.tar" --exclude=bin/azhaq "${items[@]}"
  fi
  ;;
*)
  echo "usage: bench-tools.sh key|list|pack OUT_DIR" >&2
  exit 2
  ;;
esac

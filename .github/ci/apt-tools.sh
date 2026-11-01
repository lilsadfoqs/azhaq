#!/bin/bash
# apt-tools.sh DEBDIR PACKAGE...: installs the packages from the .deb files
# in DEBDIR (kept in the bench's tools artifact) with dpkg, which takes a
# second where apt-get update and the mirror took 8 to 145 s. A package the
# files do not give, or a dpkg that fails (the runner image moved on), falls
# back to apt-get update and install, and the .deb files apt downloads for
# the missing packages are copied to DEBDIR for the next artifact.
# SUDO, DPKG, APT_GET and DPKG_QUERY name the commands (tests stub them).
set -uo pipefail
dir=${1:?usage: apt-tools.sh DEBDIR PACKAGE...}
shift
[ $# -gt 0 ] || { echo "usage: apt-tools.sh DEBDIR PACKAGE..." >&2; exit 2; }
sudo=${SUDO-sudo}
dpkg=${DPKG:-dpkg}
apt=${APT_GET:-apt-get}
query=${DPKG_QUERY:-dpkg-query}

missing() {
  local p
  for p in "$@"; do
    "$query" -W -f '${Status}' "$p" 2>/dev/null | grep -q "install ok installed" || echo "$p"
  done
}

# Packages the image or a file provides already are not asked for again.
need=$(missing "$@")
[ -n "$need" ] || { echo "apt-tools: $* are installed"; exit 0; }

shopt -s nullglob
debs=("$dir"/*.deb)
if [ ${#debs[@]} -gt 0 ]; then
  if $sudo "$dpkg" -i "${debs[@]}" >/dev/null 2>&1; then
    # shellcheck disable=SC2086 # the names are words
    need=$(missing $need)
    [ -n "$need" ] || { echo "apt-tools: installed from ${#debs[@]} .deb files in $dir"; exit 0; }
    echo "apt-tools: the .deb files in $dir lack: $(echo $need)"
  else
    echo "apt-tools: dpkg could not install the .deb files in $dir; using apt"
  fi
fi

# shellcheck disable=SC2086
$sudo "$apt" update -q || echo "apt-tools: apt-get update failed; trying the install"
cache=${APT_ARCHIVES:-/var/cache/apt/archives}
before=$(ls "$cache" 2>/dev/null)
# shellcheck disable=SC2086
$sudo "$apt" install -y -q --download-only $need || true
mkdir -p "$dir"
for f in "$cache"/*.deb; do
  # Only what this download brought, not what the image had lying there.
  grep -qxF "$(basename "$f")" <<<"$before" || cp -p "$f" "$dir"/ 2>/dev/null || true
done
# shellcheck disable=SC2086
$sudo "$apt" install -y -q $need

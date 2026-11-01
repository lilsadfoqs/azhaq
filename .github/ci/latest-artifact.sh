#!/bin/bash
# latest-artifact.sh NAME DIR: unpacks the newest unexpired Actions artifact
# called NAME of this repository (GITHUB_REPOSITORY, GH_TOKEN) into DIR. The
# artifact holds one file, artifact.tar, because a zip loses file modes. A
# miss or a failed download prints a note and exits 0: the cache is only a
# speed-up, never a reason to fail a job. (Actions caches are no use here: a
# tag run reads only its own ref's caches, and every bench run is a new tag.)
set -uo pipefail
name=${1:?usage: latest-artifact.sh NAME DIR}
dir=${2:?usage: latest-artifact.sh NAME DIR}
repo=${GITHUB_REPOSITORY:?latest-artifact.sh: GITHUB_REPOSITORY is not set}
tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT
miss() { echo "latest-artifact: $name: $1; going on without it"; exit 0; }

# Newest first; the newest that has not expired.
list=$(gh api "repos/$repo/actions/artifacts?name=$name&per_page=30") || miss "could not list artifacts"
id=$(jq -r --arg n "$name" '[.artifacts[] | select(.name == $n and (.expired | not))][0].id // empty' <<<"$list") || miss "unreadable list"
[ -n "$id" ] || miss "no unexpired artifact"
gh api "repos/$repo/actions/artifacts/$id/zip" >"$tmp/a.zip" || miss "download of artifact $id failed"
python3 -I -m zipfile -e "$tmp/a.zip" "$tmp/x" || miss "artifact $id is not a zip"
[ -f "$tmp/x/artifact.tar" ] || miss "artifact $id holds no artifact.tar"
mkdir -p "$dir"
tar -xf "$tmp/x/artifact.tar" -C "$dir" || miss "artifact $id does not unpack"
echo "latest-artifact: $name: artifact $id unpacked into $dir"

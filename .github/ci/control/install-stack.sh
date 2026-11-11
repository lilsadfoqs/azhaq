#!/bin/bash
# install-stack.sh DIR: installs the control's candidate into DIR: orvel (the
# front end), its README as orvel-README.md, its table of tools as
# orvel-stack.tsv, and the pinned stack the table names (stack.tsv): release
# binaries checked against their sha256, arjun in a virtualenv behind a
# wrapper, nmap from apt as the gate jobs have it. nuclei fetches its
# templates itself on first use. The pins are the ones bench/tools.go and
# bench/params.go have. STACK names another table (tests).
set -euo pipefail
here=$(cd "$(dirname "$0")" && pwd)
dir=${1:?usage: install-stack.sh DIR}
stack=${STACK:-$here/stack.tsv}
mkdir -p "$dir"
dir=$(cd "$dir" && pwd) # absolute: the arjun wrapper names its virtualenv
work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT

while IFS=$'\t' read -r sub tool version kind source sha; do
  case $sub in '' | '#'*) continue ;; esac
  echo "install-stack: $tool $version"
  case $kind in
  zip | tgz | bin)
    file=$work/$tool.download
    curl -fsSL --retry 3 -o "$file" "$source"
    got=$(sha256sum "$file" | cut -d' ' -f1)
    [ "$got" = "$sha" ] || { echo "install-stack: $tool: checksum mismatch (got $got, want $sha)" >&2; exit 1; }
    case $kind in
    zip) unzip -oq "$file" "$tool" -d "$work/$tool.x" ;;
    tgz) mkdir -p "$work/$tool.x" && tar -xzf "$file" -C "$work/$tool.x" "$tool" ;;
    bin) mkdir -p "$work/$tool.x" && cp "$file" "$work/$tool.x/$tool" ;;
    esac
    install -m 755 "$work/$tool.x/$tool" "$dir/$tool"
    ;;
  pip)
    python3 -m venv "$dir/.$tool-venv"
    "$dir/.$tool-venv/bin/pip" install -q "$tool==$version"
    printf '#!/bin/sh\nexec "%s/.%s-venv/bin/%s" "$@"\n' "$dir" "$tool" "$tool" > "$dir/$tool"
    chmod 755 "$dir/$tool"
    ;;
  apt)
    command -v "$tool" > /dev/null || "$here/../apt-tools.sh" "$work/debs" "$tool"
    ln -sf "$(command -v "$tool")" "$dir/$tool"
    ;;
  *)
    echo "install-stack: $tool: unknown kind $kind" >&2
    exit 1
    ;;
  esac
done < "$stack"

install -m 755 "$here/orvel" "$dir/orvel"
install -m 644 "$here/README.md" "$dir/orvel-README.md"
install -m 644 "$stack" "$dir/orvel-stack.tsv"
"$dir/orvel" version

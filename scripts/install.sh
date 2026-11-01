#!/bin/sh
# Installs azhaq from a GitHub release, or from a local directory (-f) such
# as `goreleaser release --snapshot`'s dist/: the archive must match
# checksums.txt and, when cosign is available (a release, not a local
# source), checksums.txt must carry a valid signature from this
# repository's release workflow. Nothing is written to DIR before both
# checks pass.
#
# Without cosign the install rests on the checksum alone, and says so. To
# refuse that, give -s (--require-signature) or set AZHAQ_REQUIRE_SIGNATURE=1:
# the script then stops before downloading anything when cosign is missing,
# and stops when the signature does not verify. A local source (-f) has no
# signature to check; -s with -f stops instead of silently skipping it.
#
# Needs: curl or wget (not with -f); tar and gzip (the archive is a .tar.gz);
# sha256sum or shasum; cosign (optional, required with -s); and the usual sh,
# awk, sed, head, mktemp, uname, cp, chmod and mkdir.
#
# Usage: sh install.sh [-v VERSION] [-d DIR] [-f SOURCE_DIR] [-s | --require-signature]
set -eu

REPO=lilsadfoqs/azhaq
RELEASES=https://github.com/$REPO/releases
VERSION=
INSTALL_DIR=
FROM_DIR=
TMP=
REQUIRE_SIG=
case ${AZHAQ_REQUIRE_SIGNATURE:-} in
    ''|0|false|no) ;;
    *) REQUIRE_SIG=1 ;;
esac

err() {
    printf 'install.sh: %s\n' "$*" >&2
    exit 1
}

info() {
    printf 'install.sh: %s\n' "$*"
}

usage() {
    cat <<EOF
usage: sh install.sh [-v VERSION] [-d DIR] [-f SOURCE_DIR] [-s | --require-signature]
  -v VERSION           release tag such as v0.8.1 (required with -f; no
                       "latest" lookup for a local source)
  -d DIR               install directory (default: \$HOME/.local/bin)
  -f SOURCE_DIR        install from this local directory instead of
                       downloading: the archive and checksums.txt are read
                       from it, as goreleaser's dist/ holds them after
                       \`goreleaser release --snapshot\`
  -s, --require-signature
                       install only when cosign verifies the signature of
                       checksums.txt; stop when cosign is missing or the
                       signature fails (same: AZHAQ_REQUIRE_SIGNATURE=1).
                       With -f, stop instead: a local source has nothing to
                       verify a signature against.
EOF
}

# need CMD...: stops, naming every command of the list that is missing.
need() {
    missing=
    for c in "$@"; do
        command -v "$c" >/dev/null 2>&1 || missing="$missing $c"
    done
    [ -z "$missing" ] || err "missing commands:$missing; install them and run again"
}

# fetch URL FILE: curl if present, else wget.
fetch() {
    if command -v curl >/dev/null 2>&1; then
        curl -fsSL -o "$2" "$1" || err "download failed: $1"
    elif command -v wget >/dev/null 2>&1; then
        wget -q -O "$2" "$1" || err "download failed: $1"
    else
        err "need curl or wget to download files"
    fi
}

# getopts reads no long option: take --require-signature out first.
n=$#
while [ "$n" -gt 0 ]; do
    a=$1
    shift
    case $a in
        --require-signature) REQUIRE_SIG=1 ;;
        *) set -- "$@" "$a" ;;
    esac
    n=$((n - 1))
done

while getopts ':v:d:f:sh' opt; do
    case $opt in
        v) VERSION=$OPTARG ;;
        d) INSTALL_DIR=$OPTARG ;;
        f) FROM_DIR=$OPTARG ;;
        s) REQUIRE_SIG=1 ;;
        h) usage; exit 0 ;;
        \?) err "unknown option -$OPTARG (see: sh install.sh -h)" ;;
        :) err "option -$OPTARG needs a value" ;;
    esac
done
shift $((OPTIND - 1))
[ $# -eq 0 ] || err "unexpected argument: $1"

if [ -n "$FROM_DIR" ]; then
    [ -d "$FROM_DIR" ] || err "no such directory: $FROM_DIR"
    [ -n "$VERSION" ] || err "-f needs -v VERSION too: a local source has no \"latest\" to look up"
    if [ -n "$REQUIRE_SIG" ]; then
        err "-f (a local source) has no signature to verify; drop -s/--require-signature, or sign $FROM_DIR/checksums.txt first"
    fi
fi

# Every tool is checked before anything is downloaded.
need uname mktemp awk sed head tar gzip cp chmod mkdir
command -v sha256sum >/dev/null 2>&1 || command -v shasum >/dev/null 2>&1 || err "need sha256sum or shasum to verify the download"
if [ -z "$FROM_DIR" ]; then
    command -v curl >/dev/null 2>&1 || command -v wget >/dev/null 2>&1 || err "need curl or wget to download files"
fi
COSIGN_BIN=
if [ -z "$FROM_DIR" ]; then
    COSIGN_BIN=$(command -v "${COSIGN:-cosign}" 2>/dev/null || true)
    if [ -n "${COSIGN:-}" ] && [ -z "$COSIGN_BIN" ]; then
        err "COSIGN=$COSIGN is not an executable"
    fi
    if [ -n "$REQUIRE_SIG" ] && [ -z "$COSIGN_BIN" ]; then
        printf 'install.sh: a signature is required (-s, AZHAQ_REQUIRE_SIGNATURE) but cosign was not found; nothing was downloaded or installed.\n' >&2
        printf 'install.sh: install cosign, then run this again. Any one of:\n' >&2
        printf '  go install github.com/sigstore/cosign/v2/cmd/cosign@latest   (needs Go; puts cosign in $(go env GOPATH)/bin)\n' >&2
        printf '  brew install cosign   |   pacman -S cosign   |   apk add cosign   |   nix-shell -p cosign\n' >&2
        printf '  a release binary: https://github.com/sigstore/cosign/releases/latest\n' >&2
        printf 'install.sh: if it is installed outside PATH, name it with COSIGN=/path/to/cosign (other systems: https://docs.sigstore.dev/cosign/system_config/installation/)\n' >&2
        exit 1
    fi
fi

case $(uname -s) in
    Linux) OS=linux ;;
    Darwin) OS=darwin ;;
    *) err "unsupported OS $(uname -s); download manually from $RELEASES" ;;
esac

case $(uname -m) in
    x86_64|amd64) ARCH=amd64 ;;
    aarch64|arm64) ARCH=arm64 ;;
    *) err "unsupported architecture $(uname -m); download manually from $RELEASES" ;;
esac

INSTALL_DIR=${INSTALL_DIR:-$HOME/.local/bin}
case $INSTALL_DIR in
    /*) ;;
    *) INSTALL_DIR=$PWD/$INSTALL_DIR ;;
esac
INSTALL_DIR=${INSTALL_DIR%/}

TMP=$(mktemp -d) || err "cannot create a temp dir"
trap 'if [ -n "$TMP" ]; then rm -rf "$TMP"; fi' EXIT
trap 'exit 1' HUP INT TERM

# get NAME FILE: FROM_DIR/NAME copied, or BASE/NAME downloaded.
get() {
    if [ -n "$FROM_DIR" ]; then
        [ -f "$FROM_DIR/$1" ] || err "$FROM_DIR/$1 not found"
        cp "$FROM_DIR/$1" "$2" || err "cannot read $FROM_DIR/$1"
    else
        fetch "$BASE/$1" "$2"
    fi
}

if [ -z "$VERSION" ]; then
    fetch "https://api.github.com/repos/$REPO/releases/latest" "$TMP/latest.json"
    VERSION=$(sed -n 's/.*"tag_name": *"\([^"]*\)".*/\1/p' "$TMP/latest.json" | head -n 1)
    [ -n "$VERSION" ] || err "could not read the latest release tag from the GitHub API"
    info "latest release is $VERSION"
fi

case $VERSION in
    [0-9]*) VERSION=v$VERSION ;;
esac
case $VERSION in
    v[0-9]*) ;;
    *) err "bad version: $VERSION" ;;
esac
case $VERSION in
    *[!A-Za-z0-9._+-]*) err "bad version: $VERSION" ;;
esac

NUM=${VERSION#v}
ARCHIVE=azhaq_${NUM}_${OS}_${ARCH}.tar.gz
BASE=$RELEASES/download/$VERSION

get "$ARCHIVE" "$TMP/$ARCHIVE"
get checksums.txt "$TMP/checksums.txt"

awk -v f="$ARCHIVE" '$2 == f' "$TMP/checksums.txt" > "$TMP/check.txt"
[ -s "$TMP/check.txt" ] || err "checksums.txt has no entry for $ARCHIVE"

if command -v sha256sum >/dev/null 2>&1; then
    SHA_CMD="sha256sum -c"
elif command -v shasum >/dev/null 2>&1; then
    SHA_CMD="shasum -a 256 -c"
else
    err "need sha256sum or shasum to verify the download"
fi
(cd "$TMP" && $SHA_CMD check.txt >/dev/null 2>&1) || err "checksum mismatch for $ARCHIVE; nothing installed"
info "sha256 of $ARCHIVE matches checksums.txt"

if [ -n "$FROM_DIR" ]; then
    info "local source ($FROM_DIR): the signature is not checked (there is no release to verify against)"
elif [ -n "$COSIGN_BIN" ]; then
    fetch "$BASE/checksums.txt.sigstore.json" "$TMP/checksums.txt.sigstore.json"
    "$COSIGN_BIN" verify-blob \
        --bundle "$TMP/checksums.txt.sigstore.json" \
        --certificate-identity-regexp '^https://github\.com/(lilsadfoqs|trannghiach)/azhaq/\.github/workflows/release\.yml@refs/tags/v' \
        --certificate-oidc-issuer https://token.actions.githubusercontent.com \
        "$TMP/checksums.txt" || err "signature check failed for checksums.txt; nothing installed"
    info "signature of checksums.txt verified with cosign"
else
    info "checksum verified, but the signature was NOT verified (cosign not found); to verify, run this in a directory holding the release's checksums.txt and checksums.txt.sigstore.json:"
    printf '%s\n' "cosign verify-blob --bundle checksums.txt.sigstore.json --certificate-identity-regexp '^https://github\.com/(lilsadfoqs|trannghiach)/azhaq/\.github/workflows/release\.yml@refs/tags/v' --certificate-oidc-issuer https://token.actions.githubusercontent.com checksums.txt"
fi

mkdir "$TMP/x"
tar -xzf "$TMP/$ARCHIVE" -C "$TMP/x" || err "cannot extract $ARCHIVE"
[ -f "$TMP/x/azhaq" ] || err "$ARCHIVE does not contain azhaq"

mkdir -p "$INSTALL_DIR" || err "cannot create $INSTALL_DIR"
cp "$TMP/x/azhaq" "$INSTALL_DIR/azhaq" || err "cannot write $INSTALL_DIR/azhaq"
chmod 755 "$INSTALL_DIR/azhaq"

info "installed $INSTALL_DIR/azhaq"
"$INSTALL_DIR/azhaq" version || err "installed binary did not run"

case ":$PATH:" in
    *":$INSTALL_DIR:"*) ;;
    *) info "$INSTALL_DIR is not on PATH; add it with: export PATH=\"$INSTALL_DIR:\$PATH\"" ;;
esac

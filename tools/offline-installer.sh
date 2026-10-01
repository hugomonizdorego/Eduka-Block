#!/bin/sh
# Eduka-Block offline installer.
#
# This file is a shell script followed by a compressed archive containing the
# Eduka-Block package and every dependency it needs, as a small local APT
# repository. Run it as root (it asks for sudo/pkexec when needed):
#
#     sudo sh eduka-block-<version>-offline-<distro>-<arch>.run
#
# Options:
#     --offline-only   never fall back to the internet
#     --extract DIR    only unpack the bundle into DIR (for inspection)
#
# APT installs from the bundled repository only, so no internet connection is
# needed. Packages that are already installed at the same or a newer version
# are left alone. If the computer is missing something the bundle does not
# contain, the installer falls back to the normal APT sources (internet)
# unless --offline-only is given.
set -eu

PAYLOAD_MARKER="__EDUKA_BLOCK_PAYLOAD__"
SELF=$(readlink -f "$0")
OFFLINE_ONLY=0
EXTRACT_DIR=""

while [ "$#" -gt 0 ]; do
    case "$1" in
        --offline-only) OFFLINE_ONLY=1 ;;
        --extract) shift; EXTRACT_DIR=${1:-} ;;
        -h|--help) sed -n '2,20p' "$SELF"; exit 0 ;;
        *) printf 'Unknown option: %s\n' "$1" >&2; exit 2 ;;
    esac
    shift
done

say() { printf '\033[1;36m==>\033[0m %s\n' "$*"; }
fail() { printf '\033[1;31mError:\033[0m %s\n' "$*" >&2; exit 1; }

extract() {
    line=$(awk -v marker="$PAYLOAD_MARKER" '$0 == marker { print NR + 1; exit 0 }' "$SELF")
    [ -n "$line" ] || fail "the installer is damaged (payload not found)"
    tail -n +"$line" "$SELF" | tar -xzf - -C "$1" || fail "the installer is damaged (cannot unpack)"
}

if [ -n "$EXTRACT_DIR" ]; then
    mkdir -p "$EXTRACT_DIR"
    extract "$EXTRACT_DIR"
    say "Unpacked to $EXTRACT_DIR"
    exit 0
fi

if [ "$(id -u)" -ne 0 ]; then
    if command -v sudo >/dev/null 2>&1; then
        exec sudo sh "$SELF" "$@"
    elif command -v pkexec >/dev/null 2>&1; then
        exec pkexec sh "$SELF" "$@"
    fi
    fail "run this installer as root, for example: sudo sh $(basename "$SELF")"
fi

command -v apt-get >/dev/null 2>&1 || fail "this installer needs a Debian-based system with APT"

# /var/tmp, not /tmp: it may be noexec or too small, and APT's unprivileged
# _apt user must be able to read the repository.
WORK=$(mktemp -d /var/tmp/eduka-block-install.XXXXXX)
trap 'rm -rf "$WORK"' EXIT INT TERM
chmod 0755 "$WORK"
say "Unpacking Eduka-Block and its dependencies…"
extract "$WORK"
# shellcheck disable=SC1091
. "$WORK/bundle.env"

ARCH=$(dpkg --print-architecture)
[ "$ARCH" = "$BUNDLE_ARCH" ] || fail "this bundle is for $BUNDLE_ARCH computers, but this computer is $ARCH"
if [ -r /etc/os-release ]; then
    # shellcheck disable=SC1091
    CODENAME=$( . /etc/os-release; printf '%s' "${VERSION_CODENAME:-}" )
    if [ -n "$CODENAME" ] && [ "$CODENAME" != "$BUNDLE_CODENAME" ]; then
        say "Note: bundle built for '$BUNDLE_CODENAME', this system is '$CODENAME'. Continuing."
    fi
fi

# A private APT configuration that only sees the bundled repository. The
# system's own package lists and sources are not touched.
mkdir -p "$WORK/apt/lists/partial" "$WORK/apt/sources.list.d"
printf 'deb [trusted=yes] file:%s ./\n' "$WORK/repo" > "$WORK/apt/sources.list"
set -- \
    -o "Dir::Etc::SourceList=$WORK/apt/sources.list" \
    -o "Dir::Etc::SourceParts=$WORK/apt/sources.list.d" \
    -o "Dir::State::Lists=$WORK/apt/lists" \
    -o "APT::Get::List-Cleanup=false" \
    -o "Acquire::Languages=none"

say "Installing Eduka-Block $BUNDLE_VERSION (offline, $(ls "$WORK/repo" | grep -c '\.deb$') packages in bundle)…"
apt-get "$@" -qq update
if DEBIAN_FRONTEND=noninteractive apt-get "$@" install -y --no-install-recommends eduka-block; then
    say "Eduka-Block $BUNDLE_VERSION is installed. Open it from the menu: System → Eduka-Block."
    exit 0
fi

[ "$OFFLINE_ONLY" -eq 0 ] || fail "offline installation was not possible on this system"
say "Some dependencies are missing from the bundle or too old on this computer."
say "Trying the normal package sources (internet connection required)…"
apt-get update
DEBIAN_FRONTEND=noninteractive apt-get install -y "$WORK"/repo/eduka-block_*.deb
say "Eduka-Block $BUNDLE_VERSION is installed. Open it from the menu: System → Eduka-Block."
exit 0
__EDUKA_BLOCK_PAYLOAD__

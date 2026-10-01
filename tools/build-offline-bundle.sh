#!/bin/sh
# Build a single-file offline installer: Eduka-Block plus all dependencies.
#
# Run on the distribution you are targeting (Debian 13 "trixie" for
# Edukasaun OS), as root, with internet access — for example in a container:
#
#     docker run --rm -v "$PWD:/src" -w /src debian:trixie \
#         sh -c 'apt-get update && apt-get install -y dpkg-dev && tools/build-offline-bundle.sh'
#
# CI does exactly this on every push (see .github/workflows/ci.yml) and
# attaches the result to GitHub releases.
#
# Output: dist/eduka-block-<version>-offline-<codename>-<arch>.run
#
# Dependencies are resolved against an EMPTY package database, so the bundle
# contains the complete dependency tree and works even on a minimal system.
# APT installs only what the target computer is actually missing.
set -eu

PROJECT_DIR=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
DIST_DIR="$PROJECT_DIR/dist"

say() { printf '==> %s\n' "$*"; }
fail() { printf 'build-offline-bundle: %s\n' "$*" >&2; exit 1; }

[ "$(id -u)" -eq 0 ] || fail "run as root (APT needs it to download packages)"
command -v apt-get >/dev/null 2>&1 || fail "APT is required"
command -v dpkg-scanpackages >/dev/null 2>&1 || fail "dpkg-scanpackages is required: apt-get install dpkg-dev"

APP_VERSION=$(sed -n 's/^APP_VERSION = "\(.*\)"$/\1/p' "$PROJECT_DIR/src/eduka_block_common.py")
DEB=$(ls "$DIST_DIR"/eduka-block_"$APP_VERSION"-*_all.deb 2>/dev/null | tail -n 1 || true)
if [ -z "$DEB" ]; then
    say "Building the Eduka-Block package first"
    "$PROJECT_DIR/build.sh"
    DEB=$(ls "$DIST_DIR"/eduka-block_"$APP_VERSION"-*_all.deb | tail -n 1)
fi

ARCH=$(dpkg --print-architecture)
CODENAME=$( . /etc/os-release; printf '%s' "${VERSION_CODENAME:-unknown}" )
OUTPUT="$DIST_DIR/eduka-block-$APP_VERSION-offline-$CODENAME-$ARCH.run"

WORK=$(mktemp -d)
trap 'rm -rf "$WORK"' EXIT INT TERM
mkdir -p "$WORK/apt/state/lists/partial" "$WORK/apt/cache/archives/partial" "$WORK/stage/repo"
: > "$WORK/apt/status"
set -- \
    -o "Dir::State=$WORK/apt/state" \
    -o "Dir::State::status=$WORK/apt/status" \
    -o "Dir::Cache=$WORK/apt/cache" \
    -o "Debug::NoLocking=1" \
    -o "APT::Install-Recommends=false" \
    -o "APT::Sandbox::User=root"

say "Resolving dependencies of $(basename "$DEB") for $CODENAME/$ARCH"
apt-get "$@" -qq update
apt-get "$@" install --download-only -y -qq "$DEB"

cp "$WORK"/apt/cache/archives/*.deb "$WORK/stage/repo/"
cp "$DEB" "$WORK/stage/repo/"
say "Bundling $(ls "$WORK"/apt/cache/archives/*.deb | wc -l) dependencies + Eduka-Block"

(cd "$WORK/stage/repo" && dpkg-scanpackages --multiversion . /dev/null > Packages 2>/dev/null)
gzip -9nk "$WORK/stage/repo/Packages"
cat > "$WORK/stage/bundle.env" <<EOF
BUNDLE_VERSION='$APP_VERSION'
BUNDLE_ARCH='$ARCH'
BUNDLE_CODENAME='$CODENAME'
EOF

mkdir -p "$DIST_DIR"
cp "$PROJECT_DIR/tools/offline-installer.sh" "$OUTPUT"
tar -C "$WORK/stage" -czf - . >> "$OUTPUT"
chmod 0755 "$OUTPUT"
(cd "$DIST_DIR" && sha256sum "$(basename "$OUTPUT")" > "$(basename "$OUTPUT").sha256")
say "Built: $OUTPUT ($(du -h "$OUTPUT" | cut -f1))"

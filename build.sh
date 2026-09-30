#!/bin/sh
set -eu

PROJECT_DIR=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
PACKAGE_NAME=eduka-block
PACKAGE_VERSION=0.4.1-1
BUILD_ROOT="$PROJECT_DIR/.build/${PACKAGE_NAME}_${PACKAGE_VERSION}_all"
DIST_DIR="$PROJECT_DIR/dist"
SOURCE_DATE_EPOCH=${SOURCE_DATE_EPOCH:-1788566400}
export SOURCE_DATE_EPOCH

if [ -d "$BUILD_ROOT" ]; then
    find "$BUILD_ROOT" -mindepth 1 -delete
fi
install -d "$BUILD_ROOT/DEBIAN"
install -d "$BUILD_ROOT/usr/bin"
install -d "$BUILD_ROOT/usr/lib/eduka-block"
install -d "$BUILD_ROOT/usr/share/eduka-block"
install -d "$BUILD_ROOT/usr/share/Eduka-Block"
install -d "$BUILD_ROOT/usr/share/applications"
install -d "$BUILD_ROOT/usr/share/icons/hicolor/scalable/apps"
install -d "$BUILD_ROOT/usr/share/metainfo"
install -d "$BUILD_ROOT/usr/share/polkit-1/actions"
install -d "$BUILD_ROOT/usr/lib/systemd/system"
install -d "$BUILD_ROOT/etc/NetworkManager/conf.d"
install -d "$BUILD_ROOT/etc/NetworkManager/dnsmasq.d"
install -d "$BUILD_ROOT/usr/share/doc/eduka-block"

install -m 0644 "$PROJECT_DIR/packaging/control" "$BUILD_ROOT/DEBIAN/control"
install -m 0755 "$PROJECT_DIR/packaging/postinst" "$BUILD_ROOT/DEBIAN/postinst"
install -m 0755 "$PROJECT_DIR/packaging/prerm" "$BUILD_ROOT/DEBIAN/prerm"
install -m 0755 "$PROJECT_DIR/packaging/postrm" "$BUILD_ROOT/DEBIAN/postrm"

install -m 0755 "$PROJECT_DIR/src/eduka_block.py" "$BUILD_ROOT/usr/bin/eduka-block"
install -m 0755 "$PROJECT_DIR/src/eduka_block_helper.py" "$BUILD_ROOT/usr/lib/eduka-block/eduka-block-helper"
install -m 0644 "$PROJECT_DIR/src/eduka_block_common.py" "$BUILD_ROOT/usr/lib/eduka-block/eduka_block_common.py"
install -m 0644 "$PROJECT_DIR/src/eduka_block_i18n.py" "$BUILD_ROOT/usr/lib/eduka-block/eduka_block_i18n.py"
install -m 0644 "$PROJECT_DIR/assets/eduka-block.css" "$BUILD_ROOT/usr/share/eduka-block/eduka-block.css"
install -m 0644 "$PROJECT_DIR/assets/eduka-block.svg" "$BUILD_ROOT/usr/share/icons/hicolor/scalable/apps/eduka-block.svg"
install -m 0644 "$PROJECT_DIR/data/eduka-block.desktop" "$BUILD_ROOT/usr/share/applications/eduka-block.desktop"
install -m 0644 "$PROJECT_DIR/data/org.edukasaun.edukablock.metainfo.xml" "$BUILD_ROOT/usr/share/metainfo/org.edukasaun.edukablock.metainfo.xml"
install -m 0644 "$PROJECT_DIR/data/org.edukasaun.edukablock.policy" "$BUILD_ROOT/usr/share/polkit-1/actions/org.edukasaun.edukablock.policy"
install -m 0644 "$PROJECT_DIR/data/eduka-block-firewall.service" "$BUILD_ROOT/usr/lib/systemd/system/eduka-block-firewall.service"
install -m 0644 "$PROJECT_DIR/data/eduka-block-sync.service" "$BUILD_ROOT/usr/lib/systemd/system/eduka-block-sync.service"
install -m 0644 "$PROJECT_DIR/data/eduka-block-sync.timer" "$BUILD_ROOT/usr/lib/systemd/system/eduka-block-sync.timer"
install -m 0644 "$PROJECT_DIR/data/90-eduka-block-dns.conf" "$BUILD_ROOT/etc/NetworkManager/conf.d/90-eduka-block-dns.conf"
install -m 0644 "$PROJECT_DIR/packaging/copyright" "$BUILD_ROOT/usr/share/doc/eduka-block/copyright"
install -m 0644 "$PROJECT_DIR/README.md" "$BUILD_ROOT/usr/share/doc/eduka-block/README.md"
install -m 0644 "$PROJECT_DIR/SECURITY.md" "$BUILD_ROOT/usr/share/doc/eduka-block/SECURITY.md"
install -m 0644 "$PROJECT_DIR/CHANGELOG.md" "$BUILD_ROOT/usr/share/doc/eduka-block/changelog.gz.in"
install -m 0644 "$PROJECT_DIR/data/share-directory-readme.txt" "$BUILD_ROOT/usr/share/Eduka-Block/README.txt"

gzip -9n "$BUILD_ROOT/usr/share/doc/eduka-block/README.md"
gzip -9n "$BUILD_ROOT/usr/share/doc/eduka-block/SECURITY.md"
gzip -9n < "$BUILD_ROOT/usr/share/doc/eduka-block/changelog.gz.in" > "$BUILD_ROOT/usr/share/doc/eduka-block/changelog.gz"
rm -f "$BUILD_ROOT/usr/share/doc/eduka-block/changelog.gz.in"

install -d "$DIST_DIR"
dpkg-deb --root-owner-group --build "$BUILD_ROOT" "$DIST_DIR/${PACKAGE_NAME}_${PACKAGE_VERSION}_all.deb"
printf 'Built: %s\n' "$DIST_DIR/${PACKAGE_NAME}_${PACKAGE_VERSION}_all.deb"

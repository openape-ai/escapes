#!/usr/bin/env bash
#
# Build and publish a GitHub release on a Mac (replaces the removed release workflow).
#
#   scripts/release.sh --dry-run   build every asset into dist/, publish nothing
#   scripts/release.sh             same, then `gh release create v<version>`
#
# Requires: rustup targets {aarch64,x86_64}-{apple-darwin,unknown-linux-gnu}, `zig` +
# `cargo-zigbuild` (Linux builds, glibc 2.28+), `nfpm` (brew), Xcode command line
# tools, authenticated `gh`.
# The version comes from Cargo.toml; a real release needs a clean checkout whose
# HEAD is the pushed tag v<version>. Asset names match earlier releases because
# `escapes --update` and packaging/install.sh download them by name.
# The .pkg is signed and notarized only when a "Developer ID Installer" identity
# and the notarytool keychain profile "escapes-notary" exist; otherwise unsigned.

set -euo pipefail
cd "$(git rev-parse --show-toplevel)"

DRY_RUN=
[ "${1:-}" = "--dry-run" ] && DRY_RUN=1
VERSION=$(sed -n 's/^version = "\(.*\)"/\1/p' Cargo.toml | head -1)
TAG="v${VERSION}"

if [ -z "$DRY_RUN" ]; then
  [ -z "$(git status --porcelain)" ] || { echo "working tree not clean"; exit 1; }
  [ "$(git rev-parse HEAD)" = "$(git rev-parse "${TAG}^{commit}" 2>/dev/null)" ] \
    || { echo "HEAD is not tag ${TAG}"; exit 1; }
  git ls-remote --exit-code --tags origin "refs/tags/${TAG}" >/dev/null || { echo "${TAG} not pushed"; exit 1; }
  ! gh release view "$TAG" >/dev/null 2>&1 || { echo "release ${TAG} already exists"; exit 1; }
fi

rm -rf dist build && mkdir -p dist build

echo "→ Build binaries"
for t in aarch64-apple-darwin x86_64-apple-darwin; do cargo build --release --target "$t"; done
for t in x86_64-unknown-linux-gnu aarch64-unknown-linux-gnu; do cargo zigbuild --release --target "$t.2.28"; done
bin() { echo "target/$1/release/escapes"; }

echo "→ Tarballs"
for t in aarch64-apple-darwin x86_64-apple-darwin x86_64-unknown-linux-gnu aarch64-unknown-linux-gnu; do
  dir="escapes-${TAG}-${t}"
  mkdir -p "build/$dir"
  cp "$(bin "$t")" config.example.toml LICENSE README.md "build/$dir/"
  chmod +x "build/$dir/escapes"
  tar czf "dist/${dir}.tar.gz" -C build "$dir"
done

echo "→ macOS universal .pkg"
mkdir -p build/root/usr/local/bin build/root/usr/local/share/openape
lipo -create -output build/root/usr/local/bin/escapes "$(bin aarch64-apple-darwin)" "$(bin x86_64-apple-darwin)"
cp config.example.toml build/root/usr/local/share/openape/
pkgbuild --root build/root --scripts packaging/macos/scripts --identifier at.openape.escapes \
  --version "$VERSION" --ownership recommended build/escapes-component.pkg
PKG="dist/escapes-${TAG}-macos-universal.pkg"
productbuild --distribution packaging/macos/distribution.xml --package-path build --version "$VERSION" "$PKG"
INSTALLER_ID=$(security find-identity -v | sed -n 's/.*"\(Developer ID Installer: [^"]*\)".*/\1/p' | head -1)
if [ -n "$INSTALLER_ID" ]; then
  productsign --sign "$INSTALLER_ID" "$PKG" build/signed.pkg && mv build/signed.pkg "$PKG"
  [ -n "$DRY_RUN" ] || { xcrun notarytool submit "$PKG" --keychain-profile escapes-notary --wait && xcrun stapler staple "$PKG"; }
else
  echo "⚠ no Developer ID Installer identity: .pkg stays unsigned"
fi

echo "→ Linux .deb/.rpm"
for pair in amd64:x86_64-unknown-linux-gnu arm64:aarch64-unknown-linux-gnu; do
  cp "$(bin "${pair#*:}")" escapes
  for p in deb rpm; do ARCH="${pair%%:*}" VERSION="$VERSION" nfpm package --config packaging/linux/nfpm.yaml --packager "$p" --target dist/; done
  rm escapes
done

(cd dist && shasum -a 256 -- * > checksums-sha256.txt)
cp packaging/install.sh packaging/macos/uninstall.sh dist/
ls -1 dist

if [ -n "$DRY_RUN" ]; then echo "✓ dry run: assets in dist/, nothing published"; exit 0; fi
gh release create "$TAG" --verify-tag --generate-notes dist/*
echo "✓ released ${TAG}"

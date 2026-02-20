#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
MANIFEST_PATH="$ROOT_DIR/Cargo.toml"
DIST_DIR="${DIST_DIR:-$ROOT_DIR/dist}"

TAG="${1:-${GITHUB_REF_NAME:-dev}}"
TARGET="${2:-${RUST_TARGET:-x86_64-unknown-linux-gnu}}"

if [[ ! -f "$MANIFEST_PATH" ]]; then
  echo "Cargo.toml not found at $MANIFEST_PATH" >&2
  exit 1
fi

mkdir -p "$DIST_DIR"

case "$TARGET" in
  *windows*) BIN_NAME="vulnera.exe" ;;
  *) BIN_NAME="vulnera" ;;
esac

PACKAGE_NAME="vulnera-cli-${TAG}-${TARGET}"
PACKAGE_DIR="$DIST_DIR/$PACKAGE_NAME"
ARCHIVE_PATH="$DIST_DIR/${PACKAGE_NAME}.tar.gz"
CHECKSUM_PATH="$DIST_DIR/${PACKAGE_NAME}.sha256"

rm -rf "$PACKAGE_DIR" "$ARCHIVE_PATH" "$CHECKSUM_PATH"
mkdir -p "$PACKAGE_DIR"

echo "Building $PACKAGE_NAME"
cargo build --release --manifest-path "$MANIFEST_PATH" --target "$TARGET"

BIN_PATH="$ROOT_DIR/target/$TARGET/release/$BIN_NAME"
if [[ ! -f "$BIN_PATH" ]]; then
  echo "Built binary not found: $BIN_PATH" >&2
  exit 1
fi

cp "$BIN_PATH" "$PACKAGE_DIR/$BIN_NAME"
cp "$ROOT_DIR/README.md" "$PACKAGE_DIR/README.md"
cp "$ROOT_DIR/CHANGELOG.md" "$PACKAGE_DIR/CHANGELOG.md"

tar -C "$DIST_DIR" -czf "$ARCHIVE_PATH" "$PACKAGE_NAME"

if command -v sha256sum >/dev/null 2>&1; then
  (cd "$DIST_DIR" && sha256sum "$(basename "$ARCHIVE_PATH")" > "$(basename "$CHECKSUM_PATH")")
elif command -v shasum >/dev/null 2>&1; then
  (cd "$DIST_DIR" && shasum -a 256 "$(basename "$ARCHIVE_PATH")" > "$(basename "$CHECKSUM_PATH")")
else
  echo "No checksum utility found (sha256sum/shasum)." >&2
  exit 1
fi

echo "Artifacts generated:"
echo "  $ARCHIVE_PATH"
echo "  $CHECKSUM_PATH"

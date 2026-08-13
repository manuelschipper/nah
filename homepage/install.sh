#!/bin/sh
# nah installer — https://nahguard.ai
# Downloads the latest release binary for this machine, verifies its
# checksum, and installs it to ~/.local/bin (no sudo). Override the
# version with NAH_VERSION=v1.3.1 or the directory with NAH_INSTALL_DIR.
set -eu

REPO="manuelschipper/nah"
BIN_DIR="${NAH_INSTALL_DIR:-$HOME/.local/bin}"

os=$(uname -s)
arch=$(uname -m)
case "$arch" in
  x86_64|amd64) arch="x86_64" ;;
  arm64|aarch64) arch="aarch64" ;;
  *) echo "nah: unsupported architecture: $arch" >&2; exit 1 ;;
esac
case "$os" in
  Linux) target="$arch-unknown-linux-musl" ;;
  Darwin) target="$arch-apple-darwin" ;;
  *) echo "nah: unsupported OS: $os (Linux and macOS only for now)" >&2; exit 1 ;;
esac

if [ -n "${NAH_VERSION:-}" ]; then
  base="https://github.com/$REPO/releases/download/$NAH_VERSION"
else
  base="https://github.com/$REPO/releases/latest/download"
fi
asset="nah-$target.tar.gz"

tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT

echo "downloading $asset ..."
if ! curl -fsSL -o "$tmp/$asset" "$base/$asset"; then
  echo "nah: download failed: $base/$asset" >&2
  echo "nah: either no release is published yet, or this target is not built." >&2
  exit 1
fi
curl -fsSL -o "$tmp/sha256sums.txt" "$base/sha256sums.txt"

(
  cd "$tmp"
  expected=$(awk -v asset="$asset" '
    $2 == asset && length($1) == 64 && $1 !~ /[^0-9A-Fa-f]/ { print tolower($1) }
  ' sha256sums.txt)
  if [ -z "$expected" ]; then
    echo "nah: checksum not found for $asset" >&2
    exit 1
  fi
  if command -v sha256sum >/dev/null 2>&1; then
    output=$(sha256sum "$asset")
  elif command -v shasum >/dev/null 2>&1; then
    output=$(shasum -a 256 "$asset")
  else
    echo "nah: SHA-256 tool not found (need sha256sum or shasum)" >&2
    exit 1
  fi
  actual=$(printf '%s\n' "$output" | awk '
    NR == 1 && length($1) == 64 && $1 !~ /[^0-9A-Fa-f]/ { print tolower($1) }
  ')
  if [ "$actual" != "$expected" ]; then
    echo "nah: checksum mismatch for $asset" >&2
    exit 1
  fi
)
echo "checksum ok"

mkdir -p "$BIN_DIR"
tar -C "$tmp" -xzf "$tmp/$asset" nah
mv "$tmp/nah" "$BIN_DIR/nah"
chmod +x "$BIN_DIR/nah"

echo "installed $("$BIN_DIR/nah" --version 2>/dev/null || echo nah) to $BIN_DIR/nah"

# an earlier nah on PATH still wins, and a stale one keeps guarding the
# agent while you think this install took effect
hash -r 2>/dev/null || true
found=$(command -v nah 2>/dev/null || true)
if [ -z "$found" ]; then
  echo
  echo "note: $BIN_DIR is not on your PATH; add it to your shell profile."
elif [ "$found" != "$BIN_DIR/nah" ]; then
  echo
  echo "warning: another nah comes first on your PATH:"
  echo "  $found ($("$found" --version 2>/dev/null || echo 'unknown version'))"
  echo "remove it, or put $BIN_DIR ahead of it in your shell profile."
  echo "the 0.x Python line is no longer supported; 'pip uninstall nah'"
  echo "in the environment that owns it clears the way."
fi
echo
echo "next: nah docs start"

#!/usr/bin/env bash
# Preserve Cargo binary-path environment names, which can contain hyphens.
set -eu

# Cargo may prepend a workspace wrapper such as clippy-driver, which expects the
# real rustc as its first argument, so the remap flag goes last. The root is the
# parent of this script's directory: archive builds have no .git to ask.
root=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd -P)
exec "$@" --remap-path-prefix="$root"=.

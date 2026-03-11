#!/usr/bin/env bash
# Build nah docs and copy to schipper.ai Hugo static dir.
# Usage: ./scripts/deploy-docs.sh

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
NAH_ROOT="$(dirname "$SCRIPT_DIR")"
SCHIPPER_AI="${SCHIPPER_AI:-$HOME/workspace/manuelschipper/schipper.ai}"

if [ ! -d "$SCHIPPER_AI" ]; then
  echo "error: schipper.ai repo not found at $SCHIPPER_AI" >&2
  echo "  set SCHIPPER_AI env var to override" >&2
  exit 1
fi

echo "Building nah docs..."
python -m mkdocs build -f "$NAH_ROOT/mkdocs.yml"

echo "Copying to $SCHIPPER_AI/static/nah/..."
rm -rf "$SCHIPPER_AI/static/nah"
cp -r "$NAH_ROOT/_build" "$SCHIPPER_AI/static/nah"

echo "Done — run 'hugo' in schipper.ai to rebuild the site."

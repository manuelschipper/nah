#!/bin/sh
# Stands in for curl when testing install.sh: answers the installer's
# `curl -fsSL -o DEST URL` from the local release directory
# NAH_TEST_RELEASE_DIR, and fails as `curl -f` does when the asset is missing.
set -eu
[ "$#" -eq 4 ] && [ "$1" = "-fsSL" ] && [ "$2" = "-o" ] || exit 2
cp "$NAH_TEST_RELEASE_DIR/${4##*/}" "$3" 2>/dev/null || exit 22

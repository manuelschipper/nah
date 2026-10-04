#!/bin/sh
# Tests homepage/install.sh against a fake release served from a local
# directory: no network, and nothing outside a temporary directory is touched.
# Each case builds the PATH the installer sees, which decides the SHA-256 tool
# it finds and whether another `nah` shadows the one it installs.
set -eu

here=$(cd "$(dirname "$0")" && pwd)
installer="$here/../install.sh"
work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT

fail() {
  echo "FAIL: $1" >&2
  cat "$work/out" >&2
  exit 1
}

# The host's real SHA-256 command. The `sha256sum` and `shasum` the installer
# sees are wrappers over it, so both of its branches run on every host,
# whichever tool the host ships.
if command -v sha256sum >/dev/null 2>&1; then
  hasher=$(command -v sha256sum)
else
  hasher="$(command -v shasum) -a 256"
fi

# The release: one archive laid out as release.yml packages it, published
# under every Unix asset name so the installer finds this machine's target.
mkdir -p "$work/pkg" "$work/release"
printf '#!/bin/sh\necho "nah 9.9.9"\n' >"$work/pkg/nah"
chmod +x "$work/pkg/nah"
echo license >"$work/pkg/LICENSE"
tar -C "$work/pkg" -czf "$work/release/nah.tar.gz" nah LICENSE
for target in x86_64-unknown-linux-musl aarch64-unknown-linux-musl \
  x86_64-apple-darwin aarch64-apple-darwin; do
  cp "$work/release/nah.tar.gz" "$work/release/nah-$target.tar.gz"
done
rm "$work/release/nah.tar.gz"
(cd "$work/release" && for asset in nah-*.tar.gz; do $hasher "$asset"; done >sha256sums.txt)

# The same archives with every checksum replaced by one for other bytes.
mkdir "$work/tampered"
cp "$work/release"/nah-*.tar.gz "$work/tampered/"
other=$($hasher "$work/pkg/LICENSE" | awk '{ print $1 }')
awk -v other="$other" '{ print other "  " $2 }' "$work/release/sha256sums.txt" \
  >"$work/tampered/sha256sums.txt"

# The same archives with a checksum file that lists none of them.
mkdir "$work/unlisted"
cp "$work/release"/nah-*.tar.gz "$work/unlisted/"
echo "$other  some-other-asset.tar.gz" >"$work/unlisted/sha256sums.txt"

# What the installer needs besides a SHA-256 tool, and nothing else.
mkdir "$work/base"
for tool in uname mktemp awk tar gzip mkdir mv cp chmod rm; do
  ln -s "$(command -v "$tool")" "$work/base/$tool"
done
cp "$here/local-release-curl.sh" "$work/base/curl"
chmod +x "$work/base/curl"

mkdir "$work/sha256sum" "$work/shasum" "$work/shadow"
cat >"$work/sha256sum/sha256sum" <<WRAPPER
#!/bin/sh
[ "\$#" -eq 1 ] || exit 2
exec $hasher "\$1"
WRAPPER
cat >"$work/shasum/shasum" <<WRAPPER
#!/bin/sh
[ "\$#" -eq 3 ] && [ "\$1" = "-a" ] && [ "\$2" = "256" ] || exit 2
exec $hasher "\$3"
WRAPPER
printf '#!/bin/sh\necho "nah 0.0.1"\n' >"$work/shadow/nah"
chmod +x "$work/sha256sum/sha256sum" "$work/shasum/shasum" "$work/shadow/nah"

# run_install RELEASE BIN_DIR PATH: runs the installer, keeping its output.
run_install() {
  NAH_TEST_RELEASE_DIR="$work/$1" NAH_INSTALL_DIR="$2" PATH="$3" HOME="$work/home" \
    /bin/sh "$installer" >"$work/out" 2>&1
}

installed() {
  [ "$("$1/nah" --version 2>/dev/null)" = "nah 9.9.9" ]
}

bin="$work/with-sha256sum"
run_install release "$bin" "$bin:$work/base:$work/sha256sum" || fail "sha256sum: installer failed"
installed "$bin" || fail "sha256sum: nah was not installed"
grep -q "warning:" "$work/out" && fail "sha256sum: warned although the installed nah comes first"

bin="$work/with-shasum"
run_install release "$bin" "$bin:$work/base:$work/shasum" || fail "shasum: installer failed"
installed "$bin" || fail "shasum: nah was not installed"

bin="$work/without-hasher"
run_install release "$bin" "$bin:$work/base" && fail "no SHA-256 tool: installer succeeded"
[ -e "$bin/nah" ] && fail "no SHA-256 tool: nah was installed unverified"

# A rejected download must also leave an existing installation as it was.
bin="$work/with-mismatch"
mkdir "$bin"
cp "$work/shadow/nah" "$bin/nah"
run_install tampered "$bin" "$bin:$work/base:$work/sha256sum" && fail "mismatch: installer succeeded"
cmp -s "$work/shadow/nah" "$bin/nah" || fail "mismatch: the existing nah was replaced"

bin="$work/with-unlisted"
run_install unlisted "$bin" "$bin:$work/base:$work/sha256sum" && fail "unlisted: installer succeeded"
[ -e "$bin/nah" ] && fail "unlisted: nah was installed unverified"

bin="$work/shadowed"
run_install release "$bin" "$work/shadow:$bin:$work/base:$work/sha256sum" || fail "shadowed: installer failed"
installed "$bin" || fail "shadowed: nah was not installed"
grep -q "warning:" "$work/out" && grep -q "$work/shadow/nah" "$work/out" ||
  fail "shadowed: no warning names the nah that comes first on PATH"

echo "install.sh: all cases passed"

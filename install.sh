#!/bin/sh
# Installs the code-watch release binary for this machine into a user directory, without sudo.
# Download it, read it, then run it: sh install.sh
#
# CODE_WATCH_VERSION      release to install, with or without a leading v (default: latest)
# CODE_WATCH_INSTALL_DIR  where to put the binary (default: $HOME/.local/bin)
# CODE_WATCH_BASE_URL     releases root, for tests and mirrors only
#                         (default: https://github.com/Boundtec/code-watch/releases)
set -eu

base_url=${CODE_WATCH_BASE_URL:-https://github.com/Boundtec/code-watch/releases}
install_dir=${CODE_WATCH_INSTALL_DIR:-${HOME:?HOME is not set}/.local/bin}

fail() {
    echo "code-watch install: $*" >&2
    exit 1
}

case "$(uname -s)" in
    Darwin) os=apple-darwin ;;
    Linux) os=unknown-linux-musl ;;
    *) fail "unsupported operating system: $(uname -s)" ;;
esac
case "$(uname -m)" in
    arm64 | aarch64) arch=aarch64 ;;
    x86_64 | amd64) arch=x86_64 ;;
    *) fail "unsupported architecture: $(uname -m)" ;;
esac
target="$arch-$os"

if [ -n "${CODE_WATCH_VERSION:-}" ]; then
    release_url="$base_url/download/v${CODE_WATCH_VERSION#v}"
else
    release_url="$base_url/latest/download"
fi

if command -v sha256sum >/dev/null 2>&1; then
    sha256() { sha256sum "$1" | cut -d ' ' -f 1; }
elif command -v shasum >/dev/null 2>&1; then
    sha256() { shasum -a 256 "$1" | cut -d ' ' -f 1; }
else
    fail "neither sha256sum nor shasum is available"
fi

tmp=$(mktemp -d "${TMPDIR:-/tmp}/code-watch-install.XXXXXX") || fail "cannot create a temporary directory"
staged=
cleanup() {
    rm -rf "$tmp"
    if [ -n "$staged" ]; then rm -f "$staged"; fi
}
trap cleanup EXIT
trap 'exit 1' HUP INT TERM

download() {
    curl -fsSL --connect-timeout 15 --max-time 120 -o "$2" "$1" || fail "download failed: $1"
}

download "$release_url/SHA256SUMS" "$tmp/SHA256SUMS"

# The archive name carries the version, so for "latest" it comes from the one line for this target.
lines=$(grep -E "^[0-9a-f]{64}  code-watch-[^ /]+-$target\.tar\.gz\$" "$tmp/SHA256SUMS" || true)
if [ -n "${CODE_WATCH_VERSION:-}" ]; then
    lines=$(printf '%s\n' "$lines" | grep -F "  code-watch-${CODE_WATCH_VERSION#v}-$target.tar.gz" || true)
fi
[ -n "$lines" ] || fail "SHA256SUMS has no entry for $target"
[ "$(printf '%s\n' "$lines" | wc -l)" -eq 1 ] || fail "SHA256SUMS has more than one entry for $target"
expected=${lines%%  *}
archive=${lines#*  }

download "$release_url/$archive" "$tmp/$archive"
actual=$(sha256 "$tmp/$archive")
[ "$actual" = "$expected" ] || fail "checksum mismatch for $archive, nothing installed"

tar -xzf "$tmp/$archive" -C "$tmp" || fail "cannot extract $archive"
binary="$tmp/${archive%.tar.gz}/code-watch"
[ -f "$binary" ] || fail "$archive has no code-watch binary"

mkdir -p "$install_dir" || fail "cannot create $install_dir"
# Copy beside the target and rename over it: replaces the file even while the old binary is running.
staged="$install_dir/.code-watch.new.$$"
cp "$binary" "$staged" || fail "cannot write into $install_dir"
chmod 755 "$staged"
mv -f "$staged" "$install_dir/code-watch" || fail "cannot install into $install_dir"
staged=

echo "installed code-watch ($archive) to $install_dir/code-watch"
case ":$PATH:" in
    *":$install_dir:"*) ;;
    *) echo "add it to your PATH: export PATH=\"$install_dir:\$PATH\"" ;;
esac

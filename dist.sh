#!/bin/sh
# Builds dist/: Linux x86_64 and aarch64 servers, and (if cargo-zigbuild is
# installed) a universal macOS client with both Linux binaries embedded.
set -e
cd "$(dirname "$0")"
[ -x "$HOME/tools/zig/zig" ] && PATH="$HOME/tools/zig:$PATH"
mkdir -p dist
cargo build --release --target aarch64-unknown-linux-musl
cp target/aarch64-unknown-linux-musl/release/ussh dist/ussh-linux-aarch64
USSH_EMBED_DIR=dist cargo build --release --target x86_64-unknown-linux-musl
cp target/x86_64-unknown-linux-musl/release/ussh dist/ussh-linux-x86_64
if command -v cargo-zigbuild >/dev/null; then
  USSH_EMBED_DIR="$PWD/dist" cargo zigbuild --release --target universal2-apple-darwin
  cp target/universal2-apple-darwin/release/ussh dist/ussh-macos
fi
ls -la dist

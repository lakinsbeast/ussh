#!/bin/sh
# One-time: installs zig (~/tools/zig) and cargo-zigbuild so dist.sh can
# also build the macOS client. No root needed.
set -e
. "$HOME/.cargo/env"
if [ ! -x "$HOME/tools/zig/zig" ]; then
  V=$(curl -s https://ziglang.org/download/index.json | python3 -c "import json,sys; d=json.load(sys.stdin); print(sorted([k for k in d if k!='master'], key=lambda v:[int(x) for x in v.split('.')])[-1])")
  URL=$(curl -s https://ziglang.org/download/index.json | python3 -c "import json,sys; print(json.load(sys.stdin)['$V']['x86_64-linux']['tarball'])")
  echo "zig $V: $URL"
  mkdir -p "$HOME/tools/zig"
  curl -sSfL "$URL" | tar -xJ -C "$HOME/tools/zig" --strip-components=1
fi
"$HOME/tools/zig/zig" version
command -v cargo-zigbuild >/dev/null || cargo install cargo-zigbuild
rustup target add x86_64-apple-darwin aarch64-apple-darwin aarch64-unknown-linux-musl x86_64-unknown-linux-musl
echo "ok: now run ./dist.sh"

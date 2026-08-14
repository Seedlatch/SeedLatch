#!/usr/bin/env bash
#
# Build the WASM module with absolute build paths remapped out of it.
#
# Use this instead of calling wasm-pack directly. A plain `wasm-pack build` embeds the
# build machine's absolute paths in the module — the maintainer's home directory and
# operating-system account name, in the file every user downloads, for a project published
# under a pseudonym.
#
# `[profile.release] trim-paths = "all"` would be the tidy fix, but it is not stabilised in
# the pinned Cargo (1.96). `--remap-path-prefix` is, and it needs the literal local prefix
# — which must never be written into a tracked file, since that would put the username in
# the repository to keep it out of the binary. So the prefixes are computed here, at run
# time, from the environment.
#
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cargo_home="${CARGO_HOME:-$HOME/.cargo}"

# rustc records paths in the platform's native form. Under Git Bash the shell reports
# slash-separated POSIX paths while rustc emits the native Windows form, drive letter and
# backslashes, so a POSIX prefix would silently fail to match and the remap would quietly do
# nothing — the worst outcome, because the build still succeeds and the leak is still there.
#
# The two forms are described rather than written out. scripts/check-identifiers.mjs treats
# a drive letter followed by a separator as an identifier wherever it appears, and a comment
# is not worth an exception in a gate whose value is that it has none.
if command -v cygpath >/dev/null 2>&1; then
  repo_root="$(cygpath -w "$repo_root")"
  cargo_home="$(cygpath -w "$cargo_home")"
fi

export RUSTFLAGS="${RUSTFLAGS:-} --remap-path-prefix=${cargo_home}=/cargo --remap-path-prefix=${repo_root}=/seedlatch"

echo "building with remapped paths…"
wasm-pack build --release --target web --out-dir web/pkg "$@"

echo
echo "checking artefacts for absolute paths…"
node "${BASH_SOURCE[0]%/*}/check-artifact-paths.mjs" \
  web/pkg/seedlatch_bg.wasm \
  web/pkg/seedlatch.js

# Toolchains and the reproducible-build claim

The claim this project makes is *nothing leaves your browser, here is the hash to verify
it*. That claim is only as strong as the least-pinned thing that produced the hash.

**Three toolchains feed the build.** Every one of them must be pinned, and every one of
them is part of what a verifier has to reproduce.

**No version numbers appear in this document.** Each is stated in exactly one place, and
this table points at it. A version restated in prose is a version that drifts from the file
that actually controls the build — which is precisely how `dtolnay/rust-toolchain@stable`
in CI silently overrode `rust-toolchain.toml` before it was caught.

| | Authoritative pin | Produces | Live today? |
|---|---|---|---|
| Rust | `rust-toolchain.toml` | the WASM module | yes |
| esbuild | `web/package.json` + `web/package-lock.json` | the JS bundle | yes |
| Node | `web/package.json` `engines.node` | runs esbuild | yes |
| clang | `.github/workflows/ci.yml`, the `Install pinned clang` step | libsecp256k1, compiled to WASM | **dormant** |

**clang is dormant until week 2.** It is needed only by `secp256k1-sys`, which arrives with
`miniscript`, which is currently not declared because no code references it yet
(`Cargo.toml` explains why). Today the browser build needs no C compiler at all. The CI
step that installs clang is kept so the job is ready when the dependency returns, but be
clear that it is currently exercising nothing.

Node is the fourth input. CI reads it with `node-version-file: web/package.json` rather
than naming it again in the workflow, for the same reason.

---

## Rust

`rust-toolchain.toml` pins the channel exactly, so `cargo build` uses that compiler
regardless of a developer's default. `Cargo.lock` is committed (see `.gitignore`, which
says why). `[profile.release]` sets `codegen-units = 1` and disables incremental
compilation, both of which are required for deterministic output.

## clang — the one that is easy to forget

**Not currently required. This section describes what happens when `miniscript` returns in
week 2**, and is kept because the requirement is real and easy to rediscover the hard way.

It was rediscovered the hard way once already: `miniscript` was declared before any code
used it, which put `secp256k1-sys` in the tree, which made
`cargo build --target wasm32-unknown-unknown` impossible on any host without clang — and
so `src/wasm.rs`, the whole browser boundary, went three rounds without being compiled or
linked even once while the frontend was written against it. A dependency added ahead of its
first caller bought nothing and cost a verification path.

`secp256k1-sys` vendors upstream libsecp256k1 as C and compiles it with `cc`. There is no
pure-Rust fallback: `secp256k1` has no Rust backend and `bitcoin` 0.32 declares it
non-optionally. It cannot be avoided by scope either — BIP-32 public child derivation is
elliptic-curve point addition, and invariant 5 forbids writing that by hand.

The crate supports `wasm32-unknown-unknown` directly. `build.rs` branches on
`CARGO_CFG_TARGET_ARCH == "wasm32"` and adds its own `wasm/wasm-sysroot` and `wasm/wasm.c`.
That sysroot is not a libc: `stdio.h` and `stdlib.h` are zero bytes, `string.h` declares
only `memset`, `memcpy` and `memcmp`, and `printf` is `#define`d away.

So the requirement is exactly **a clang that can emit wasm32**. Not a WASI SDK, not a full
sysroot, not Emscripten.

**Different LLVM versions can emit different WASM from identical C.** The clang version is
therefore a build input on equal footing with the Rust version, and CI pins it explicitly.

The `Record the exact toolchain versions` step in the `wasm` job prints the full version
string of every toolchain on each run. That log is the record — writing the number into
this file as well would be the same duplication the top of this document warns about.

**`cargo audit` cannot see vendored C.** The advisory database covers crates, not the C
inside them. A libsecp256k1 vulnerability surfaces only as a `secp256k1-sys` version bump,
so that crate needs watching by version directly rather than relying on the audit gate.

## esbuild and TypeScript

`web/.npmrc` sets `save-exact=true`, so no caret ranges get written. CI uses `npm ci`,
which fails rather than silently updating if `package.json` and the lockfile disagree.

**Both ship prebuilt platform binaries**, not JavaScript source — esbuild has always, and
TypeScript 7 is the Go rewrite, distributed as `@typescript/typescript-<platform>`. Every
one is pinned by sha512 in `package-lock.json`, so a substituted binary fails installation.
But it is worth being clear-eyed: reproducing this build means trusting prebuilt binaries
from two npm organisations. That is a weaker position than the Rust side, where everything
is compiled from source.

TypeScript is used for type checking only (`npm run typecheck`). esbuild does the
transpiling and bundling, and is the only one of the two whose output reaches a user.

### The bundle ships unminified, with sources, on purpose

`npm run build` does **not** pass `--minify`, and does pass `--sourcemap`. The TypeScript
sources in `web/src/` are published alongside the bundle.

This is a deliberate choice, not esbuild's default behaviour showing through. The reasoning:
the JS toolchain is a prebuilt binary, so a reviewer cannot close the gap by rebuilding —
reproducing the bundle only proves the same binary produces the same output, which is
exactly what a compromised binary would also do. What a reviewer *can* do is read the
shipped JavaScript and compare it to the sources. Minification would remove that, leaving
trust in the binary as the only option.

So: injection stays detectable by reading rather than by reproducing. The frontend is thin
by design and nothing about it is size-sensitive, so this costs nothing worth having.

#### The sourcemap carries source, never state

Checked directly rather than assumed, since shipping one is new. A sourcemap produced by
our build config has exactly five top-level fields and nothing else:

| field | contents |
|---|---|
| `version` | `3` |
| `sources` | paths, relative to the output file |
| `sourcesContent` | the source text, byte-identical to the files on disk |
| `mappings` | VLQ-encoded position mappings |
| `names` | identifier names |

It is a **build-time artefact**. esbuild writes it once and nothing writes to it again —
the browser only reads it, and only when devtools is open. Nothing in the running page
holds a handle to it. There is no mechanism by which a runtime value could enter it, and
that is a property of what a sourcemap *is*, not of how carefully this one is configured.

Two consequences that do need care:

1. **A sourcemap discloses exactly what is in the source**, because `sourcesContent` is a
   verbatim copy. That is fine here — the sources are published deliberately — but it makes
   a standing constraint explicit: **nothing secret may ever be hardcoded in `web/src/`.**
   No endpoint credentials, no keys, no tokens. There are none today.
2. **`sources` paths must stay repo-relative.** Built through `npm run build` from `web/`,
   they come out as `../web/src/…` — no absolute path, no home directory. Built with an
   absolute `--outfile`, esbuild bakes the builder's directory layout into the map, which
   both leaks it and makes the `.map` differ byte-for-byte between machines, breaking the
   reproducibility claim for the very artefact meant to support review. Always build via
   the npm script; never invoke esbuild with an absolute output path.

### What a reviewer can and cannot verify

Stated plainly, because "here is the hash, verify it" means different things on the two
sides of this build.

| | Rust / WASM | JavaScript bundle |
|---|---|---|
| Toolchain provenance | rustc and clang build from source; both open-source and independently buildable | esbuild and tsc are **prebuilt binaries** from npm |
| Dependency source | every crate compiles from source in the local build | n/a — no third-party JavaScript is shipped |
| Reproducing the output | yes: pin the toolchain, rebuild, compare hashes | yes, but it only proves the same binary yields the same bytes |
| Reading the output | no: WASM is a compiled artefact, not meaningfully reviewable by eye | **yes: unminified, sourcemapped, sources published** |
| Vendored C | `secp256k1-sys` bundles libsecp256k1; `cargo audit` cannot see inside it | n/a |

The honest summary: **on the Rust side, trust rests on reproducing the build. On the
JavaScript side, it rests on reading the output.** Neither is complete alone, and the
JavaScript side is the weaker of the two. Anyone claiming otherwise has not read this table.

---

## What ships to the browser

`wasm-bindgen` is gated to `cfg(target_arch = "wasm32")` so native test builds do not carry
it. The two trees differ, and the difference matters when reading `cargo audit`:

```
cargo tree -e normal --target x86_64-pc-windows-msvc   # 14 crates — what the tests compile
cargo tree -e normal --target wasm32-unknown-unknown   # 25 crates — the browser path
```

Per invariant 6, everything in the WASM tree from **outside the rust-bitcoin organisation**,
named rather than absorbed:

| crate | source | ships in the `.wasm`? |
|---|---|---|
| `zeroize` | RustCrypto | yes |
| `arrayvec` | bluss, via `hex-conservative` | yes |
| `wasm-bindgen`, `wasm-bindgen-shared` | rustwasm | yes |
| `bumpalo` | fitzgen, via `wasm-bindgen` | yes |
| `cfg-if`, `once_cell` | rust-lang | yes |
| `wasm-bindgen-macro`, `-macro-support` | rustwasm | no — proc-macro, host-only |
| `proc-macro2`, `quote`, `syn`, `unicode-ident` | dtolnay, via the macro | no — proc-macro, host-only |

The proc-macro crates compile for the build host and expand at compile time. They are in
the dependency graph and they are absolutely part of the trusted build path, but they do
not end up in the shipped binary.

`serde` remains in `Cargo.lock` as an optional feature of the rust-bitcoin crates and is
**not compiled**. Verify with `cargo tree -e normal`. Say so if that changes.

---

## Verifying a published build

1. Check out the tagged commit.
2. `sha256sum -c data/SHA256SUMS` — vendored data is byte-identical.
3. Install the three toolchains at the versions above.
4. `cargo build --release --target wasm32-unknown-unknown`
5. `cd web && npm ci && npm run build`
6. Compare hashes against the published ones.

Any step that requires a version not written down here is a defect in this document.

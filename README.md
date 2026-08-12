# Seedlatch — Exposure Checker

Paste a Bitcoin **descriptor or extended public key**, get a plain-language account of your
wallet's *structural* exposure: how many independent things have to be correct for it to be
safe, and how many of them you can actually verify.

Runs entirely in your browser. Nothing is transmitted, nothing is stored.

> **Status: pre-release, pre-audit. Not published, not usable yet.**
> Week 1 of 4 is complete: secret-material rejection. Everything else is scaffolding.

---

## What it will not tell you

Whether your seed is weak. Nobody can tell you that from a public key — entropy quality is
invisible in one. That is why the defect this tool exists to talk about survived five years
undetected, and it is the argument the tool is built to make.

A tool that *could* confirm a key was weakly generated would be mechanically identical to
the attack on it, and a service holding that knowledge would be the most valuable target in
the space. So this one does not do it, and the architecture is fixed now so that it cannot
quietly start later.

v0 makes **no vendor-specific claim**. It will not say your device or firmware is affected.

## Non-negotiables
1. **No secret material.** Recovery phrases, WIF keys, hex private keys and extended
   private keys are detected and refused before anything else happens — including when
   nested inside an otherwise-valid descriptor.
2. **No transmission of your input.** No backend, no telemetry, no analytics, no error
   reporting. The only outbound call the finished tool will make is an Esplora balance
   lookup, and it will tell you what that leaks before it makes it.
3. **No persistence.** No localStorage, no cookies, no cache. Refresh is a clean slate.
4. **Fail closed.** Ambiguous input is refused and explained, never guessed at.
5. **No hand-rolled crypto.**

## Build and verify

```bash
cargo test
```

```bash
cargo clippy --all-targets -- -D warnings
```

```bash
cargo audit
```

Verify the vendored BIP-39 wordlist against its published hash:

```bash
cd data && sha256sum -c SHA256SUMS
```

The wordlist is additionally re-checked at test time against the properties BIP-39 states
it has — 2048 words, sorted, unique, unique four-letter prefixes — so a substituted list
fails even if someone edits the recorded hash to match. See
[`data/PROVENANCE.md`](data/PROVENANCE.md).

## Layout

```
src/parse/     input handling and secret-material rejection   — implemented
src/wasm.rs    the browser boundary                           — compiled, linked, linted
src/derive/    path enumeration                               — week 3
src/classify/  structural tiers                               — week 4
src/report/    report output                                  — week 4
web/           frontend                                       — boundary and questionnaire only
data/          vendored, hash-pinned reference data
docs/          spec, security model, toolchain, vendor data
tests/         known-answer vectors, detector tests, threshold calibration
```

`web/pkg/` is the wasm-pack output directory and is deliberately gitignored. `npm run
build` fails loudly if it is missing, which is correct: a bundle built without it would
ship a page whose detector does nothing.

## Dependencies

`zeroize`, and `wasm-bindgen` gated to `cfg(target_arch = "wasm32")` so the test suite does
not carry it. That is all of it today.

`rust-miniscript` is approved for all Bitcoin logic and returns in week 2, with the code
that uses it. It is not declared yet because nothing references it, and declaring it early
had a cost: it pulls `secp256k1-sys`, which vendors C and needs a `clang` that can emit
`wasm32`, which made the browser build impossible on any host without one — so the browser
boundary went three rounds unable to be compiled even once. Not `bdk` in any case: it is a
wallet framework whose persistence and chain-sync layers this product is forbidden from
using.

The two trees differ, and the difference is the point:

```bash
cargo tree -e normal --target x86_64-unknown-linux-gnu   # what the tests compile
```

```bash
cargo tree -e normal --target wasm32-unknown-unknown     # what reaches the browser
```

Counts and per-crate provenance are in [`docs/toolchain.md`](docs/toolchain.md) rather than
restated here. Adding anything further requires explicit approval each time, transitive
additions included. A checker that people trust with their wallet layout has no business
pulling in a dependency tree nobody has read.

The browser build currently needs **no C toolchain**. That changes when `rust-miniscript`
returns; see [`docs/toolchain.md`](docs/toolchain.md).

```bash
wasm-pack build --release --target web --out-dir web/pkg
```

`--out-dir web/pkg` is not optional — the frontend resolves the module through the `#core`
subpath import in `web/package.json`, which points there. wasm-pack's default `./pkg`
builds fine and then fails to bundle.

## Contributing

Tests come before implementation in `parse/`, `derive/` and `classify/`, using known-answer
vectors from BIP-32, BIP-39 and BIP-380–386. Reproducing any known-vulnerable derivation is
permanently out of scope here — that code is attack-equivalent.

## Licence

MIT, © 2026 Anton Corvin. See [`LICENSE`](LICENSE).

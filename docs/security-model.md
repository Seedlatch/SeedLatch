# Security model — v0

What this tool protects, what it cannot protect, and the reasoning behind the choices that
are not obvious. Written to be read by someone deciding whether to trust it with a
descriptor, and by whoever performs the independent review before launch.

---

## 1. What the tool is trusted with

A descriptor or extended public key. That is public information — it reveals every address
in the wallet and its whole balance history, but it cannot spend anything.

It is still sensitive. Anyone holding it knows exactly how much a specific person has and
where. So the architecture treats it as private even though it is not secret: nothing is
transmitted, nothing is persisted, and the analysis runs in the browser.

## 2. What the tool must never be trusted with

Anything that can spend: recovery phrases, extended private keys, WIF keys, raw private
keys. The product's job when it sees one is to refuse loudly, immediately, and before
anything else happens.

This is not a hypothetical. The audience is people who have just been told their wallet may
be defective. A meaningful fraction of them will paste a seed phrase into the first box
they see, because they are frightened and the box is there.

## 3. Detection

Two detectors, in `src/parse/`. Both are **shape-based**. Neither base58-decodes, verifies
a BIP-39 checksum, or derives anything.

### Why no checksum validation

The natural implementation — "12/15/18/21/24 words, all in the wordlist, checksum valid" —
fails open in four common cases:

| What the user does | Why the strict check misses it |
|---|---|
| Mistypes one word | Checksum fails, so it "isn't a mnemonic" |
| Pastes a partial phrase (clipped selection) | Word count is wrong |
| Pastes the phrase inside a sentence | Word count is wrong |
| Writes it in 4-letter shorthand | Words are not in the list |

Each of those is still a live seed phrase. So detection instead looks for **a dense region
of wordlist words**, with two triggers:

- **Run** — 8 or more consecutive wordlist words.
- **Density** — 8 or more wordlist words forming at least 3/4 of all tokens.

Both run twice: on exact matches, and allowing 3–4 letter shorthand (BIP-39 guarantees four
letters identify a word uniquely).

### Measured behaviour, not asserted behaviour

The corpus is `tests/fixtures/negative-corpus.txt` — 119 samples across 10 categories.
`cargo test --test calibration -- --nocapture` prints this table; it is regenerated from
the shipped code, not transcribed.

| category | n | longest run | max density | flagged |
|---|---:|---:|---:|---:|
| descriptor | 3 | 0 | 0.00 | 0 |
| address | 4 | 0 | 0.00 | 0 |
| json | 2 | 3 | 0.00 | 0 |
| prose | 4 | 3 | 0.59 | 0 |
| questionnaire-prose | 15 | 3 | 0.53 | 0 |
| support | 5 | 3 | 0.67 | 0 |
| near-miss | 31 | 7 | 0.67 | 0 |
| **questionnaire-terse** | **47** | **10** | **1.00** | **2** |
| **keyword-list** | **5** | **12** | **1.00** | **5** |
| **prose-long-run** | **3** | **10** | **1.00** | **3** |

Triggers are run ≥ 8 and density ≥ 0.75 at ≥ 8 matches.

### Correction: an earlier version of this document was wrong

It said prose stays at a longest run of 3, "a wide margin", because the function words that
hold sentences together are absent from the wordlist. That was inferred from 24 hand-written
samples and it does not survive contact with real English.

`you`, `have`, `make`, `sure`, `some`, `them` and `than` are all in the BIP-39 wordlist.
Scanning **658,092 tokens** of public-domain novels (Austen, Shelley, Melville, Doyle,
Dickens):

| longest run | occurrences | per 100k tokens |
|---:|---:|---:|
| 7 | 20 | 3.04 |
| 8 | 3 | 0.46 |
| 9 | 3 | 0.46 |
| 10 | 1 | 0.15 |

Runs of **8 or more occur 1.22 times per 100,000 tokens** of ordinary prose. Verbatim
examples, now in the corpus as `prose-long-run`:

> `such over this round globe they either lead` (8)
> `will they make you happy have you any other` (9)
> `all right again before long all right again before long` (10)

Shorthand matching is **not** the cause — exact matching alone accounts for 0.91 of those
1.22, so tightening the 4-letter rule would not help and would cost truncated-seed
detection. For a realistic paste of ~20 tokens of prose the false-positive rate works out
around 1 in 4,000. Low, but not the "wide margin" previously claimed.

The curated wallet-domain sentences reach 7 — one word below the trigger.

### Terse text: the failure class no threshold can close

108 of 153 words a wallet questionnaire would plausibly use are in the wordlist — 71%,
because it is a list of ordinary English nouns and verbs and that is the register these
answers are written in. Drop the connective tissue and the margin vanishes:

> `second copy metal plate office safe main copy home safe`

Ten tokens, ten wordlist words. And the case that settles the argument:

> `home safe, office safe, deposit box, metal plate, paper copy, spare device`

**Twelve tokens, twelve wordlist words, longest run 12, density 1.00.** A twelve-word seed
phrase is twelve tokens, twelve wordlist words, longest run 12, density 1.00. They are
identical in every dimension the detector measures, so no threshold separates them, and
raising the run trigger above 12 would blind the detector to every twelve-word mnemonic.

That is a proof, not a judgement, and it is asserted in
`tests/calibration.rs::a_keyword_list_is_numerically_identical_to_a_seed_phrase`.

The distinguishing information is not in the string. It is in which field the string was
typed into — which is why the resolution below is a product decision rather than a number.

### The consequence for the questionnaire

The spec (§3) describes an optional questionnaire: number of devices, vendors used,
passphrase in use, dice entropy used. It does not say those are free-text fields, and on
this evidence they must not be. All four are naturally structured — a number, a
multi-select, two booleans — and a structured control cannot receive a pasted phrase in a
form the detector then has to adjudicate.

**Decided: the questionnaire is structured controls, and the descriptor field is the only
text input in the product.** Recorded with its reasoning in `spec.md` §3.1–3.3, including
the field semantics and the decision not to collect dice entropy at all. The corpus test
asserts the seven categories that can reach the descriptor field; `questionnaire-terse`,
`keyword-list` and `prose-long-run` are measured and reported rather than asserted.

**What remains, and it cannot be solved by structure.** The descriptor field must accept
arbitrary text, so a wrong-clipboard paste of keyword-dense notes still trips the detector,
and roughly 1 in 4,000 prose pastes will too. Raising the threshold is not available — see
above. The residual mitigation is therefore in the wording, not the rule: the interstitial
should lead with *"that is not a descriptor"* and state the compromise advice
conditionally — "if what you pasted was a recovery phrase, treat it as exposed" — which is
accurate whether or not the detection was correct.

This costs nothing in safety. The input is still refused, still cleared, still never
parsed, and `CLAUDE.md`'s three required elements are all still present. It only stops the
product telling people something false with total confidence, which is what makes warnings
get clicked through. **The copy itself is reviewed wording and is not written here.**

### Private-key detection

| Form | Rule |
|---|---|
| Extended private key | One of `xprv`/`yprv`/`zprv`/`tprv`/`uprv`/`vprv`, case-insensitive, anywhere — including nested inside a valid descriptor. One exception below. |
| WIF | 51–52 base58 characters beginning `5`, `9`, `K`, `L` or `c` |
| Raw hex | A maximal run of exactly 64 hex characters |

**The exception, and why it was measured before it was made.** A prefix occurring
*mid-token, inside a token that is itself a well-formed extended public key* is discounted.
An extended key is one indivisible base58 blob, so a private key cannot be nested inside a
public one; such a hit is always coincidence.

Without that rule the coincidence is common. Each prefix is four characters from an
alphabet in which `x y z t u v p r` all exist in both cases, giving 96 matching 4-grams out
of 58⁴, across 108 starting positions in a 111-character key:

| | rate |
|---|---|
| analytic, per extended public key | 1 in 1,091 |
| measured, 1,000,000 synthetic keys | 1 in 1,124 |
| analytic, per three-key multisig descriptor | 1 in 364 |
| **shipped detector, same 1,000,000 keys** | **0** |

An interstitial that tells one in a few hundred honest users their wallet may be
compromised is one they learn to click through. That costs more safety than the blunt rule
buys. Reproduce with `cargo test --test calibration -- --ignored --nocapture`.

### Case-insensitive detection, case-sensitive parsing

These are opposite requirements and they are kept in separate code paths.

Detection ignores case: SLIP-132 really does use capitals — `Yprv` and `Zprv` are the
mainnet *multisig* private prefixes, `Uprv`/`Vprv` their testnet forms — and someone
retyping from a metal plate will mangle case anyway.

Parsing must preserve it. `ypub` and `Ypub` are **different version bytes**: single-sig
nested-segwit versus multisig. Folding them would mean deriving the wrong script type and
reporting on addresses the user does not own.

The separation is structural rather than a convention to remember. `private_key.rs` never
returns a key, only a category, so nothing downstream can consume a case-folded one;
parsing operates on `AcceptedInput`, which holds the original bytes exactly as pasted.

## 4. Known limitations — stated, not hidden

**Zeroization does not extend to the browser.** Rust-side buffers are `Zeroizing`, and the
lowercase buffer is preallocated so it cannot reallocate and strand a copy in freed memory.
None of that reaches JavaScript: JS strings are immutable and garbage-collected, so a
pasted phrase can sit in the JS heap until the collector runs, and nothing in this codebase
can force that. The frontend must pass input into WASM immediately, keep no JS-side copy,
and clear the field — and the UI must say this rather than implying a guarantee.

**`tr()` descriptors carrying a raw x-only public key are refused.** A 32-byte x-only
public key and a 32-byte private key are both 64 hex characters and are not distinguishable
by shape. Rather than guess, v0 refuses and says why. Use an xpub-based descriptor. This is
a real usability cost, accepted deliberately.

**A 64-hex private key inside a longer hex blob is not detected.** Only maximal runs of
exactly 64 are flagged, because 66-character runs are compressed public keys and 40 are
hashes, and flagging those would break legitimate descriptors.

**Terse, keyword-style free text is indistinguishable from a seed phrase.** Measured, not
theorised — see §3. The mitigation is a product decision (structured questionnaire fields),
not a threshold.

**Detection reads the input.** It has to. Nothing else does: no parse, no derivation, no
storage, no display, no network call happens until the scan returns clean. That ordering is
enforced by the type system — `AcceptedInput` is constructible only by `guard_input`.

**None of this proves a key was well generated.** No structural property can. Every result
carries `UNKNOWN_PROVENANCE` regardless of tier.

## 5. Supply chain

Two direct dependencies: `zeroize`, and `rust-miniscript` for all Bitcoin logic.
16 crates in the compiled tree, all from the rust-bitcoin organisation apart from
`arrayvec`. `bdk` is deliberately excluded — it is a wallet framework whose persistence and
chain-sync layers §1 forbids this product from using, so it would be unaudited surface
carried for nothing. Adding anything further requires explicit approval, every time.

```
seedlatch
├── miniscript
│   ├── bech32
│   ├── bitcoin
│   │   ├── base58ck · bitcoin-io · bitcoin-units · bitcoin_hashes
│   │   ├── hex-conservative → arrayvec
│   │   ├── hex_lit
│   │   └── secp256k1 → secp256k1-sys
│   └── hex-conservative
└── zeroize
```

Versions are deliberately absent: `Cargo.lock` is the only place they are stated, and
`cargo tree -e normal` prints this with them filled in. The browser build additionally
carries `wasm-bindgen` and its dependencies — see `docs/toolchain.md` for the split.

`cargo audit`: clean. `serde` appears in `Cargo.lock` as an optional feature of the
rust-bitcoin crates but is **not** in the compiled tree — verify with `cargo tree -e normal`.

### Determinism is not integrity

A published hash invites a reader to rebuild and compare. On the Rust side that check has
teeth: rustc and clang are open source, every crate compiles from source, and a matching
hash means the bytes really did come from the source you just read.

On the JavaScript side it has much less. esbuild and the TypeScript compiler ship as
prebuilt binaries, not as source. **Reproducing the bundle proves that the same binary, run
twice, produces the same bytes — which is exactly what a compromised binary would also do.**
A backdoored bundler is perfectly reproducible. Determinism and integrity are different
properties, and only one of them is being demonstrated.

So the JavaScript side needs a check that does not route through the toolchain, and there
is only one: read the shipped code. That is why the bundle is **not minified**, carries a
sourcemap, and is published alongside its TypeScript sources. It does not remove the need
to trust esbuild — nothing available does — but it moves detection of an injected line from
*reproduce the toolchain* to *read the file*, and the second is something a reviewer can
actually do in an afternoon. The frontend is thin by design and nothing about it is
size-sensitive, so this costs nothing worth having.

The consequence is worth stating in the same breath: **on the Rust side, trust rests on
reproducing the build. On the JavaScript side, it rests on reading the output.** The
JavaScript side is the weaker of the two, and no amount of hash publishing changes that.
Full breakdown in `docs/toolchain.md`.

### The WASM build compiles C, and that has consequences

`secp256k1-sys` 0.10.1 vendors upstream libsecp256k1 (`depend/secp256k1/`) and compiles it
with `cc`. **There is no pure-Rust fallback anywhere in this dependency set**: `secp256k1`
has no Rust backend, and `bitcoin` 0.32 declares it non-optionally, so it cannot be
feature-gated away. Nor can it be avoided by scope — BIP-32 public child derivation is
elliptic-curve point addition, so it is the one operation the tool genuinely needs a curve
implementation for, and invariant 5 forbids writing one.

The crate does support `wasm32-unknown-unknown` directly. Its `build.rs` branches on
`CARGO_CFG_TARGET_ARCH == "wasm32"` and adds `wasm/wasm-sysroot` plus `wasm/wasm.c`. That
"sysroot" is not a libc — it is three stub headers, of which `stdio.h` and `stdlib.h` are
zero bytes and `string.h` declares only `memset`, `memcpy` and `memcmp`, with `printf`
`#define`d away. libsecp256k1 is close enough to freestanding for that to work.

So the requirement is precisely: **a clang that can emit `wasm32`**, plus the stub sysroot
the crate already ships. Not a WASI SDK, not a full sysroot, not Emscripten.

Two consequences worth stating rather than discovering later:

1. **The C toolchain becomes a build input for reproducibility.** "Reproducible builds,
   published hashes" now means pinning a clang version alongside the Rust toolchain, since
   different LLVM versions can emit different WASM for the same C. Whatever pins the Rust
   version must pin clang too.
2. **`cargo audit` does not see vendored C.** The advisory database covers crates. A
   libsecp256k1 CVE would surface as a `secp256k1-sys` version bump, so the crate version
   needs watching directly rather than relying on the audit gate.

Vendored data is pinned by SHA-256 *and* re-derived from properties BIP-39 states
independently, so a substituted list fails even if someone updates the recorded hash.
See `data/PROVENANCE.md`.

## 6. Not yet done

- Independent review of derivation and classification logic. Blocks public launch.
- Legal review of the disclaimer and liability language shown to users.
- Reproducible build pipeline and published hashes.
- The tier wording itself, which is reviewed copy, not developer prose.

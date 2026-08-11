# Seedlatch — Exposure Checker

Client-side tool. User pastes a Bitcoin **descriptor or extended public key**; it reports structural exposure.

Spec: `@docs/spec.md` · Vendor data: `@docs/affected-firmware.md`

**Business notes are deliberately not in this repository, and this repository goes public.** References below cite them by section number as *business notes §x* — an external private document. Never create `docs/master.md`, never quote from the notes into a tracked file, and if a section is needed to make a decision here, ask for the specific fact rather than the document.

**This code is read by people deciding whether to move their life savings. A confident wrong answer is worse than no answer.**

---

## HARD INVARIANTS

Never violate. Never "temporarily" relax. If a request conflicts with one, refuse and name it.

1. **No secret material.** Never accept, parse, store, transmit, log, display, or derive from: BIP-39 mnemonics, WIF keys, hex private keys, or **extended private keys, including inside an otherwise-valid descriptor**. Public keys and public descriptors only.

   Extended private key prefixes in full — BIP-32 `xprv`/`tprv`, and the SLIP-132 variants: `yprv`/`zprv` (mainnet single-sig, nested and native segwit), `Yprv`/`Zprv` (mainnet **multisig** — capitalised, and easy to miss), `uprv`/`vprv` and `Uprv`/`Vprv` (the testnet equivalents of both). Detection is case-insensitive, which covers the whole set including any case a panicking user mangles. Do not narrow this list.
2. **No transmission of user input.** No backend, no telemetry, no analytics, no error reporting containing input. Analysis runs in-browser via WASM. The only permitted outbound call is an Esplora lookup (§Network).
3. **No persistence of user input or results.** No localStorage, sessionStorage, IndexedDB, cookies, or cache. Refresh = clean slate. (Non-input UI config may persist — see §Persistence exception.)
4. **Fail closed.** Ambiguous input, parse failure, unexpected state → refuse and explain. Never guess, never partially process, never "best effort."
5. **No hand-rolled crypto.** Use `rust-miniscript` and `rust-bitcoin` for all Bitcoin logic. If a task appears to need custom crypto, stop and ask.

   **Not `bdk`.** Earlier drafts named it; that was shorthand for "use vetted libraries, don't hand-roll", not a decision to take on a wallet framework. `bdk` carries persistence and chain-sync layers that invariant 3 forbids this product from using, so it would be pure unaudited surface. `rust-miniscript` (which pulls `rust-bitcoin`) covers descriptor parsing, BIP-380 checksums, derivation and address generation — everything v0 needs. Do not re-add `bdk`.
6. **No new dependencies without explicit approval.** Ask every time.

   **This covers transitive additions.** Anything entering the tree from outside the
   rust-bitcoin organisation gets called out by name, even when it arrives as somebody
   else's dependency — the point of this invariant is that additions get noticed rather
   than absorbed.

   The approved non-rust-bitcoin crates are **listed in `docs/toolchain.md`**, split by
   whether they reach the shipped `.wasm`, and are not enumerated here — a list in two
   places drifts, and this one already had, going stale the moment `wasm-bindgen` landed.

   `serde` is present in `Cargo.lock` as an optional feature of the rust-bitcoin crates
   but is **not** compiled. Keep it that way, and say so if it changes. CI fails if it
   enters the compiled tree; verify by hand with `cargo tree -e normal`.
7. **This repository is public. Everything committed is permanent and world-readable within minutes.**

   **Never push, publish, or add a remote without asking first — every time, no exceptions.** Not when it seems obviously wanted, not when a previous push was approved, not when the change is trivial, not when it is the natural next step of a task already agreed. Approval to build is never approval to publish. Ask, and wait for an answer.

   **Nothing enters a tracked file, a commit message, or a build artefact except a description of the tool and its behaviour.** That is the whole of the permitted content. If a sentence explains what the tool does, why it refuses what it refuses, or how a claim about it was measured, it may be committed. If it explains anything else, it may not.

   Excluded always, whatever the justification:

   - **Personal identifiers** — real names, email addresses, usernames, filesystem paths, machine names, timezones, working patterns. Timezone is not rhetorical: a commit records the committer's UTC offset, so **every commit is made with `TZ=UTC` exported**, and the whole history has been normalised to `+0000`. Check with `git log --format='%ai %ci' | awk '$3!="+0000" || $6!="+0000"'` — it must return nothing. A single commit made without it reintroduces the fingerprint the rest of the history no longer carries.
   - **Circumstances** — jurisdiction, legal questions, regulatory exposure, employment, availability, or anything about the maintainer's situation.
   - **Commercials** — pricing, revenue, business terms, market positioning, commercial rationale, conversion or persuasion language.
   - **Secrets** — credentials, tokens, keys, endpoints, or anything from a `.env`.

   The pseudonym is **Anton Corvin**, `315577937+antoncorvin@users.noreply.github.com`, already configured and present throughout the history. **Never** change `user.name` or `user.email`, **never** commit with `--author`. If a git identity is missing, wrong or ambiguous, **stop and ask** — do not derive one from the environment, the account email, a previous commit, or anything else that looks authoritative. Deriving a plausible identity is exactly how the wrong one got into this history once already, and no file edit takes it back out.

   ### Three rules, each one paid for

   Every leak this project has had was outside the tracked files. These are not precautions; they are the shape of what actually happened.

   1. **Grepping the source is not sufficient, and never was.** The compiler wrote an absolute build path containing the maintainer's account name into the shipped `.wasm`, with nothing of the kind anywhere in the source. A CI gate would have printed a caught private key into a public Actions log. A history rewrite left the previous identity intact in `refs/original/`, pushable by `--mirror`. **Before any push, scan the built artefacts, the CI configuration and `.git` internals as well as the tree** — `scripts/build-wasm.sh` and `scripts/check-artifact-paths.mjs` exist for the first of those; use them and do not build around them.
   2. **A gate must never print what it catches.** Any check for secrets or identifiers redacts before output. CI logs on a public repository are public, so a scanner that echoes its match converts a contained mistake into a disclosed one. Report filenames and counts, never content.

      **This rule was already written here, and has since been broken twice by gates added after it.** Stating it is evidently not a mechanism, so it now comes with one. Before any gate is committed or changed, plant a positive and run it. Three things must be *observed*, not assumed:

      - **it fails.** A gate that cannot fail is decoration, and it is indistinguishable from a working one on every green run.
      - **it names only the file.** No matched value, no offending line, no surrounding context.
      - **it fails when there is nothing to check.** Zero inputs means the gate proved nothing and must not report green. A gate keyed to a specific filename quietly stops checking the moment that file is renamed or a second one appears beside it.

      Plant **one positive per variant the invariant names**, not one overall. The committed-private-key gate matched `xprv` and missed `Zprv`, `Yprv`, `Uprv` and `Vprv` from the day it was written, on a repository whose first invariant names those four explicitly; a single lowercase sample would have looked like proof that it worked.

      Two escape routes for the value, both found in gates that were already shipped here:

      - **interpolated into the failure message** — the obvious one, and still the one that happened;
      - **an uncaught exception.** `JSON.parse` prints the offending line when it throws, and a sourcemap is one long line containing every source path — so the error handler for a truncated file would have published precisely what the gate exists to withhold. Wrap the parse and report the filename.

      A gate that looks for paths, keys or identifiers is by definition holding the thing it is looking for. Treat every code path that can print as printing publicly, including the ones that only run when something has already gone wrong.
   3. **If a fact is needed from the business notes, ask for that fact.** Never quote them, never reproduce them, never create `docs/master.md`.

   ### Before any push, and before any change to CI or the build

   Verify the tree, the artefacts and the commit messages — then **report what was checked, rather than asserting it is clean**. "Verified" without a list of what was actually examined is worth nothing, and is how three separate leaks survived earlier passes.

   **Any violation is an incident, not a bug.** Stop and report before doing anything else, including before finishing work already in progress. Do not quietly fix it: what was exposed, for how long, and whether anything was pushed while it was there are the maintainer's questions to answer, not yours to close.

8. **No invented security-relevant data.** Firmware versions, affected date ranges, vendor defaults and derivation conventions come from `docs/affected-firmware.md` only — which is **empty and unused in v0**. Never hardcode from memory or inference. If data seems needed, stop and ask.

Violating 1–3 is a security incident, not a bug. If existing code violates one, stop and report before continuing.

---

## Rejecting secret material (highest-risk path)

Panicking users **will** paste seed phrases. Two detectors, both mandatory:

**A. Mnemonic detection** — a **dense region of BIP-39 wordlist words**: 8 or more consecutive, or 8 or more making up at least three quarters of all tokens. Both checked twice, once on exact matches and once allowing 3–4 letter shorthand.

**Not** "12/15/18/21/24 tokens all in the wordlist", which earlier revisions of this file specified. That rule fails open on a mistyped word, a clipped paste, a phrase quoted inside a sentence, and 4-letter shorthand entry — every one of which is still a live seed. **Never verify the BIP-39 checksum as part of detection**: a phrase with one word wrong fails its checksum and would then be waved through and processed. Thresholds and the measurements behind them: `src/parse/mnemonic.rs`, `docs/security-model.md` §3, `tests/calibration.rs`.
**B. Private-key detection** — an extended private key prefix (see invariant 1 for the full list) anywhere in input, WIF format, or 64-char hex. Applies to bare input *and* to key expressions inside a descriptor. Matching is case-insensitive.

One deliberate narrowing, measured before it was made: a prefix occurring **mid-token inside a token that is itself a well-formed extended public key** is discounted as coincidence. An extended key is a single indivisible base58 blob, so a private key cannot be nested inside a public one. Without this, 96 case variants across 58⁴ four-grams make a plain substring scan fire on **1 in ~1,100** extended public keys and **1 in ~364** three-key multisig descriptors — measured at 1 in 1,124 over a million synthetic keys, against zero for the shipped rule (`tests/calibration.rs`, ignored test). An interstitial that tells one in a few hundred honest users their wallet may be compromised is one they learn to click through, which costs more than the blunt rule buys. Token-initial hits and hits in anything not a well-formed public key still detect.

Required behaviour on either:
- Detect **before** parsing, derivation, storage, display, or any network call. Detection itself necessarily reads the input; nothing else may.
- Clear the input field immediately.
- Blocking interstitial: what was detected (by category, never the value), that it never left their device, and that they should treat the material as compromised if pasted anywhere else.
- Never echo the value, never include it in an error, panic message, or console output.

**There is a third refusal reason, and it is not a detection.** Input over `MAX_INPUT_BYTES` (100 KB) is refused *without being examined* — the bound exists to cap allocation, so it has to run before the scan allocates. That screen therefore states no category and makes no compromise claim, because none was computed. It says so plainly instead. Do not "fix" it to match the three bullets above by asserting something the code did not establish; the copy is in `docs/spec.md` §6.1 and the reasoning is in `guard_input`.

Tests before implementation on both detectors.

**Zeroization — honest limits.** In Rust, zeroize buffers that held input (`zeroize` crate). Browser-side this is **not achievable**: JS strings are immutable and garbage-collected, so a pasted seed may persist until GC. Pass input into WASM as early as possible, keep no JS-side copies, clear the DOM field. Document the limitation in the UI rather than implying a guarantee.

---

## Stack

Rust core → WASM. Thin TypeScript frontend. Static hosting, no server.
Reproducible builds, published hashes, source public from commit one.
**License: MIT.**

## Commands

```
cargo test                                # must pass before every commit
cargo clippy --all-targets -- -D warnings # zero tolerance; --all-targets or tests go unchecked
cargo audit                               # run before every merge to main
cd data && sha256sum -c SHA256SUMS        # vendored data integrity
cd tests/fixtures && sha256sum -c SHA256SUMS

wasm-pack build --release --target web --out-dir web/pkg
cd web && npm ci && npm run typecheck && npm run build
```

`--out-dir web/pkg` is not optional: the frontend resolves the module through the `#core`
subpath import in `web/package.json`, which points there. wasm-pack's default `./pkg` will
build successfully and then fail to bundle.

## Layout

- `src/parse/` — input handling, secret-material rejection
- `src/wasm.rs` — the browser boundary, `cfg(target_arch = "wasm32")` only
- `src/derive/` — path enumeration
- `src/classify/` — structural tiers
- `src/report/` — report output
- `web/` — frontend; `web/pkg/` is wasm-pack output and is gitignored
- `data/` — vendored, hash-pinned reference data
- `docs/` — spec, security model, toolchain, vendor data (**not** business notes — see above)

---

## Coding rules

- **Tests first** in `parse/`, `derive/`, `classify/`. Known-answer vectors from BIP-32/39/380–386. No implementation before its vector test exists.
- No `unwrap()` / `expect()` / `panic!` in library code reachable from user input. Typed `Result` errors. (Tests may unwrap freely.)
- Error messages are user-facing: never include input material, never leak internal state.
- No `unsafe` without written justification and explicit approval.
- Comments explain *why*, not *what*.

## Classification rules

**v0 is structural only.** Tiers derive from descriptor shape and clearly-labelled user self-report. **No vendor-specific claim, ever, in v0** — never state or imply a given device or firmware is affected. The underlying entropy figures are still disputed between Coinkite, Block and independent analysts (business notes §2.1, external).

- Tiers: `SINGLE_POINT_OF_FAILURE` / `PARTIALLY_MITIGATED` / `STRUCTURALLY_MITIGATED`. Never a numeric score.
- `UNKNOWN_PROVENANCE` applies to **every** result regardless of tier: no structure proves a key was well generated. Never emit language implying a key is verified good.
- **When uncertain between two tiers, assign the more severe one.** A false negative stops someone migrating. That is the failure that costs coins.
- User-facing tier wording is reviewed before shipping. Don't rewrite those strings unprompted.

## Report output

**The secret-material interstitial asks the user for nothing.** No call to action, booking link or mailing list appears on the screen that tells someone their secret may be compromised, or anywhere it leads directly; its only interactive element is Start over. That screen tells a frightened person to move their funds now, and a warning is worth acting on quickly only if it comes from a party with nothing to gain by issuing it. See `docs/spec.md` §6.1.

Report JSON is the first draft of a format intended for eventual standardisation. **Do not design the schema unprompted** — propose, wait for approval, then implement. No secret material, no unrequested identifiers.

---

## Network

- Only permitted outbound call: Esplora address/balance lookup.
- **Endpoint:** selectable from a small compile-time allowlist, plus a user-entered custom URL. CSP `connect-src` lists the allowlist; custom endpoints require self-hosting or a local build — state this tradeoff in the UI rather than weakening CSP.
- Disclose the privacy leak (the endpoint operator learns their wallet) in plain language **before** the first lookup.
- **Enumeration limits:** batch requests, cap concurrency, enforce a gap limit of 20 consecutive unused addresses per chain rather than fixed large ranges. Surface progress, allow cancel. Never issue unbounded volume against a public instance.
- No third-party scripts, fonts, CDNs, or trackers. Everything self-hosted. CSP forbids inline script.

## Persistence exception

Non-sensitive UI preferences (selected endpoint, theme, language) may persist in localStorage. **Nothing derived from user input** — no descriptors, xpubs, addresses, balances, results, or history. When in doubt, don't persist it.

---

## Scope gates — stop and ask before

- Reproducing any known-vulnerable derivation. Out of scope permanently in this repo. Attack-equivalent code.
- **Any tripwire work** — path derivation, funding, monitoring, alerting. Blocked pending independent review (business notes §8.5 gate 3, external). Four unresolved design questions, including whether tripwires can be funded without fingerprinting them on-chain.
- Adding a backend, database, session, account, or auth
- Adding a dependency
- Designing the report schema
- Anything touching key generation or signing

---

## Workflow

- Plan mode for anything in `parse/`, `derive/`, or `classify/`. Show the plan, wait for approval.
- Small diffs, one concern each.
- **Attribution in commit messages:** end with `Aided by Claude Opus 5.` — a plain sentence, not a `Co-Authored-By:` trailer. The trailer is a machine-readable authorship claim that forges a second author onto the commit; the tool assisted, it did not co-author. Do not add `Co-Authored-By` for any model, and do not name a model as an author anywhere else.
- **Publishing is always a separate decision.** Committing is not publishing. Ask before every push, every remote, every release — see invariant 7. A task that ends "and push it" still gets the question.
- **Review reality:** "reviewed" means the maintainer read the full diff, not that CI passed. Explain risk in plain language in every PR description.
- Before public launch, derivation and classification logic requires review by an independent party who did not write it.

---

## Status

v0 = structural assessment only. Pre-audit, pre-release. Nothing ships publicly until independent review is complete.

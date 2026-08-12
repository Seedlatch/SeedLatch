# Seedlatch Exposure Checker — v0 Spec (structural analysis only)

**Scope note:** v0 makes **no vendor-specific claim**. It does not say "your firmware is affected." It analyses wallet *structure* and reports how many independent things must be correct for the wallet to be safe. See business notes §2.1 (an external private document) — the entropy figures are still disputed between Coinkite, Block and independent analysts, which is itself a reason not to build verdicts on them yet.

**Goal:** free, public, client-side. Paste a descriptor or extended public key, learn your structural exposure, get a report.

---

## 1. The constraint that shapes everything

A tool that can *confirm* a key is weakly generated is mechanically identical to the attack, and a service holding that knowledge is the most valuable target in the space.

v0 sidesteps this by not doing it. The architecture is fixed now so it stays safe later:

> **Runs entirely client-side. Nothing transmitted. No server, no logs, no analytics on input.**

Rust → WASM, static page, reproducible build. The claim this buys: *nothing leaves your browser, here is the hash to verify it.*

---

## 2. What a descriptor can and cannot tell you

**Determinable:** script type (`pkh`, `wpkh`, `sh(wpkh)`, `tr`, `wsh(multi)`, `wsh(sortedmulti)`); single-sig vs multisig and the m-of-n threshold; derivation paths and fingerprints; number of distinct signers; whether paths match common vendor defaults.

**Not determinable:** which device or firmware generated it; whether dice entropy or a passphrase was used; **whether the seed is actually weak.**

Entropy quality is invisible in a public key. This is why the defect survived five years, and it is the argument the tool exists to make.

---

## 3. Input handling

Accept: descriptors with checksum, bare extended public keys, Sparrow/Nunchuk/Electrum export JSON (extract the descriptor).

**Every SLIP-132 public form, not just the BIP-32 ones.** `xpub`/`tpub`, `ypub`/`zpub`, and the capitalised multisig variants `Ypub`/`Zpub` with their testnet forms `Upub`/`Vpub`. `rust-bitcoin` understands only `xpub`/`tpub` natively, so the others need version-byte translation — that is week 2 work and it is **not optional**: the interstitial (§6.1) tells users their `Zpub` is accepted, and multisig holders are both the audience most likely to have survived the defect and the audience worth talking to. Shipping copy that promises it while the parser rejects it would be worse than never mentioning it.

Case is significant on this path. `ypub` and `Ypub` are different version bytes — single-sig nested segwit versus multisig — and folding them means deriving the wrong script type and reporting on addresses the user does not own. Detection folds case; parsing must not. See `AcceptedInput` in `src/parse/mod.rs`.

Reject hard, before any other processing — full required behaviour in `CLAUDE.md`:
- BIP-39 mnemonics
- Extended private keys, including inside an otherwise-valid descriptor: BIP-32 `xprv`/`tprv` and the SLIP-132 variants `yprv`/`zprv`, the capitalised multisig forms `Yprv`/`Zprv`, and the testnet equivalents `uprv`/`vprv`/`Uprv`/`Vprv`. Detection is case-insensitive and covers all of them.
- WIF and 64-char hex private keys

Validate descriptor checksums. Reject malformed input rather than guessing.

### 3.1 The questionnaire is structured controls. There is no free-text field in v0.

**Decided. Do not reintroduce free text as a usability improvement.**

The descriptor field is the only text input in the product. The questionnaire is
structured controls — an integer, a multi-select, an enum — clearly labelled as unverified
self-report, feeding the structural narrative and never a verdict.

**Why this is forced, not a preference.** 108 of 153 words a wallet questionnaire would
plausibly use are in the BIP-39 English wordlist (71%). It is a list of ordinary English
nouns and verbs, which is exactly the register these answers get written in. Measured:

> `second copy metal plate office safe main copy home safe`

Ten tokens, all ten in the wordlist. And the case that settles it:

> `home safe, office safe, deposit box, metal plate, paper copy, spare device`

Twelve tokens, twelve wordlist words, longest run 12, density 1.00 — **the exact signature
of a twelve-word seed phrase, in every dimension the detector measures.** They are the same
object as text. No threshold separates them, and raising the run trigger above 12 would
blind the detector to every twelve-word mnemonic. This is asserted in
`tests/calibration.rs::a_keyword_list_is_numerically_identical_to_a_seed_phrase` so it
cannot be quietly re-litigated.

Structured controls delete the failure class. A threshold would only move it somewhere it
has to be re-validated every time the corpus grows.

### 3.2 Fields and semantics

Implementation deferred until the frontend toolchain is settled; the semantics are fixed now.

| Field | Control | Semantics |
|---|---|---|
| Device count | Bounded integer, 1–20 | **Reject out-of-range, do not clamp.** Clamping silently changes the user's answer, and the answer feeds a report they may act on. |
| Vendors used | Fixed multi-select | **No "other" with a text box.** That reintroduces exactly the field eliminated in §3.1. If "other" exists it is a checkbox with no accompanying input. |
| Passphrase in use | yes / no / unsure | **`unsure` takes the same branch as `no`.** Per §5's more-severe-tier rule: an unverified passphrase cannot be counted as mitigation. The UI must state this — "we treat 'unsure' the same as 'no'" — rather than leaving the user to guess what their answer did. |
| Dice entropy | **Not collected in v0** | See §3.3. |

An option whose semantics are not written down gets implemented three different ways.

### 3.3 Dice entropy is not collected in v0

The tiers in §5 are structural: signer count, vendor diversity, passphrase. Dice entropy
appears in none of them, so as specified it has no consumer.

It should not acquire one. "I used dice" is a claim about **how well a seed was generated**
— which is precisely the judgement this product says it cannot make and must never imply.
§2 exists to make the point that entropy quality is invisible in a public key;
`UNKNOWN_PROVENANCE` attaches to every result regardless of tier for the same reason.
Collecting an unverifiable self-reported provenance claim creates exactly the affordance
that invites a future session to wire it into classification, at which point the tool is
issuing provenance verdicts on the strength of a checkbox.

There is a second, quieter harm: asking a question implies the answer changes the result.
If it does not, asking it is misleading UI.

If a future version wants it, the bar is that §5 says explicitly what it changes in the
narrative text and what it must never change in the tier — written before the control is
built, not after.

---

## 4. Path enumeration

Derive and check across purposes `44h`, `49h`, `84h`, `86h`, and `48h/…/2h` for multisig.

**Gap limit 20** consecutive unused addresses per chain rather than fixed large ranges. Batch, cap concurrency, show progress, allow cancel. Never unbounded volume against a public Esplora instance.

Account indices 0–4 by default; deeper on explicit request.

This engine is reused later by monitoring. Build it clean.

---

## 5. Structural classification

Tiers are **structural only** — descriptor shape and self-report, never vendor data.

**SINGLE POINT OF FAILURE** — single-sig, one signer, no passphrase reported. Every satoshi depends on one device having generated one number correctly, with no way to verify it did.

**PARTIALLY MITIGATED** — single-sig with a reported passphrase, or multisig where signers share a vendor. More than one independent failure required, but correlated.

**STRUCTURALLY MITIGATED** — multisig across distinct vendors, threshold such that no single device compromise suffices. Explain *why*: this is the tier where the reasoning behind the whole assessment becomes visible to the user.

**UNKNOWN PROVENANCE** — applies to all of the above, always. No structure proves a key was well generated. Every wallet on earth is in this state today, and saying so plainly is the point.

No numeric scores. When uncertain between tiers, assign the more severe one.

---

## 6. Output

- Tier plus one plain-language paragraph
- Which signers and paths are affected
- Ordered next actions
- Downloadable JSON report — **schema requires approval before implementation**

### 6.0 Standing rule for all user-facing copy: judgements hedge, arithmetic doesn't

Every sentence the product shows a user is one of two kinds, and they are written
differently. This applies to everything — interstitials, tier wording, error messages,
report text, the results page — not only the screens that exist today.

**A judgement hedges.** Anything derived from a heuristic, a threshold, or an inference
about something unobservable says *looks like*, *may*, *we can't be certain*. Mnemonic
detection is a judgement: it is wrong about one time in four thousand on prose, and a
keyword list is indistinguishable from a seed phrase. Every tier is a judgement: it rests
on descriptor shape and unverified self-report. `UNKNOWN_PROVENANCE` exists because the
most important thing about a wallet is one the tool cannot observe at all.

**Arithmetic does not hedge.** Anything the code actually computed states it plainly. The
input was 4.2 MB and the limit is 100 KB. The descriptor has three signers. Nothing was
transmitted. Hedging these is not modesty, it is noise — and it teaches a reader that the
hedges elsewhere are decoration rather than meaning.

**The failure mode this prevents.** Hedge everything and the hedges stop being read, so the
one that matters gets skipped. Hedge nothing and the product asserts things it cannot know,
which is the sentence a hostile reader quotes. Both are how a tool loses the standing to be
believed by someone deciding whether to move their savings, and that standing is the whole
product.

**Applying it is not optional and not a style preference.** Before shipping any user-facing
string, name which kind it is. If it is a judgement, point at the code that computes it and
check the copy does not claim more than that code establishes. Two findings against earlier
drafts came from exactly this check: a headline asserting *"that doesn't look like a
descriptor"* about inputs that were valid descriptors, and a `Display` implementation
asserting the input field had been cleared, which the library has no way to know.

### 6.1 Secret-material interstitial

**Status: approved, and shipped. Do not edit this text unprompted.**

Rendered by `web/src/interstitial.ts`, which reproduces it verbatim. If that file and this
section ever disagree, this section is right and the file is a bug.

Blocking modal. No dismiss-and-continue: the only action is to clear and start again.

#### Why it is worded conditionally

The detector cannot be made precise enough to assert what was pasted. A comma-separated
keyword list is numerically identical to a twelve-word seed phrase (`docs/security-model.md`
§3), and ordinary English prose crosses the run threshold about once per 4,000 realistic
pastes. Both stay detected — that is the correct, fail-closed behaviour — but the product
must not *assert* to a user that they pasted a secret when it cannot know.

So the copy leads with what is certainly true (this is not a descriptor) and states the
compromise advice conditionally (if it was a secret, here is what to do). That is accurate
in both cases, and it is what stops the warning becoming one people click through — which
is the failure that would degrade every real alert afterwards.

All three elements `CLAUDE.md` requires are present: what was detected by category, that it
never left the device, and what to do if it was pasted elsewhere.

#### Two things an earlier draft got wrong, kept here so they don't come back

**It opened with "That doesn't look like a descriptor", which is false for real inputs.**
`wpkh([origin]xprv…/0/*)` is a well-formed descriptor, refused because it carries a private
key. So is `tr(<64 hex characters>)`, refused because 32 bytes of hex is ambiguous. Both
users pasted a genuine descriptor and were told they hadn't — and the first of those is the
highest-severity detection in the product, opening on a false statement. The headline now
describes only our own action, `We didn't accept that`, which is true in every case and
claims nothing about the input.

The same draft said the input was "not checked against anything". It was: against the
BIP-39 wordlist. That is the one thing we did do, and the copy now says so precisely.

**The false-positive branch came fourth**, after a bolded *treat it as exposed* and *move
the funds*. Someone who pasted a sentence had already been through the alarm before
reaching the line telling them it might not apply. Reordering to put reassurance first was
not an option — true positives dominate, and that is the case where minutes matter. The fix
is the fork header, `Only you can tell which of these just happened`, which presents both
branches as live before either one is argued, so the reassuring branch is reachable in one
read without softening the urgent one.

**"The box is now empty" sat four paragraphs above its own limitation**, which was in
italics, unbolded, and last — the single most skippable element on the screen. A skimmer
reads bold text and first lines: *Nothing left your device*, *The box is now empty*, and
concludes nothing remains anywhere. The limitation is exactly what `CLAUDE.md` requires be
stated rather than implied away, and burying it under the reassurance is implying it away.

The three claims are genuinely distinct — *nothing was transmitted*, *the input field is
empty*, *browser memory is beyond reach* — and only the second invites the wrong
generalisation, because "empty" sounds total. So the limitation now sits on the same claim
it qualifies, bold-led rather than italic-buried, and the separate footnote is gone. It also
does useful work there: the browser's copy is part of *why* the next paragraph says treat it
as exposed, and it gives `Start over` a second, real purpose.

**The prefix enumeration `xpub, ypub, zpub, tpub` omitted the SLIP-132 multisig forms.**
A `Zpub` holder reads a list that contains `zpub` but not `Zpub` — forms that SLIP-132
defines as genuinely different things — and reasonably concludes their key is not accepted.
That is the multisig audience, which is the audience most likely to have survived the defect.

Enumerating all eight would have traded one problem for noise, so the copy now states the
rule instead: any of the `pub` forms, with `Ypub`/`Zpub` named explicitly so a multisig
holder sees themselves, and `prv` named as the thing that is never accepted. Complete by
construction, shorter than the list, and it teaches the distinction that actually matters.

#### Copy

> ### We didn't accept that
>
> What you pasted looks like **{category}**. This check reads shape, not meaning, so it
> can't be certain — it refuses anything that might be secret rather than guessing.
> {category note}
>
> **Nothing left your device.** It was checked for secret material and nothing else: not
> parsed as a wallet, no addresses worked out, no balances looked up. Nothing sent, nothing
> saved, nothing written to a log.
>
> **We've cleared the box — that's the limit of what we can reach.** Your browser may still
> be holding a copy of anything you pasted, until it decides to let go, and no web page can
> force that. Start over reloads this page, which gives it the best chance to.
>
> **Only you can tell which of these just happened.**
>
> **If it was a secret** — a recovery phrase, a private key, anything that can spend —
> treat it as exposed, and move your coins to a wallet created fresh on a device you trust.
> Do that before anything else. Not because of this page, but because something that has
> been on a clipboard is one keystroke away from a note, a chat, a screenshot or a support
> ticket.
>
> **If it wasn't** — a sentence, a note, a list of words — then nothing has gone wrong
> here. This check is deliberately strict and it stops harmless things too. Choose Start
> over and paste a descriptor or an extended public key instead.
>
> This tool only ever needs public information: a descriptor, or an extended public key —
> any of the `pub` forms, including the capitalised `Ypub` and `Zpub` that multisig wallets
> use. Anything with `prv` in it is the private version and this tool will never accept
> one. A public key shows your balance and every address you own, which is why we don't
> send it anywhere either — but it cannot spend anything.
>
> `[ Start over ]`

#### Second variant: refused on size

Shown when the input exceeds 100 KB. Same modal, same recovery, same no-offer rule.

**This one does not hedge, and the difference is deliberate.** Detection is a judgement
that can be wrong about one time in four thousand, so that copy says *looks like*. Size is
arithmetic. We know exactly what happened and there is nothing to soften.

> ### That's too big to check
>
> The box takes up to 100 KB. What you pasted was **{size}**, so we stopped without looking
> at it — not a sample, not the first part, none of it.
>
> **Nothing left your device**, because nothing was read in the first place. The box is now
> empty. Your browser may still be holding a copy of anything you pasted, and no web page
> can reach that; Start over reloads this page, which gives it the best chance to let go.
>
> A descriptor or an extended public key is small — a few hundred characters, or a few
> thousand for a large multisig. Something this size is usually a whole file. If you have a
> wallet backup or an export, open it and copy out just the descriptor line.
>
> **One thing we can't tell you:** we don't know what was in it, because we didn't look. If
> that file held a recovery phrase or a private key, we have no way of knowing and no way of
> warning you. Check for yourself before you paste it anywhere else.
>
> `[ Start over ]`

`{size}` is rendered from `CheckResult.size` in human units — `4.2 MB`, not `4404019`. It
is not secret: the user knows what they pasted, and it never leaves the device.

The fourth paragraph exists because the size check runs **before** the scan, by necessity —
bounding allocation is the whole point of it. Someone who pastes a 200 KB backup containing
their seed gets no secret-material warning, because none was computed. Saying so plainly is
the only honest option; the alternative is a silence they would reasonably read as "it was
fine". See `guard_input` in `src/parse/mod.rs`.

#### Third variant: could not be read

Shown when the input passed the guard and then parsed as neither a descriptor nor an
extended public key. Same modal, same recovery, same no-offer rule.

**This one does not hedge either, for the same reason as the size variant.** A parser ran
and it failed. That is arithmetic, not judgement, so the copy says *isn't* rather than
*doesn't look like*.

**Nothing here suggests a secret was involved** — no alarm language, no compromise, no
*treat it as exposed*. Nothing alarming was found; the input was simply not something this
tool reads. Telling someone who mistyped an extended key that their wallet may be
compromised would be false, and it would spend the alarm the first variant depends on.

It is deliberately the shortest of the three. The other two are long because they carry
urgency, or a refusal that needs explaining. Matching their length here would flatten the
difference and teach a reader to skim all three.

> ### We couldn't read that
>
> What you pasted isn't a descriptor, and isn't an extended public key. That is the only
> thing we checked it for: it wasn't parsed as a wallet, no addresses were worked out, no
> balances looked up. Nothing sent, nothing saved, nothing written to a log.
>
> **Nothing left your device.** We've cleared the box. Your browser may still be holding a
> copy until it decides to let go, and no web page can force that — Start over reloads this
> page, which gives it the best chance to.
>
> **What this tool reads.** A descriptor — `wpkh(…)`, `sh(wpkh(…))`, `wsh(sortedmulti(…))`
> and the like. Or an extended public key: any of the `pub` forms, including the capitalised
> `Ypub` and `Zpub` that multisig wallets use.
>
> `[ Start over ]`

The browser-memory limitation appears here too, and that is not padding. The moment the
copy says *we've cleared the box* it invites the same generalisation the first variant was
rewritten to avoid: a reader takes "cleared" to mean nothing remains anywhere. `CLAUDE.md`
requires that limitation be stated rather than implied away, and the requirement does not
weaken because this screen is calmer.

An earlier draft named where descriptors are usually found in wallet software. It was cut:
menu labels differ between wallets and change between releases, so it is a specific claim
about third-party software that would be wrong the moment one of them renames something.

#### `{reason note}` — one refusal needs a way forward the generic copy can't give

Empty for every reason except one. Omit the line entirely when empty. Same mechanism as
`{category note}`, and it exists for the same reason: a refusal that leaves a user holding a
real wallet with nowhere to go is a dead end, not an answer.

| reason | note |
|---|---|
| `slip132_key_in_descriptor` | *Descriptors have to use the `xpub` or `tpub` form of a key. If it's a single-key wallet, paste the `zpub` on its own instead — this tool reads that.* |

**The conditional is load-bearing.** For a single-key `wpkh(zpub…)` the bare `zpub` is
exactly equivalent — same key material, same script type, and this tool accepts it. For a
multisig descriptor it is not, and telling someone to paste one `Zpub` out of three would be
wrong. So the note offers the alternative where it holds and does not claim it elsewhere.

#### Why a SLIP-132 key inside a descriptor is refused rather than rewritten

**Decided deliberately. Do not reopen this as an obvious usability win.**

The tool already holds an unambiguous mapping from SLIP-132 version bytes to BIP-32 ones
(`src/parse/extended_key.rs`), so it could rewrite `wpkh(zpub…)` into the descriptor BIP-380
allows and parse that. It does not, and the mapping being unambiguous is what makes this a
judgement call rather than a limitation — which is why it is written down here.

BIP-380 defines what a descriptor is, and tools vary in how strictly they enforce it. A
permissive parser means our reading of an input can disagree with a strict tool's, and the
user has no way to tell which is right. That is a bad position to put someone in when the
subject is where their coins are.

It would also break the report. The report would have to describe a descriptor that does not
exist as written — either explaining the rewrite, which is noise about our own internals at
the moment the user is trying to understand their wallet, or asserting something untrue about
what they gave us. This tool's whole argument is that it does not assert what it cannot
support, and quietly reinterpreting the input contradicts that more than a refusal does.

The `{reason note}` above solves the real dead end — the single-key case, which is the common
one — without diverging from the standard.

#### `{category}` substitutions

Rendered from `SecretMaterial::label()` in `src/parse/mod.rs`. Multiple categories join
with commas and a final "and".

| variant | text |
|---|---|
| `Bip39Mnemonic` | a recovery phrase (seed words) |
| `ExtendedPrivateKey` | an extended private key |
| `WifPrivateKey` | a private key in WIF form |
| `RawHexPrivateKey` | a raw private key in hexadecimal |

#### `{category note}` — one case needs a way forward the generic copy can't give

Empty for every variant except one. Omit the line entirely when empty.

| variant | note |
|---|---|
| `RawHexPrivateKey` | *32 bytes of hexadecimal is a private key or a public one, and nothing in the value itself distinguishes them. If yours was a public key inside a `tr()` descriptor, use the `xpub` form of the same descriptor — this tool reads that.* |

Without this, a `tr()` descriptor carrying a raw x-only public key is a dead end: the user
pasted a perfectly good public descriptor, is told it looks like a private key, correctly
concludes it wasn't, follows "start over and paste a descriptor" — and hits the same wall.
The refusal is deliberate (§3, and `docs/security-model.md` §4), so the copy has to carry
the way out.

#### Recovery — non-dismissible must not mean stuck

About one in four thousand of these is a prose false positive, and rather more than that
for keyword-style pastes. That user has done nothing wrong and needs a way forward that is
not "work out for yourself that reloading fixes it".

**`[ Start over ]` performs a full page reload.** Not a state reset in JavaScript — an
actual reload, which is a genuine clean slate here because nothing persists: no
localStorage, no sessionStorage, no cookies, no cache. It also gives the browser its best
opportunity to release the pasted string, which a soft reset does not.

- The button receives focus when the modal opens, and focus is trapped inside the modal.
  A keyboard user is therefore one Enter away from recovery, which is what makes disabling
  Escape acceptable rather than hostile.
- It is the **only** interactive element on the screen.
- If scripting has failed and the modal is somehow shown without a working handler, a
  browser reload reaches the same state. Nothing about recovery depends on our code being
  correct.

#### Constraints on the implementation

- The pasted value is **never** rendered, echoed, or included in any DOM node, error, or
  console output — only the category.
- The input is cleared before the modal paints, not after it is dismissed.
- No "continue anyway" affordance exists.
- The modal is not dismissible by clicking outside it or pressing Escape. Someone who has
  just pasted a seed phrase should not be able to dismiss this by reflex.

#### This screen asks the user for nothing

**No call to action, no booking link, no mailing list, no "we can help with this" — on the
interstitial or anywhere it leads directly. The only interactive element is Start over.**

This screen tells someone their secret may be compromised and that they should move their
funds now. A warning is worth acting on quickly only if it comes from a party with nothing
to gain by issuing it; anything asking something of the reader, at the moment they are
being told to hurry, undermines the urgency the screen exists to create. Do not add one
here later as an obvious improvement.

---

## 7. Stack

Rust (`rust-miniscript`, which pulls `rust-bitcoin`) → WASM. Thin TypeScript frontend. Static hosting. Reproducible build, published hashes, MIT, public from commit one.

**Explicitly not `bdk`.** Earlier drafts of this section named it. That was shorthand for "use vetted Bitcoin libraries, don't hand-roll crypto" — it was never meant to pull in a wallet framework whose persistence and chain-sync layers §1 and invariant 3 forbid. `rust-miniscript` covers descriptor parsing, BIP-380 checksum validation, path derivation and address generation, which is the whole of what v0 needs. Do not re-add `bdk` on the strength of an older revision of this document.

---

## 8. Open questions before launch

1. **Esplora default** — public instance (better UX) vs own node (better privacy). Probably: public default, prominent pre-lookup warning, one-click switch.
2. **Independent review** of derivation logic before public launch.

---

## 9. Four weeks

- **Week 1:** secret-material rejection detectors. Tests first. Nothing else.
- **Week 2:** descriptor parsing, validation, structural analysis.
- **Week 3:** path enumeration, Esplora integration, gap limits.
- **Week 4:** classification, report, WASM build, reproducible pipeline, publish.

---

## Deferred — do not build in this repo

- Vendor-specific firmware classification
- Any reproduction of known-vulnerable derivation — attack-equivalent, permanently out of scope here
- **All tripwire work** — blocked pending independent review. Four unresolved design questions (business notes §8.5 gate 3): funding fingerprint, multisig per-cosigner model, fee reserve custody, ladder viability.

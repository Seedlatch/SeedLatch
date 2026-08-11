# Vendored data provenance

Everything in this directory is copied verbatim from an upstream source and pinned by
hash. Nothing here was written, recalled, or reconstructed by hand. Re-verify with:

```
sha256sum -c data/SHA256SUMS
```

## `bip39-english.txt`

- **Upstream:** `https://raw.githubusercontent.com/bitcoin/bips/master/bip-0039/english.txt`
- **Retrieved:** 2026-08-10
- **SHA-256:** in `data/SHA256SUMS`, not restated here — a hash written in two places is a
  hash that will eventually disagree with itself. That file is the one CI checks.
- **Lines:** 2048 · **Line endings:** LF · trailing newline present

Used only as a membership set for detecting pasted secret material. It is never used to
derive a seed, validate a BIP-39 checksum, or reconstruct entropy.

### Why the hash alone is not the whole check

A hash only proves the file matches *some* value written down next to it. So
`tests/wordlist_integrity.rs` additionally asserts the four properties BIP-39 states the
English wordlist must have, each of which is independently verifiable from the spec text:

1. exactly 2048 words
2. sorted lexicographically (BIP-39 requires this so wallets can binary-search)
3. every word unique
4. every word uniquely identified by its first four letters

Plus two observable constraints: all words are `[a-z]+`, and lengths run 3–8.
A corrupted, truncated, or substituted list fails at least one of these even if someone
updated the recorded hash to match.

## `slip132-versions.txt`

- **Standard:** SLIP-0132, *Registered HD version bytes for BIP-0032*.
- **Upstream:** `https://raw.githubusercontent.com/satoshilabs/slips/master/slip-0132.md`
- **Retrieved:** 2026-08-11
- **Source document SHA-256:** `e22db297863b7e200637bd4b507cb31a5bea31a91c0398e27a6657403d8ce167`
- **SHA-256 of this extract:** in `data/SHA256SUMS`, which is the file CI checks.
- 10 rows: 5 Bitcoin, 5 Bitcoin Testnet. 10 distinct public version bytes, 10 distinct
  private, no value appearing in both columns.

Rows whose first column is exactly `Bitcoin` or `Bitcoin Testnet`, copied verbatim with the
table header. Exact match, not a prefix match, so a future `Bitcoin Cash`-style row cannot
be absorbed silently.

The source document hash is recorded here because — unusually for this directory — the
source is **not** vendored, so `SHA256SUMS` cannot pin it. It states which revision of a
living registry these rows were read from. Other coins are appended to that registry over
time; the Bitcoin rows are stable, so re-verification means fetching the document and
confirming these ten rows still appear in it unchanged.

### Why the document itself is not committed

It contains serialised `xprv`, `yprv` and `zprv` test vectors and a real BIP-39 mnemonic, in
its *Bitcoin Test Vectors* section. Invariant 1 says never store an extended private key and
carves out no exception for published ones, and the CI gate that enforces it would refuse
the build — correctly. Only the registry rows are extracted, and they carry version
**bytes**: four-byte constants, never a key. The extraction asserts its own output contains
nothing matching a serialised extended private key before writing anything to disk.

### These version bytes do not identify the coin

Fifteen non-Bitcoin rows in the same registry share Bitcoin's public version bytes.
Groestlcoin duplicates **all ten** exactly; Vertcoin, Syscoin, Nexa Testnet and Kylacoin
Testnet each collide with at least one.

One collision disagrees about more than the coin. `0x045f1cf6` is Bitcoin Testnet `vpub`,
whose address encoding is **P2WPKH** — and Kylacoin Testnet `vpub`, whose encoding is
**P2PKH or P2SH**. The same four bytes, a different script type.

So this table is read as *"interpreted as Bitcoin, these bytes mean this"*, which is what the
tool is for, rather than as an identification of the chain. A Groestlcoin `xpub` is
byte-identical to a Bitcoin one and cannot be distinguished from it here or anywhere else.
A prefix outside this table — Litecoin's `Ltub`, Lyncoin's `Lpub`, Polis's `ppub` — is not
recognised and is refused rather than guessed at.

## `../tests/fixtures/bip39-english-mnemonics.txt`

- **Upstream:** `https://raw.githubusercontent.com/trezor/python-mnemonic/master/vectors.json`,
  `english` group, field index 1 of each entry (the mnemonic string).
- **Retrieved:** 2026-08-10
- **SHA-256:** in `tests/fixtures/SHA256SUMS`, machine-checked by CI alongside the corpus
  and the BIP-32 xpub fixture.
- 24 mnemonics: 8 × 12-word, 8 × 18-word, 8 × 24-word.

These are the reference vectors BIP-39 itself points to. Only the mnemonic strings were
extracted — the entropy and seed columns are deliberately left upstream, since this
repository has no use for them and no business storing 64-character hex blobs that its
own detector is built to reject.

15- and 21-word mnemonics do not appear in the upstream vectors. Tests needing those
construct them from wordlist entries and are labelled as constructed, not known-answer.

## `../tests/fixtures/bip32-xpubs.txt`

- **Standard:** BIP-32, *Hierarchical Deterministic Wallets* — the "Test Vectors" sections.
- **Upstream:** `https://raw.githubusercontent.com/bitcoin/bips/master/bip-0032.mediawiki`
- **Retrieved:** 2026-08-10
- **SHA-256:** in `tests/fixtures/SHA256SUMS`, machine-checked by CI.
- 23 unique extended public keys, every one 111 characters, every one beginning `xpub`.

Extracted from the document by matching `\bxpub[1-9A-HJ-NP-Za-km-z]{100,115}\b` and
deduplicating, in source order. These are the reference vectors BIP-32 defines for
derivation, so they are the right negatives for a detector that must accept public keys and
refuse private ones.

### The extraction deliberately dropped half the vectors

BIP-32's test vectors publish an extended **private** key beside every public one. None of
them are in this file, and none of them passed through a variable, a log line or a
temporary file on the way here: the extraction matched `xpub` only, and asserted the output
contained no `prv` before writing anything to disk.

They are published test keys and any wallet derived from them was emptied years ago — but
invariant 1 says never store an extended private key, and it does not carve out an
exception for harmless ones. A repository whose stated purpose is refusing key material
should not contain key material it happens to think is safe. The file is checked at 0
occurrences of `prv`, and CI fails the build if a serialised extended private key appears
anywhere in the tree.

## What is deliberately *not* hash-pinned

`tests/fixtures/negative-corpus.txt` is ours, not vendored, and it is meant to grow — a
reviewer attacking the thresholds adds samples to it. Pinning a file that is supposed to
change would make every legitimate addition a two-step, and would train exactly the reflex
that makes hash pinning worthless elsewhere: updating the recorded hash without thinking
about why it changed. Its integrity is guarded by the assertions in `tests/calibration.rs`,
which is the right mechanism for a file whose *content* matters rather than its provenance.

## This repository contains real BIP-39 mnemonics, on purpose

`bip39-english-mnemonics.txt` holds 24 genuine, published test-phrase vectors. They are not
secrets — they are the reference vectors BIP-39 itself points at, and any wallet derived
from them was drained years ago — but a scanner run over this repository will find them and
it will look alarming. It is intentional and it is the only place it happens. Nothing here
is or ever should be a live secret.

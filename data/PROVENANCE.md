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

//! The BIP-39 English wordlist, vendored and pinned.
//!
//! Used **only** as a membership set for detecting pasted secret material. It is never
//! used to derive a seed, validate a BIP-39 checksum, or reconstruct entropy — see
//! `mnemonic.rs` for why checksum validation would be actively harmful here.
//!
//! Provenance and integrity: `data/PROVENANCE.md`, enforced by `tests/wordlist_integrity.rs`.

use std::sync::OnceLock;

/// Vendored verbatim. The hash lives in `data/SHA256SUMS`, which CI machine-checks, and is
/// deliberately not restated here — a hash written in two places is a hash that will
/// eventually disagree with itself.
const RAW: &str = include_str!("../../data/bip39-english.txt");

/// The 2048 words, in the file's (lexicographic) order.
pub fn words() -> &'static [&'static str] {
    static WORDS: OnceLock<Vec<&'static str>> = OnceLock::new();
    WORDS.get_or_init(|| RAW.lines().filter(|line| !line.is_empty()).collect())
}

/// First four bytes of each word — or the whole word when shorter than four.
///
/// BIP-39 guarantees these are unique, which is what makes 4-letter shorthand entry
/// unambiguous. Because the wordlist is sorted and the prefixes are unique, this table is
/// sorted too, so it can be binary-searched directly (asserted in the integrity tests).
pub fn prefixes() -> &'static [&'static str] {
    static PREFIXES: OnceLock<Vec<&'static str>> = OnceLock::new();
    PREFIXES.get_or_init(|| {
        words()
            .iter()
            .map(|word| word.get(..4).unwrap_or(word))
            .collect()
    })
}

/// Exact membership. Input must already be lowercased.
pub fn is_word(candidate: &str) -> bool {
    words().binary_search(&candidate).is_ok()
}

/// Whether `candidate` is the 3- or 4-letter shorthand for some wordlist entry.
pub fn is_prefix_of_word(candidate: &str) -> bool {
    prefixes().binary_search(&candidate).is_ok()
}

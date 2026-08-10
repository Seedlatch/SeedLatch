//! The vendored BIP-39 English wordlist is the entire basis of mnemonic detection.
//! If it is silently truncated, reordered, or substituted, the detector fails open and a
//! seed phrase gets processed. These assertions are the properties BIP-39 states the
//! English wordlist has, so they hold independently of anything recorded in this repo.
//!
//! Provenance and the pinned SHA-256 live in `data/PROVENANCE.md`.

use seedlatch::parse::wordlist;

#[test]
fn contains_exactly_2048_words() {
    assert_eq!(wordlist::words().len(), 2048);
}

#[test]
fn is_sorted_ascending() {
    // BIP-39 requires lexicographic order so wallets can binary-search.
    // Our lookup binary-searches too, so an unsorted list would silently miss words.
    let words = wordlist::words();
    for pair in words.windows(2) {
        assert!(
            pair[0] < pair[1],
            "not sorted at {:?} -> {:?}",
            pair[0],
            pair[1]
        );
    }
}

#[test]
fn all_words_unique() {
    let mut seen = std::collections::HashSet::new();
    for w in wordlist::words() {
        assert!(seen.insert(*w), "duplicate word {w:?}");
    }
}

#[test]
fn all_words_are_lowercase_ascii_letters() {
    for w in wordlist::words() {
        assert!(
            w.chars().all(|c| c.is_ascii_lowercase()),
            "unexpected character in {w:?}"
        );
    }
}

#[test]
fn word_lengths_are_three_to_eight() {
    for w in wordlist::words() {
        assert!((3..=8).contains(&w.len()), "unexpected length for {w:?}");
    }
}

#[test]
fn first_four_letters_are_unique() {
    // BIP-39 guarantees this, and it is what makes truncated (4-letter) entry
    // unambiguous — which is why we detect truncated pastes at all.
    let mut seen = std::collections::HashSet::new();
    for w in wordlist::words() {
        let prefix: String = w.chars().take(4).collect();
        assert!(
            seen.insert(prefix.clone()),
            "duplicate 4-prefix {prefix:?} at {w:?}"
        );
    }
}

#[test]
fn prefix_table_is_sorted_and_same_length_as_wordlist() {
    let prefixes = wordlist::prefixes();
    assert_eq!(prefixes.len(), wordlist::words().len());
    for pair in prefixes.windows(2) {
        assert!(pair[0] < pair[1], "prefix table not sorted");
    }
}

#[test]
fn lookup_agrees_with_linear_scan() {
    // Guards against a binary-search bug making the whole detector fail open.
    for w in wordlist::words() {
        assert!(wordlist::is_word(w), "is_word missed {w:?}");
        assert!(
            wordlist::is_prefix_of_word(&w[..w.len().min(4)]),
            "is_prefix missed {w:?}"
        );
    }
    for not_a_word in [
        "", "a", "zzzz", "abandonn", "the", "and", "qqqqqqqq", "ABANDON",
    ] {
        assert!(
            !wordlist::is_word(not_a_word),
            "false positive on {not_a_word:?}"
        );
    }
}

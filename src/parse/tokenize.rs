//! Normalisation shared by both secret-material detectors.
//!
//! Two normalised forms are produced, deliberately:
//!
//! * **cleaned** — zero-width characters removed, case preserved. Needed because base58
//!   is case-significant: `K`, `L` and `c` mean different things from `k`, `l` and `C`,
//!   so WIF shape detection cannot run on lowercased text.
//! * **lowered** — cleaned, then lowercased. Used for wordlist lookup and for matching
//!   extended-private-key prefixes without caring about `xprv` vs `Zprv`.
//!
//! Both are `Zeroizing`, since both are copies of whatever the user pasted.

use zeroize::Zeroizing;

/// Invisible characters that survive a copy-paste from a web page and would otherwise
/// break tokenisation — which is also how someone would try to smuggle input past a
/// naive detector.
const ZERO_WIDTH: [char; 5] = ['\u{200b}', '\u{200c}', '\u{200d}', '\u{2060}', '\u{feff}'];

/// Separators. Whitespace covers the usual pastes; `,` and `;` cover the comma-separated
/// lists people produce when transcribing a seed out of a spreadsheet or a chat message.
fn is_separator(c: char) -> bool {
    c.is_whitespace() || c == ',' || c == ';'
}

pub(crate) fn clean(input: &str) -> Zeroizing<String> {
    let mut out = String::with_capacity(input.len());
    out.extend(input.chars().filter(|c| !ZERO_WIDTH.contains(c)));
    Zeroizing::new(out)
}

pub(crate) fn lowercase(cleaned: &str) -> Zeroizing<String> {
    // Preallocate for the worst case so the buffer is never reallocated: a realloc would
    // leave a copy of the input in freed memory that `zeroize` can no longer reach.
    //
    // 3x is not a guess. The worst byte expansion of `char::to_lowercase` across the whole
    // of Unicode is 1.5x — U+0130 (İ), two bytes, lowering to `i` plus a combining dot at
    // three. Asserted in `lowercase_never_reallocates` below, by scanning every scalar
    // value, because the no-realloc claim is only true if that bound holds.
    let mut out = String::with_capacity(cleaned.len().saturating_mul(3).saturating_add(16));
    out.extend(cleaned.chars().flat_map(char::to_lowercase));
    Zeroizing::new(out)
}

/// Word-shaped tokens for mnemonic detection: split on separators, then strip anything
/// that is not an ASCII lowercase letter from each end.
///
/// The stripping is what makes `"1. abandon"`, `"abandon,"` and `"(abandon)"` all reduce
/// to `abandon`. It only ever *adds* matches, which is the direction we want to fail in.
///
/// Returned slices borrow from `lowered`; nothing is copied.
pub(crate) fn word_tokens(lowered: &str) -> Vec<&str> {
    lowered
        .split(is_separator)
        .map(|token| token.trim_matches(|c: char| !c.is_ascii_lowercase()))
        .filter(|token| !token.is_empty())
        .collect()
}

/// Tokens for key-shaped material. Splits on separators *and* on descriptor punctuation,
/// so a key nested inside `wsh(sortedmulti(2,...))` is examined on its own.
///
/// Returned slices borrow from `cleaned`; nothing is copied.
pub(crate) fn key_tokens(cleaned: &str) -> Vec<&str> {
    cleaned
        .split(|c: char| {
            is_separator(c)
                || matches!(
                    c,
                    '(' | ')'
                        | '['
                        | ']'
                        | '{'
                        | '}'
                        | '<'
                        | '>'
                        | '#'
                        | '/'
                        | '\\'
                        | '"'
                        | '\''
                        | ':'
                        | '*'
                        | '='
                        | '|'
                )
        })
        .filter(|token| !token.is_empty())
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn strips_zero_width_without_disturbing_anything_else() {
        let cleaned = clean("aban\u{200b}don ab\u{feff}ility");
        assert_eq!(cleaned.as_str(), "abandon ability");
    }

    #[test]
    fn splits_numbered_lists_into_bare_words() {
        let lowered = lowercase(&clean("1. Abandon  2. Ability"));
        assert_eq!(word_tokens(&lowered), vec!["abandon", "ability"]);
    }

    #[test]
    fn unwraps_keys_from_descriptor_punctuation() {
        let cleaned = clean("wsh(sortedmulti(2,[d34db33f/48h/0h]KEY1/0/*,KEY2/0/*))");
        let tokens = key_tokens(&cleaned);
        assert!(tokens.contains(&"KEY1"), "got {tokens:?}");
        assert!(tokens.contains(&"KEY2"), "got {tokens:?}");
    }

    #[test]
    fn lowercase_never_reallocates() {
        // The zeroization story depends on this: if the buffer grows, the old allocation
        // is freed with a copy of the input still in it, somewhere `zeroize` cannot reach.
        // So the preallocation factor is a security parameter, and it is checked against
        // every Unicode scalar value rather than against the cases someone thought of.
        let mut worst = 0.0f64;
        let mut worst_char = '\0';
        for cp in 0u32..=0x0010_FFFF {
            let Some(c) = char::from_u32(cp) else {
                continue;
            };
            let out: usize = c.to_lowercase().map(char::len_utf8).sum();
            let ratio = out as f64 / c.len_utf8() as f64;
            if ratio > worst {
                worst = ratio;
                worst_char = c;
            }
        }
        assert!(
            worst <= 3.0,
            "to_lowercase expands U+{:04X} by {worst}x; the 3x preallocation in `lowercase` \
             is no longer sufficient and the no-realloc guarantee is broken",
            worst_char as u32
        );

        // And the property itself, on the worst character, at length.
        let input: String = std::iter::repeat_n(worst_char, 4096).collect();
        let lowered = lowercase(&input);
        assert!(lowered.len() <= input.len().saturating_mul(3).saturating_add(16));
    }

    #[test]
    fn handles_multibyte_input_without_panicking() {
        let cleaned = clean("日本語 🔑 café");
        let lowered = lowercase(&cleaned);
        let _ = word_tokens(&lowered);
        let _ = key_tokens(&cleaned);
    }
}

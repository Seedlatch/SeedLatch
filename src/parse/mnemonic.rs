//! Detector A — BIP-39 mnemonics.
//!
//! # Why this does not validate BIP-39 checksums
//!
//! The obvious implementation is "12/15/18/21/24 words, all in the wordlist, checksum
//! valid". Every one of those conditions is a way to fail *open*:
//!
//! * A user pastes a phrase with one word mistyped. Checksum fails, so a strict detector
//!   waves it through and the tool then processes a real seed phrase.
//! * A user pastes 8 of 12 words because the selection clipped. Word count is wrong, so a
//!   strict detector waves it through.
//! * A user pastes their phrase inside a sentence ("here is my seed: ..."). Word count is
//!   wrong again.
//! * A user writes the phrase in 4-letter shorthand, which several devices accept.
//!
//! Every one of those is still secret material, and the cost of missing one is somebody's
//! coins. So detection is deliberately loose: it looks for *a dense region of wordlist
//! words*, not for a well-formed mnemonic. Checksums are never computed, which also means
//! this code never derives anything from the input.
//!
//! # The other direction
//!
//! A false positive costs a confused user one re-read of the error message. That is not
//! free, so the thresholds below were calibrated against real descriptors, extended public
//! keys, wallet-export JSON and English prose; but where the two errors compete, this
//! errs toward rejecting.
//!
//! # Thresholds
//!
//! Two independent triggers, both required to clear a floor of 8 tokens:
//!
//! 1. **Run** — 8 or more consecutive wordlist words. Catches a clean phrase, a phrase
//!    embedded in prose, and a partial paste. English prose does not reach 8 because the
//!    function words that hold sentences together (`the`, `and`, `of`, `to`, `a`, `is`,
//!    `in`, `my`) are not in the wordlist — it has no word shorter than three letters.
//! 2. **Density** — 8 or more wordlist words making up at least three quarters of all
//!    tokens. Catches a phrase broken up by typos, line numbers or stray punctuation.
//!    The densest ordinary English measured during calibration reached 0.68.
//!
//! Both triggers run twice: once on exact matches, once allowing 3- and 4-letter
//! shorthand. BIP-39 guarantees four letters identify a word uniquely.

use crate::parse::wordlist;

/// Consecutive wordlist words that constitute a detection on their own.
const MIN_RUN: usize = 8;
/// Wordlist words that must be present before density is considered at all.
const MIN_MATCHED: usize = 8;
/// Density trigger, as a fraction: matched / total >= 3/4. Kept as integers to avoid
/// float comparison in a security decision.
const MIN_DENSITY_NUMERATOR: usize = 3;
const MIN_DENSITY_DENOMINATOR: usize = 4;

#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
struct Counts {
    matched: usize,
    longest_run: usize,
}

impl Counts {
    fn observe(&mut self, is_match: bool, current_run: &mut usize) {
        if is_match {
            self.matched += 1;
            *current_run += 1;
            if *current_run > self.longest_run {
                self.longest_run = *current_run;
            }
        } else {
            *current_run = 0;
        }
    }

    fn is_dense(&self, total: usize) -> bool {
        self.matched.saturating_mul(MIN_DENSITY_DENOMINATOR)
            >= total.saturating_mul(MIN_DENSITY_NUMERATOR)
    }
}

/// The raw measurements behind a mnemonic decision, exposed so the thresholds can be
/// attacked rather than taken on trust.
///
/// This exists for calibration and independent review — see `tests/calibration.rs`, which
/// prints the distribution across a corpus of realistic non-secret inputs. It is public
/// because a reviewer needs to be able to add their own negatives and see how close they
/// come to the line, not just whether they crossed it.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub struct MnemonicSignals {
    pub total_tokens: usize,
    pub exact_matches: usize,
    pub exact_longest_run: usize,
    pub shorthand_matches: usize,
    pub shorthand_longest_run: usize,
}

impl MnemonicSignals {
    /// Fraction of tokens that are wordlist words, taking the more generous of the two
    /// matching modes. Reported for review; the decision itself uses integer arithmetic.
    pub fn density(&self) -> f64 {
        if self.total_tokens == 0 {
            return 0.0;
        }
        self.exact_matches.max(self.shorthand_matches) as f64 / self.total_tokens as f64
    }

    pub fn longest_run(&self) -> usize {
        self.exact_longest_run.max(self.shorthand_longest_run)
    }

    fn exact(&self) -> Counts {
        Counts {
            matched: self.exact_matches,
            longest_run: self.exact_longest_run,
        }
    }

    fn shorthand(&self) -> Counts {
        Counts {
            matched: self.shorthand_matches,
            longest_run: self.shorthand_longest_run,
        }
    }

    /// Whether the run trigger fires: a block of consecutive wordlist words long enough
    /// that no ordinary sentence reaches it.
    pub fn run_trigger(&self) -> bool {
        self.total_tokens >= MIN_MATCHED && self.longest_run() >= MIN_RUN
    }

    /// Whether the density trigger fires: enough wordlist words, at a high enough
    /// proportion of the whole input.
    pub fn density_trigger(&self) -> bool {
        if self.total_tokens < MIN_MATCHED {
            return false;
        }
        let total = self.total_tokens;
        (self.exact().matched >= MIN_MATCHED && self.exact().is_dense(total))
            || (self.shorthand().matched >= MIN_MATCHED && self.shorthand().is_dense(total))
    }

    pub fn triggers(&self) -> bool {
        self.run_trigger() || self.density_trigger()
    }
}

/// Measure `tokens` (already lowercased and stripped) without deciding anything.
pub(crate) fn measure(tokens: &[&str]) -> MnemonicSignals {
    let mut exact = Counts::default();
    let mut exact_run = 0usize;
    let mut shorthand = Counts::default();
    let mut shorthand_run = 0usize;

    for token in tokens {
        let is_exact = wordlist::is_word(token);
        // Shorthand entry writes every word as its first four letters; words already
        // shorter than that stay whole. Anything longer is only ever an exact match, so
        // ordinary long English words cannot inflate this count.
        let is_shorthand =
            is_exact || (matches!(token.len(), 3 | 4) && wordlist::is_prefix_of_word(token));

        exact.observe(is_exact, &mut exact_run);
        shorthand.observe(is_shorthand, &mut shorthand_run);
    }

    MnemonicSignals {
        total_tokens: tokens.len(),
        exact_matches: exact.matched,
        exact_longest_run: exact.longest_run,
        shorthand_matches: shorthand.matched,
        shorthand_longest_run: shorthand.longest_run,
    }
}

/// Whether `tokens` look like pasted seed material.
pub(crate) fn looks_like_mnemonic(tokens: &[&str]) -> bool {
    measure(tokens).triggers()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::parse::tokenize;

    fn detect(input: &str) -> bool {
        let cleaned = tokenize::clean(input);
        let lowered = tokenize::lowercase(&cleaned);
        looks_like_mnemonic(&tokenize::word_tokens(&lowered))
    }

    #[test]
    fn density_boundary_is_exactly_three_quarters() {
        // 9 wordlist words in 12 tokens is exactly 3/4 and must trigger.
        let mut tokens: Vec<&str> = wordlist::words().iter().take(9).copied().collect();
        tokens.extend(["qqqq", "qqqqq", "qqqqqq"]);
        // Break the run so only the density trigger can fire.
        tokens.swap(2, 10);
        tokens.swap(5, 11);
        assert!(looks_like_mnemonic(&tokens), "3/4 density must trigger");
    }

    #[test]
    fn just_below_the_density_boundary_does_not_trigger() {
        // 8 wordlist words in 12 tokens is 2/3.
        let mut tokens: Vec<&str> = wordlist::words().iter().take(8).copied().collect();
        tokens.extend(["qqqq", "qqqqq", "qqqqqq", "qqqqqqq"]);
        tokens.swap(1, 8);
        tokens.swap(3, 9);
        tokens.swap(5, 10);
        assert!(!looks_like_mnemonic(&tokens));
    }

    #[test]
    fn seven_consecutive_words_is_below_the_run_trigger() {
        assert!(!detect("ability able about above absent absorb abstract"));
    }

    #[test]
    fn eight_consecutive_words_reaches_the_run_trigger() {
        assert!(detect(
            "ability able about above absent absorb abstract absurd"
        ));
    }
}

//! Input handling, and the secret-material rejection that has to happen before it.
//!
//! # The one rule
//!
//! [`guard_input`] is the only way to obtain an [`AcceptedInput`], and every other
//! function in this crate that touches user input takes an [`AcceptedInput`]. That is the
//! mechanism by which "detect before parsing, derivation, storage, display, or any network
//! call" is enforced by the compiler rather than by remembering to call something.
//!
//! # Zeroization — what is and is not promised
//!
//! Rust-side buffers holding a copy of the input are `Zeroizing`, and the lowercase buffer
//! is preallocated so it cannot reallocate and strand a copy in freed memory.
//!
//! None of that extends to the browser. JavaScript strings are immutable and
//! garbage-collected, so a pasted phrase can persist in the JS heap until the collector
//! decides otherwise, and neither this crate nor the frontend can force that. The frontend
//! is required to pass input into WASM as early as possible, keep no JS-side copy, and
//! clear the DOM field — and to tell the user this limitation exists rather than implying
//! a guarantee that cannot be made.

pub mod extended_key;
pub mod wordlist;

mod mnemonic;
mod private_key;
mod tokenize;

pub use mnemonic::MnemonicSignals;

use core::fmt;

/// Measure an input against the mnemonic thresholds without deciding anything.
///
/// Exposed for calibration and independent review: a reviewer attacking the thresholds
/// needs to see how close a sample came to the line, not just which side it landed on.
/// See `tests/calibration.rs`.
pub fn mnemonic_signals(raw: &str) -> MnemonicSignals {
    let cleaned = tokenize::clean(raw);
    let lowered = tokenize::lowercase(&cleaned);
    mnemonic::measure(&tokenize::word_tokens(&lowered))
}

/// A category of secret material. Deliberately carries no value — only the fact that
/// something of this kind was seen.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum SecretMaterial {
    /// A BIP-39 recovery phrase, whole or partial, exact or in 4-letter shorthand.
    Bip39Mnemonic,
    /// An extended private key: `xprv`/`yprv`/`zprv`/`tprv`/`uprv`/`vprv`, in any case,
    /// anywhere in the input — including inside an otherwise-valid descriptor.
    ExtendedPrivateKey,
    /// A WIF-encoded private key.
    WifPrivateKey,
    /// A raw 32-byte private key written as 64 hexadecimal characters.
    RawHexPrivateKey,
}

impl SecretMaterial {
    /// Stable machine identifier. Safe to log, safe to switch on, safe to put in a report.
    ///
    /// Distinct from [`Self::label`] on purpose: the label is reviewed copy and will
    /// change when someone edits the wording, whereas this must not.
    pub const fn key(self) -> &'static str {
        match self {
            Self::Bip39Mnemonic => "bip39_mnemonic",
            Self::ExtendedPrivateKey => "extended_private_key",
            Self::WifPrivateKey => "wif_private_key",
            Self::RawHexPrivateKey => "raw_hex_private_key",
        }
    }

    /// User-facing name of the category. Never the value.
    ///
    /// This text appears on the blocking interstitial. Do not rewrite it unprompted —
    /// it is reviewed wording, drafted in `spec.md` §6.1.
    pub const fn label(self) -> &'static str {
        match self {
            Self::Bip39Mnemonic => "a recovery phrase (seed words)",
            Self::ExtendedPrivateKey => "an extended private key",
            Self::WifPrivateKey => "a private key in WIF form",
            Self::RawHexPrivateKey => "a raw private key in hexadecimal",
        }
    }
}

/// The outcome of a scan: which categories were seen, and nothing else.
///
/// `Debug` and `Display` are both safe to log. Neither can contain input, because this
/// type has nowhere to put it. `tests/secret_material.rs` asserts that continuously.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SecretMaterialFound {
    categories: Vec<SecretMaterial>,
}

impl SecretMaterialFound {
    pub fn categories(&self) -> &[SecretMaterial] {
        &self.categories
    }

    pub fn contains(&self, category: SecretMaterial) -> bool {
        self.categories.contains(&category)
    }

    /// Human-readable summary of what was found. Terse and factual.
    ///
    /// **This is not the interstitial copy.** That lives in `docs/spec.md` §6.1, is
    /// reviewed wording, and is rendered by the frontend from [`SecretMaterial::label`].
    /// An earlier version of this type carried its own `assurance()` and `advice()`
    /// strings, which meant the user-facing wording existed in two places — and the
    /// unreviewed one could reach a user through `Display`. It had already drifted: it
    /// listed `xpub, ypub, zpub, tpub` without the SLIP-132 multisig forms, and it
    /// asserted "the input has been cleared", which this library has no way to know
    /// because clearing the field is the frontend's job.
    pub fn summary(&self) -> String {
        let labels: Vec<&str> = self.categories.iter().map(|c| c.label()).collect();
        format!("input refused: looks like {}", join_with_and(&labels))
    }
}

fn join_with_and(items: &[&str]) -> String {
    match items {
        [] => String::from("secret key material"),
        [only] => (*only).to_string(),
        [rest @ .., last] => format!("{} and {last}", rest.join(", ")),
    }
}

impl fmt::Display for SecretMaterialFound {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.summary())
    }
}

impl std::error::Error for SecretMaterialFound {}

/// The largest input this tool will look at, in bytes.
///
/// A descriptor is small — a 20-of-20 multisig with full key origins is around 3 KB, and
/// wallet-export JSON runs to tens of KB. Past 100 KB it is a file, not a wallet identifier.
///
/// The bound exists because [`tokenize::lowercase`] preallocates three times the input
/// length, deliberately, so the buffer cannot reallocate and strand a copy of a secret in
/// freed memory. That makes a large paste cost several times its own size in a 32-bit WASM
/// heap, where the ceiling is low and an allocation failure aborts the module.
pub const MAX_INPUT_BYTES: usize = 100 * 1024;

/// Why an input was refused.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum Refusal {
    /// The input carries something that can spend. Categories only, never the value.
    SecretMaterial(SecretMaterialFound),
    /// The input exceeded [`MAX_INPUT_BYTES`] and **was not examined at all**.
    ///
    /// Sizes are not secret material — the user knows what they pasted — and they never
    /// leave the device.
    TooLarge {
        limit_bytes: usize,
        actual_bytes: usize,
    },
}

impl fmt::Display for Refusal {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::SecretMaterial(found) => f.write_str(&found.summary()),
            Self::TooLarge {
                limit_bytes,
                actual_bytes,
            } => write!(
                f,
                "input refused: {actual_bytes} bytes exceeds the {limit_bytes}-byte limit, \
                 and was not examined"
            ),
        }
    }
}

impl std::error::Error for Refusal {}

/// Scans for secret material without consuming the input.
///
/// **Unbounded.** This is the raw detector and it allocates in proportion to its input;
/// [`guard_input`] is the entry point that bounds it. Exposed for calibration and review
/// (`tests/calibration.rs`), not as a way into the pipeline — nothing downstream accepts
/// what this returns, because only `guard_input` can produce an [`AcceptedInput`].
///
/// Returns every category found, not just the first — a panicking user who pastes a whole
/// backup file may have several kinds in there at once, and the interstitial should say so.
pub fn scan_for_secret_material(raw: &str) -> Option<SecretMaterialFound> {
    let cleaned = tokenize::clean(raw);
    let lowered = tokenize::lowercase(&cleaned);

    let mut categories = Vec::new();

    // Ordered most-alarming first; this is the order the interstitial reads them in.
    if mnemonic::looks_like_mnemonic(&tokenize::word_tokens(&lowered)) {
        categories.push(SecretMaterial::Bip39Mnemonic);
    }
    // Case-insensitive, but on the original-case buffer: the coincidence rule needs to see
    // real base58, and case-folding `L` to `l` would take a character out of the alphabet.
    if private_key::contains_extended_private_key(&cleaned) {
        categories.push(SecretMaterial::ExtendedPrivateKey);
    }
    if private_key::contains_wif(&cleaned) {
        categories.push(SecretMaterial::WifPrivateKey);
    }
    if private_key::contains_raw_hex_key(&cleaned) {
        categories.push(SecretMaterial::RawHexPrivateKey);
    }

    if categories.is_empty() {
        None
    } else {
        Some(SecretMaterialFound { categories })
    }
}

/// Everything that can construct an [`AcceptedInput`], and nothing else.
///
/// # Why this is a module rather than two items in the file above
///
/// Rust privacy is module-**and-descendants**: a field private to `parse` is reachable from
/// `parse::mnemonic`, `parse::private_key` and every other child. So while
/// `AcceptedInput`'s field was merely private to `parse`, any sibling detector module could
/// have written `AcceptedInput(Zeroizing::new(raw))` and produced unguarded input that the
/// rest of the crate would then treat as checked. That was verified by compiling exactly
/// that expression, not inferred.
///
/// The claim being made elsewhere is that the ordering guarantee is enforced by the
/// compiler. Outside `src/parse/` it was. Inside it — where the detectors live, and where a
/// mistake is both most likely and least visible — it was a convention.
///
/// This module closes the gap: it has no children, so its private field is reachable from
/// nowhere else in the crate, and [`guard_input`] becomes the only code anywhere that can
/// produce the type. Do not add submodules here, and do not make the field `pub(super)`.
mod guarded {
    use core::fmt;
    use zeroize::Zeroizing;

    use super::{scan_for_secret_material, Refusal, MAX_INPUT_BYTES};

    /// Input that has been through [`guard_input`] and carries no detectable secret material.
    ///
    /// Held in a `Zeroizing` buffer. There is no `Deref`, no `Into<String>` and no derived
    /// `Debug`: getting the contents back out is deliberately a deliberate act.
    ///
    /// # This holds the original bytes, exactly as pasted. Do not normalise case.
    ///
    /// Detection folds case, and is right to: SLIP-132 really does use capitals, so `Yprv`
    /// and `Zprv` are the mainnet *multisig* private prefixes and `Uprv`/`Vprv` their testnet
    /// forms, and someone retyping from a metal plate will mangle case anyway.
    ///
    /// **Parsing must not.** `ypub` and `Ypub` are different SLIP-132 version bytes — the
    /// first is single-sig nested segwit, the second is multisig. Folding them together means
    /// deriving the wrong script type, which means generating addresses the user does not own,
    /// checking balances that are not theirs, and reporting on a wallet that does not exist.
    /// A user could act on that. `zpub`/`Zpub` and `upub`/`Upub`/`vpub`/`Vpub` are the same
    /// hazard.
    ///
    /// So this type is the boundary: everything upstream of it may fold case freely, nothing
    /// downstream of it may. If a future change adds `to_lowercase()` anywhere in construction
    /// or in [`Self::as_str`], that is the bug — not a simplification.
    pub struct AcceptedInput(Zeroizing<String>);

    impl AcceptedInput {
        /// The input verbatim. Case-significant — see the type docs before normalising it.
        pub fn as_str(&self) -> &str {
            &self.0
        }
    }

    impl fmt::Debug for AcceptedInput {
        /// Redacts. `AcceptedInput` is not secret by definition, but it is still the user's
        /// wallet, and a derived `Debug` is how that ends up in a log by accident.
        fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
            write!(f, "AcceptedInput(<{} bytes, redacted>)", self.0.len())
        }
    }

    /// The single entry point for user input.
    ///
    /// Nothing else in this crate may accept a raw `&str` that came from a user.
    ///
    /// # The size check runs first, and that has a consequence worth naming
    ///
    /// The bound exists to cap how much the scan is willing to allocate, so it has to happen
    /// *before* the scan allocates anything. That means an oversized input is refused without
    /// ever being examined — so if someone pastes a 200 KB wallet backup that happens to
    /// contain their recovery phrase, they are told the input was too large and **not** that it
    /// held a secret, because we genuinely do not know.
    ///
    /// This is the right trade in the fail-closed direction: the input is refused either way
    /// and never processed, and the alternative — scanning first — reintroduces exactly the
    /// unbounded allocation the limit exists to prevent. Truncating instead of refusing would
    /// be far worse: cutting a mnemonic below the run threshold turns a detection into a miss,
    /// which is fail-*open*. The interstitial copy is written to match, saying plainly that
    /// nothing was examined (`docs/spec.md` §6.1).
    pub fn guard_input(raw: &str) -> Result<AcceptedInput, Refusal> {
        if raw.len() > MAX_INPUT_BYTES {
            return Err(Refusal::TooLarge {
                limit_bytes: MAX_INPUT_BYTES,
                actual_bytes: raw.len(),
            });
        }

        match scan_for_secret_material(raw) {
            Some(found) => Err(Refusal::SecretMaterial(found)),
            None => Ok(AcceptedInput(Zeroizing::new(raw.to_owned()))),
        }
    }
}

pub use guarded::{guard_input, AcceptedInput};

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn accepted_input_debug_does_not_reveal_contents() {
        let accepted = guard_input("wpkh(xpub-shaped-placeholder)").unwrap();
        let rendered = format!("{accepted:?}");
        assert!(!rendered.contains("wpkh"));
        assert!(rendered.contains("redacted"));
    }

    #[test]
    fn joins_categories_readably() {
        assert_eq!(join_with_and(&["one"]), "one");
        assert_eq!(join_with_and(&["one", "two"]), "one and two");
        assert_eq!(
            join_with_and(&["one", "two", "three"]),
            "one, two and three"
        );
    }
}

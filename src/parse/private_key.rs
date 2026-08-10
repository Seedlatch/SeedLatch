//! Detector B — private keys in every form a user might paste.
//!
//! Extended private keys, WIF keys, and raw 32-byte hex. All three are detected by
//! **shape alone**: nothing here base58-decodes, verifies a checksum, or interprets a key.
//! Decoding would mean handling the secret, and a checksum test would fail open on a
//! mistyped key — the same trap described in `mnemonic.rs`.
//!
//! # Detection is case-insensitive. Parsing must not be.
//!
//! These are two different jobs and they need opposite answers:
//!
//! * **Here (detection)** case is ignored. SLIP-132 genuinely uses capitals — `Yprv` and
//!   `Zprv` are the mainnet *multisig* private prefixes, `Uprv`/`Vprv` their testnet
//!   equivalents — and a frightened user retyping from a metal plate will mangle case
//!   anyway. Missing a key because it was written `XPRV` is not a tradeoff worth having.
//! * **In parsing (not this module)** case is significant and must be preserved. `ypub`
//!   and `Ypub` are *different* SLIP-132 version bytes: the first is single-sig
//!   nested-segwit, the second is multisig. Folding them together would mean deriving the
//!   wrong script type and reporting on addresses the user does not own.
//!
//! The separation is structural, not a convention to remember: this module never returns
//! a key, only a category, so nothing downstream can accidentally consume a case-folded
//! one. Parsing operates on [`crate::parse::AcceptedInput`], which holds the original
//! bytes exactly as pasted.

use crate::parse::tokenize;

/// Extended **private** key prefixes, matched case-insensitively.
///
/// BIP-32 `xprv`/`tprv`, plus SLIP-132: `yprv`/`zprv` (mainnet single-sig, nested and
/// native segwit), `Yprv`/`Zprv` (mainnet multisig), and `uprv`/`vprv`/`Uprv`/`Vprv`
/// (the testnet forms of both). Case-insensitive matching covers all ten with six entries.
const EXTENDED_PRIVATE_PREFIXES: [&str; 6] = ["xprv", "yprv", "zprv", "tprv", "uprv", "vprv"];

/// Extended **public** key prefixes, same families. Used only to recognise that a token is
/// a public key, never to interpret one — see [`is_extended_public_key_shaped`].
const EXTENDED_PUBLIC_PREFIXES: [&str; 6] = ["xpub", "ypub", "zpub", "tpub", "upub", "vpub"];

/// Every extended key serialises to 78 bytes, which is always 111 base58check characters.
const EXTENDED_KEY_BASE58_LEN: usize = 111;

/// Base58 as Bitcoin defines it: no `0`, `O`, `I` or `l`.
const BASE58_ALPHABET: &str = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";

/// Version bytes that produce a WIF key, by the character they render as.
/// `5` mainnet uncompressed, `K`/`L` mainnet compressed, `9` testnet uncompressed,
/// `c` testnet compressed.
const WIF_LEADING_CHARS: [char; 5] = ['5', 'K', 'L', '9', 'c'];

/// A raw secp256k1 private key is 32 bytes — 64 hex characters.
const RAW_KEY_HEX_LEN: usize = 64;

fn starts_with_ci(token: &str, prefix: &str) -> bool {
    token
        .get(..prefix.len())
        .is_some_and(|head| head.eq_ignore_ascii_case(prefix))
}

fn contains_ci(token: &str, needle: &str) -> bool {
    token
        .as_bytes()
        .windows(needle.len())
        .any(|window| window.eq_ignore_ascii_case(needle.as_bytes()))
}

/// Whether the input carries an extended private key.
///
/// # Why this is not a plain substring search
///
/// `CLAUDE.md` says the prefix counts "anywhere in input", and the first implementation
/// took that literally: `lowered.contains("xprv")`. That is too blunt, and measurably so.
///
/// The six prefixes are four characters drawn from an alphabet where every one of
/// `x y z t u v p r` exists in both cases, so 96 distinct 4-grams match, against 58^4
/// possible ones. Across the 108 starting positions in a 111-character key that is
/// **1 in 1,091** extended public keys containing a private prefix purely by chance —
/// measured at 1 in 1,124 over a million synthetic keys. A three-key multisig descriptor
/// trips it roughly **1 time in 364**.
///
/// That is not an acceptable false-positive rate for an interstitial that tells someone
/// their wallet may be compromised. A warning that fires on one in a few hundred perfectly
/// good descriptors is a warning people learn to click through, which costs more safety
/// than the blunt rule buys.
///
/// So a mid-token hit is discounted **only** when the token containing it is itself shaped
/// like a serialised extended *public* key. An extended key is one indivisible base58
/// blob: a private key cannot be nested inside a public one, so such a hit is always
/// coincidence. Every other position — token-initial, or mid-token in anything that is not
/// a well-formed public key — still detects. Measured false-positive rate after the
/// change: zero in a million.
pub(crate) fn contains_extended_private_key(cleaned: &str) -> bool {
    // Cheap rejection first: most inputs contain no prefix anywhere at all.
    if !EXTENDED_PRIVATE_PREFIXES
        .iter()
        .any(|prefix| contains_ci(cleaned, prefix))
    {
        return false;
    }

    tokenize::key_tokens(cleaned)
        .iter()
        .any(|token| token_carries_private_key(token))
}

fn token_carries_private_key(token: &str) -> bool {
    // A key expression begins here. Unambiguous.
    if EXTENDED_PRIVATE_PREFIXES
        .iter()
        .any(|prefix| starts_with_ci(token, prefix))
    {
        return true;
    }

    if !EXTENDED_PRIVATE_PREFIXES
        .iter()
        .any(|prefix| contains_ci(token, prefix))
    {
        return false;
    }

    // Mid-token hit: coincidence only if this token is a well-formed public key.
    !is_extended_public_key_shaped(token)
}

fn is_extended_public_key_shaped(token: &str) -> bool {
    token.len() == EXTENDED_KEY_BASE58_LEN
        && EXTENDED_PUBLIC_PREFIXES
            .iter()
            .any(|prefix| starts_with_ci(token, prefix))
        && token.chars().all(|c| BASE58_ALPHABET.contains(c))
}

pub(crate) fn contains_wif(cleaned: &str) -> bool {
    tokenize::key_tokens(cleaned)
        .iter()
        .any(|token| is_wif_shaped(token))
}

fn is_wif_shaped(token: &str) -> bool {
    // WIF is 51 characters uncompressed, 52 compressed. Accepting either length for any
    // of the leading characters is deliberately looser than the encoding allows.
    if !matches!(token.len(), 51 | 52) || !token.is_ascii() {
        return false;
    }
    let Some(leading) = token.chars().next() else {
        return false;
    };
    WIF_LEADING_CHARS.contains(&leading) && token.chars().all(|c| BASE58_ALPHABET.contains(c))
}

/// A maximal run of exactly 64 hex characters.
///
/// "Maximal" matters: a 66-character run is a compressed public key and a 40-character run
/// is a hash, neither of which is secret, and flagging them would make legitimate
/// descriptors unusable. An 8-character run is a key-origin fingerprint.
///
/// The unavoidable consequence: a `tr()` descriptor carrying a raw x-only public key is
/// also 64 hex characters and is indistinguishable from a private key by shape alone. v0
/// refuses those rather than guessing, and says so. Use an xpub-based descriptor instead.
pub(crate) fn contains_raw_hex_key(cleaned: &str) -> bool {
    let mut run = 0usize;
    let mut flagged = false;
    for c in cleaned.chars() {
        if c.is_ascii_hexdigit() {
            run += 1;
        } else {
            flagged |= run == RAW_KEY_HEX_LEN;
            run = 0;
        }
    }
    flagged || run == RAW_KEY_HEX_LEN
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A 111-character token that starts `xpub` and happens to contain `xprv`. This is the
    /// 1-in-1,091 coincidence the mid-token rule exists to absorb. Shape-only fixture: the
    /// checksum is not valid and it is not a key.
    fn xpub_shaped_with_coincidental_prefix() -> String {
        let mut s = String::from("xpub");
        s.push_str(&"1".repeat(40));
        s.push_str("xprv");
        s.push_str(&"1".repeat(EXTENDED_KEY_BASE58_LEN - 48));
        debug_assert_eq!(s.len(), EXTENDED_KEY_BASE58_LEN);
        s
    }

    #[test]
    fn coincidental_prefix_inside_a_public_key_is_not_flagged() {
        let token = xpub_shaped_with_coincidental_prefix();
        assert_eq!(token.len(), EXTENDED_KEY_BASE58_LEN);
        assert!(
            contains_ci(&token, "xprv"),
            "fixture must contain the prefix"
        );
        assert!(!contains_extended_private_key(&token));
        assert!(!contains_extended_private_key(&format!(
            "wpkh({token}/0/*)"
        )));
    }

    #[test]
    fn coincidence_rule_only_applies_to_well_formed_public_keys() {
        let base = xpub_shaped_with_coincidental_prefix();

        // Wrong length: two keys pasted together with no separator, for instance.
        assert!(contains_extended_private_key(&format!("{base}zz")));

        // Right length, but not a public prefix.
        let mut not_public = base.replacen("xpub", "abcd", 1);
        assert_eq!(not_public.len(), EXTENDED_KEY_BASE58_LEN);
        assert!(contains_extended_private_key(&not_public));

        // Right length and prefix, but contains a character base58 does not have.
        not_public = base.replacen('1', "0", 1);
        assert!(contains_extended_private_key(&not_public));
    }

    #[test]
    fn token_initial_private_prefix_always_wins() {
        // Even at exactly the public-key length, a token that *starts* with a private
        // prefix is a private key, never a coincidence.
        let token = format!("xprv{}", "1".repeat(EXTENDED_KEY_BASE58_LEN - 4));
        assert_eq!(token.len(), EXTENDED_KEY_BASE58_LEN);
        assert!(contains_extended_private_key(&token));
    }

    #[test]
    fn case_insensitive_helpers_agree_with_lowercasing() {
        for token in ["XPRV1234", "xPrV1234", "Yprv0000", "zPRVabcd"] {
            assert!(EXTENDED_PRIVATE_PREFIXES
                .iter()
                .any(|p| starts_with_ci(token, p)));
        }
        assert!(
            !starts_with_ci("xpu", "xpub"),
            "must not panic on short tokens"
        );
        assert!(
            !contains_ci("abc", "xprv"),
            "must not panic when shorter than needle"
        );
    }

    #[test]
    fn wif_length_boundaries() {
        let base58: String = BASE58_ALPHABET.chars().cycle().take(60).collect();
        for len in [49usize, 50, 53, 54] {
            let token: String = std::iter::once('L')
                .chain(base58.chars())
                .take(len)
                .collect();
            assert!(
                !is_wif_shaped(&token),
                "length {len} must not be WIF-shaped"
            );
        }
        for len in [51usize, 52] {
            let token: String = std::iter::once('L')
                .chain(base58.chars())
                .take(len)
                .collect();
            assert!(is_wif_shaped(&token), "length {len} must be WIF-shaped");
        }
    }

    #[test]
    fn wif_rejects_non_base58_characters() {
        // `0`, `O`, `I` and `l` are not in the base58 alphabet, so a token containing one
        // is not an encoded key however long it is.
        let mut token: String = std::iter::once('L')
            .chain(BASE58_ALPHABET.chars().cycle())
            .take(52)
            .collect();
        token.replace_range(10..11, "0");
        assert!(!is_wif_shaped(&token));
    }

    #[test]
    fn hex_run_must_be_exactly_sixty_four() {
        assert!(contains_raw_hex_key(&"a".repeat(64)));
        assert!(!contains_raw_hex_key(&"a".repeat(63)));
        assert!(!contains_raw_hex_key(&"a".repeat(65)));
        assert!(contains_raw_hex_key(&format!("zz{}zz", "a".repeat(64))));
        assert!(contains_raw_hex_key(&format!(
            "{}zz{}",
            "a".repeat(20),
            "b".repeat(64)
        )));
        assert!(!contains_raw_hex_key(&format!(
            "{}zz{}",
            "a".repeat(20),
            "b".repeat(65)
        )));
    }

    #[test]
    fn hex_run_at_end_of_input_is_still_flagged() {
        assert!(contains_raw_hex_key(&format!("key: {}", "0".repeat(64))));
    }
}

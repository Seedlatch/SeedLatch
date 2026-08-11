//! Known-answer tests for extended public key decoding.
//!
//! These go through the public API only — `guard_input` then `parse_extended_key` — because
//! that is the path the browser boundary will take, and a test that reaches past the guard
//! would not exercise the ordering the guard exists to enforce.
//!
//! Constructed coverage of all twenty registered versions lives in the unit tests inside
//! `src/parse/extended_key.rs`, which can reach base58 encoding to build them. The vectors
//! here are real: published, third-party, and not derived from anything this repository
//! computed.

use seedlatch::parse::extended_key::{
    parse_extended_key, ExtendedKeyError, KeyNetwork, ScriptType,
};
use seedlatch::parse::guard_input;

/// Three published SLIP-132 vectors — xpub, ypub and zpub for the same wallet at
/// m/44'/0'/0', m/49'/0'/0' and m/84'/0'/0'. Public keys only; see `data/PROVENANCE.md`.
const SLIP132_PUBKEYS: &str = include_str!("fixtures/slip132-pubkeys.txt");

/// Every `xpub` appearing in BIP-32, valid and invalid alike. Extracted for the
/// secret-material detector, which only reads shape and must not flag any of them.
const BIP32_XPUBS: &str = include_str!("fixtures/bip32-xpubs.txt");

/// The six `xpub` entries from BIP-32's **Test vector 5**, which exists to list keys a
/// conforming implementation must reject. They are a subset of `BIP32_XPUBS`.
///
/// Two of them are the reason `ExtendedKeyError::InconsistentDepth` exists: rust-bitcoin
/// decodes "zero depth with non-zero parent fingerprint" and "zero depth with non-zero
/// index" without complaint, so passing this file would be impossible on the dependency
/// alone.
const BIP32_INVALID_XPUBS: &str = include_str!("fixtures/bip32-invalid-xpubs.txt");

fn invalid_vectors() -> Vec<&'static str> {
    BIP32_INVALID_XPUBS
        .lines()
        .map(str::trim)
        .filter(|l| !l.is_empty())
        .collect()
}

fn parse(text: &str) -> Result<seedlatch::parse::extended_key::ExtendedKey, ExtendedKeyError> {
    let accepted = guard_input(text).expect("fixture must pass the secret-material guard");
    parse_extended_key(&accepted)
}

#[test]
fn the_three_published_vectors_carry_their_declared_script_types() {
    let mut seen = 0;
    for line in SLIP132_PUBKEYS.lines().filter(|l| !l.trim().is_empty()) {
        let key = parse(line).expect("published vector must parse");
        let expected = match &line[..4] {
            "xpub" => ScriptType::P2pkhOrP2sh,
            "ypub" => ScriptType::P2wpkhInP2sh,
            "zpub" => ScriptType::P2wpkh,
            other => panic!("unexpected prefix in fixture: {other}"),
        };
        assert_eq!(
            key.script_type(),
            expected,
            "script type for {}",
            &line[..4]
        );
        assert_eq!(key.network(), KeyNetwork::Mainnet);
        assert_eq!(key.prefix(), &line[..4], "prefix must survive decoding");
        seen += 1;
    }
    assert_eq!(seen, 3, "fixture must hold all three vectors");
}

#[test]
fn every_valid_bip32_vector_parses_as_mainnet_p2pkh_or_p2sh() {
    let invalid = invalid_vectors();
    let mut seen = 0;
    for line in BIP32_XPUBS.lines().map(str::trim).filter(|l| !l.is_empty()) {
        if invalid.contains(&line) {
            continue;
        }
        let key = parse(line).expect("valid BIP-32 vector must parse");
        assert_eq!(key.script_type(), ScriptType::P2pkhOrP2sh);
        assert_eq!(key.network(), KeyNetwork::Mainnet);
        assert_eq!(key.prefix(), "xpub");
        seen += 1;
    }
    assert_eq!(seen, 17, "23 extracted xpubs less the 6 from Test vector 5");
}

#[test]
fn every_invalid_bip32_vector_is_refused() {
    // The point of Test vector 5. A decoder that accepts these derives addresses from a key
    // no conforming wallet produced, and reports metadata that contradicts itself.
    let invalid = invalid_vectors();
    assert_eq!(invalid.len(), 6, "Test vector 5 lists six xpub entries");

    for line in &invalid {
        let outcome = parse(line);
        assert!(
            outcome.is_err(),
            "BIP-32 declares this key invalid but it parsed: {}...",
            &line[..12]
        );
    }
}

#[test]
fn the_two_zero_depth_vectors_are_refused_by_us_not_by_the_dependency() {
    // Named separately because they are the only two Test vector 5 entries rust-bitcoin
    // accepts. If a future version starts rejecting them this test still passes, but the
    // reason InconsistentDepth exists would be worth revisiting.
    let refused = invalid_vectors()
        .iter()
        .filter(|line| matches!(parse(line), Err(ExtendedKeyError::InconsistentDepth)))
        .count();

    assert_eq!(
        refused, 2,
        "exactly two vectors should fail the zero-depth consistency check"
    );
}

#[test]
fn the_ypub_and_zpub_vectors_are_genuinely_different_keys() {
    // Guards against a decoder that reads the version bytes and then ignores the payload.
    let keys: Vec<_> = SLIP132_PUBKEYS
        .lines()
        .filter(|l| !l.trim().is_empty())
        .map(|l| parse(l).expect("parses"))
        .collect();

    for (i, a) in keys.iter().enumerate() {
        for b in keys.iter().skip(i + 1) {
            assert_ne!(
                a.as_xpub().public_key,
                b.as_xpub().public_key,
                "different derivation paths must yield different keys"
            );
        }
    }
}

#[test]
fn a_truncated_key_is_refused() {
    let line = SLIP132_PUBKEYS.lines().next().expect("fixture non-empty");
    let truncated = &line[..line.len() - 10];
    assert!(matches!(
        parse(truncated),
        Err(ExtendedKeyError::NotBase58 | ExtendedKeyError::WrongLength { .. })
    ));
}

#[test]
fn a_single_altered_character_fails_the_checksum() {
    // base58check exists to catch exactly this. A decoder that skipped the checksum would
    // accept a mistyped key and derive addresses for a wallet nobody owns.
    let line = SLIP132_PUBKEYS.lines().next().expect("fixture non-empty");
    let mut altered = line.to_owned();
    let last = altered.pop().expect("non-empty");
    altered.push(if last == 'a' { 'b' } else { 'a' });

    assert!(
        matches!(parse(&altered), Err(ExtendedKeyError::NotBase58)),
        "a corrupted key must not decode"
    );
}

#[test]
fn input_that_is_not_a_key_at_all_is_refused() {
    for text in [
        "hello",
        "wpkh(something)",
        "1BvBMSEYstWetqTFn5Au4m4GFg7xJaNVN2",
        "0000000000000000000000000000000000000000000000000000000000000001",
    ] {
        let accepted = guard_input(text);
        // The last one is 64 hex characters and the guard refuses it as secret material
        // before this layer ever sees it, which is the correct order.
        if let Ok(accepted) = accepted {
            assert!(
                parse_extended_key(&accepted).is_err(),
                "{text} must not parse"
            );
        }
    }
}

#[test]
fn errors_never_contain_the_input() {
    // Same rule as the secret-material path: an error is a category, never a value.
    // An extended public key is not secret, but it is the user's entire wallet history,
    // and an error string is exactly how that reaches a log.
    let line = SLIP132_PUBKEYS.lines().next().expect("fixture non-empty");
    let mut altered = line.to_owned();
    altered.push('Z');

    let error = parse(&altered).expect_err("must fail");
    let rendered = format!("{error} {error:?}");

    // Any run of base58 long enough to be part of a key must not appear.
    for window_start in 0..line.len().saturating_sub(20) {
        let chunk = &line[window_start..window_start + 20];
        assert!(
            !rendered.contains(chunk),
            "error text reproduced part of the input"
        );
    }
}

#[test]
fn an_empty_input_is_refused_rather_than_treated_as_a_key() {
    let accepted = guard_input("").expect("empty input carries no secret material");
    assert!(parse_extended_key(&accepted).is_err());
}

#[test]
fn surrounding_whitespace_does_not_prevent_a_key_from_parsing() {
    // A pasted key routinely arrives with a trailing newline. Refusing that would send a
    // user to the "not recognised" screen for a key that is perfectly valid.
    let line = SLIP132_PUBKEYS.lines().next().expect("fixture non-empty");
    let padded = format!("  \n{line}\t \n");
    let key = parse(&padded).expect("whitespace-padded key must parse");
    assert_eq!(key.prefix(), "xpub");
}

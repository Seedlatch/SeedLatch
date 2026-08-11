//! Descriptor parsing, through the public API.
//!
//! The descriptors here are **constructed**, not known-answer: they are built around
//! published BIP-32 keys, but the surrounding expressions are ours. BIP-380 through BIP-386
//! publish descriptor vectors and vendoring them is worth doing; until then these test the
//! facts this module reports rather than conformance to the standard's examples.
//!
//! Testnet cases live in the module's unit tests, which can re-version a key to `tpub`.

use seedlatch::parse::descriptor::{parse_descriptor, DescriptorError, DescriptorShape};
use seedlatch::parse::extended_key::KeyNetwork;
use seedlatch::parse::guard_input;

const BIP32_XPUBS: &str = include_str!("fixtures/bip32-xpubs.txt");
const SLIP132_PUBKEYS: &str = include_str!("fixtures/slip132-pubkeys.txt");

/// Two distinct valid mainnet xpubs. Lines 1 and 2 of the BIP-32 fixture, both from
/// Test vector 1 and both confirmed valid.
fn xpubs() -> (&'static str, &'static str) {
    let mut lines = BIP32_XPUBS.lines().map(str::trim).filter(|l| !l.is_empty());
    (
        lines.next().expect("fixture has a first key"),
        lines.next().expect("fixture has a second key"),
    )
}

fn zpub() -> &'static str {
    SLIP132_PUBKEYS
        .lines()
        .map(str::trim)
        .find(|l| l.starts_with("zpub"))
        .expect("fixture holds a zpub")
}

fn facts(text: &str) -> Result<seedlatch::parse::descriptor::DescriptorFacts, DescriptorError> {
    let accepted = guard_input(text).expect("descriptor carries no secret material");
    parse_descriptor(&accepted).map(|parsed| parsed.facts().clone())
}

#[test]
fn a_native_segwit_single_key_descriptor_reports_its_shape() {
    let (a, _) = xpubs();
    let f = facts(&format!("wpkh({a}/0/*)")).expect("parses");

    assert_eq!(f.shape, DescriptorShape::Wpkh);
    assert_eq!(f.network, KeyNetwork::Mainnet);
    assert_eq!(f.key_count, 1);
    assert_eq!(f.wildcard_keys, 1);
    assert_eq!(
        f.threshold, None,
        "a single-key descriptor has no threshold"
    );
    assert_eq!(f.single_keys, 0);
}

#[test]
fn nested_segwit_is_distinguished_from_native() {
    // sh(wpkh(...)) and wpkh(...) produce different addresses from the same key. Reporting
    // them as one shape would mean checking a wallet the user does not have.
    let (a, _) = xpubs();
    assert_eq!(
        facts(&format!("sh(wpkh({a}/0/*))")).expect("parses").shape,
        DescriptorShape::ShWpkh
    );
    assert_eq!(
        facts(&format!("wpkh({a}/0/*)")).expect("parses").shape,
        DescriptorShape::Wpkh
    );
}

#[test]
fn legacy_and_taproot_shapes_are_recognised() {
    let (a, _) = xpubs();
    assert_eq!(
        facts(&format!("pkh({a}/0/*)")).expect("parses").shape,
        DescriptorShape::Pkh
    );
    assert_eq!(
        facts(&format!("tr({a}/0/*)")).expect("parses").shape,
        DescriptorShape::Tr
    );
}

#[test]
fn a_sorted_multi_reports_both_k_and_n() {
    let (a, b) = xpubs();
    let f = facts(&format!("wsh(sortedmulti(2,{a}/0/*,{b}/0/*))")).expect("parses");

    assert_eq!(f.shape, DescriptorShape::WshSortedMulti);
    assert!(f.shape.is_sorted_multi());
    assert_eq!(f.threshold, Some(2), "the k of k-of-n");
    assert_eq!(f.key_count, 2, "the n of k-of-n");
    assert_eq!(f.wildcard_keys, 2);
}

#[test]
fn a_nested_sorted_multi_still_reports_its_threshold() {
    // sh(wsh(sortedmulti(...))) is the common legacy-compatible multisig form. Reading the
    // threshold only from the outer layer would return None for exactly the descriptors
    // where the threshold matters most.
    let (a, b) = xpubs();
    let f = facts(&format!("sh(wsh(sortedmulti(2,{a}/0/*,{b}/0/*)))")).expect("parses");

    assert_eq!(f.shape, DescriptorShape::ShWshSortedMulti);
    assert_eq!(f.threshold, Some(2));
    assert_eq!(f.key_count, 2);
}

#[test]
fn a_general_miniscript_threshold_is_reported_as_unknown_not_as_one() {
    // wsh(multi(...)) is not a sortedmulti, and recovering its threshold means walking the
    // AST. None is honest; 1 would be wrong, and 1 is the answer that would let a 2-of-3
    // be reported as a single point of failure.
    let (a, b) = xpubs();
    let f = facts(&format!("wsh(multi(2,{a}/0/*,{b}/0/*))")).expect("parses");

    assert_eq!(f.shape, DescriptorShape::Wsh);
    assert_eq!(f.threshold, None);
    assert_eq!(f.key_count, 2, "keys are still counted");
}

#[test]
fn key_origin_information_is_counted_when_present() {
    let (a, _) = xpubs();
    let with_origin = facts(&format!("wpkh([d34db33f/84h/0h/0h]{a}/0/*)")).expect("parses");
    let without = facts(&format!("wpkh({a}/0/*)")).expect("parses");

    assert_eq!(with_origin.keys_with_origin, 1);
    assert_eq!(without.keys_with_origin, 0, "absence is not an error");
}

#[test]
fn a_descriptor_without_a_wildcard_reports_none() {
    let (a, _) = xpubs();
    let f = facts(&format!("wpkh({a})")).expect("parses");
    assert_eq!(f.wildcard_keys, 0);
    assert_eq!(f.key_count, 1);
}

#[test]
fn a_slip132_key_inside_a_descriptor_gets_its_own_error() {
    // Users paste these. BIP-380 key expressions are BIP-32 serialised, so a zpub is not
    // valid inside a descriptor even though this tool accepts one on its own — and "that is
    // not a descriptor" would be a useless thing to tell someone holding a valid wallet.
    let f = facts(&format!("wpkh({}/0/*)", zpub()));
    assert_eq!(f, Err(DescriptorError::Slip132KeyInDescriptor));
}

#[test]
fn input_that_is_not_a_descriptor_is_refused() {
    for text in ["hello", "wpkh(", "wpkh()", "not a descriptor at all", ""] {
        assert_eq!(
            facts(text),
            Err(DescriptorError::NotADescriptor),
            "{text:?} must not parse"
        );
    }
}

#[test]
fn a_bare_extended_key_is_not_a_descriptor() {
    // It is valid input to the tool, but through the other door. Reporting it as a
    // descriptor failure is correct here; the caller decides which parser to try.
    let (a, _) = xpubs();
    assert_eq!(facts(a), Err(DescriptorError::NotADescriptor));
}

#[test]
fn a_valid_checksum_is_accepted_and_a_wrong_one_is_not() {
    // BIP-380 checksums are optional in what we accept but must be correct when present.
    // Accepting a wrong checksum would waste the one integrity check the format offers.
    let (a, _) = xpubs();
    let plain = format!("wpkh({a}/0/*)");
    assert!(facts(&plain).is_ok(), "checksum is optional");

    assert_eq!(
        facts(&format!("{plain}#aaaaaaaa")),
        Err(DescriptorError::NotADescriptor),
        "a wrong checksum must not be ignored"
    );
}

#[test]
fn errors_never_contain_the_input() {
    let (a, _) = xpubs();
    let error = facts(&format!("wpkh({a}/0/*)#aaaaaaaa")).expect_err("wrong checksum");
    let rendered = format!("{error} {error:?}");

    let chunk = a.get(10..40).expect("key is long enough");
    assert!(
        !rendered.contains(chunk),
        "error reproduced part of the key"
    );
}

#[test]
fn debug_does_not_reproduce_the_descriptor() {
    // The facts are safe to print — shapes and counts. The descriptor is not: it is every
    // key and every path the user owns.
    let (a, _) = xpubs();
    let text = format!("wpkh({a}/0/*)");
    let accepted = guard_input(&text).expect("no secret material");
    let parsed = parse_descriptor(&accepted).expect("parses");

    let rendered = format!("{parsed:?}");
    assert!(rendered.contains("redacted"));
    assert!(rendered.contains("Wpkh"), "facts should still be visible");

    let chunk = a.get(10..40).expect("key is long enough");
    assert!(!rendered.contains(chunk), "Debug reproduced the key");
}

//! The single entry point, end to end.

use seedlatch::analysis::{analyse, Analysis, Unreadable};
use seedlatch::parse::descriptor::{DescriptorError, DescriptorShape};
use seedlatch::parse::extended_key::{ExtendedKeyError, KeyNetwork, ScriptType};
use seedlatch::parse::{Refusal, SecretMaterial};

const BIP32_XPUBS: &str = include_str!("fixtures/bip32-xpubs.txt");
const SLIP132_PUBKEYS: &str = include_str!("fixtures/slip132-pubkeys.txt");
const MNEMONICS: &str = include_str!("fixtures/bip39-english-mnemonics.txt");

fn xpub() -> &'static str {
    BIP32_XPUBS.lines().map(str::trim).next().expect("fixture")
}

fn key_with(prefix: &str) -> &'static str {
    SLIP132_PUBKEYS
        .lines()
        .map(str::trim)
        .find(|l| l.starts_with(prefix))
        .expect("fixture holds this prefix")
}

#[test]
fn a_pasted_seed_phrase_is_refused_before_anything_is_parsed() {
    let mnemonic = MNEMONICS.lines().next().expect("fixture");
    match analyse(mnemonic) {
        Analysis::Refused(Refusal::SecretMaterial(found)) => {
            assert!(found.contains(SecretMaterial::Bip39Mnemonic));
        }
        other => panic!("expected a secret-material refusal, got {other:?}"),
    }
}

#[test]
fn an_oversized_input_is_refused_without_being_examined() {
    let huge = "a".repeat(200 * 1024);
    match analyse(&huge) {
        Analysis::Refused(Refusal::TooLarge {
            limit_bytes,
            actual_bytes,
        }) => {
            assert_eq!(limit_bytes, 100 * 1024);
            assert_eq!(actual_bytes, 200 * 1024);
        }
        other => panic!("expected a size refusal, got {other:?}"),
    }
}

#[test]
fn a_bare_xpub_is_reported_as_ambiguous_so_the_frontend_asks() {
    match analyse(xpub()) {
        Analysis::Key(facts) => {
            assert_eq!(facts.prefix, "xpub");
            assert_eq!(facts.network, KeyNetwork::Mainnet);
            assert_eq!(facts.script_type, ScriptType::P2pkhOrP2sh);
            assert!(
                facts.script_type_ambiguous,
                "xpub does not say which script type; the user must"
            );
        }
        other => panic!("expected a key, got {other:?}"),
    }
}

#[test]
fn a_bare_zpub_is_not_ambiguous_and_must_not_be_asked_about() {
    match analyse(key_with("zpub")) {
        Analysis::Key(facts) => {
            assert_eq!(facts.prefix, "zpub");
            assert_eq!(facts.script_type, ScriptType::P2wpkh);
            assert!(
                !facts.script_type_ambiguous,
                "zpub states its script type; asking would invent ambiguity"
            );
        }
        other => panic!("expected a key, got {other:?}"),
    }
}

#[test]
fn a_descriptor_is_never_ambiguous() {
    // The corresponding property for descriptors: there is no ambiguity flag to set,
    // because the shape is the answer.
    let facts = match analyse(&format!("wpkh({}/0/*)", xpub())) {
        Analysis::Descriptor(parsed) => parsed.facts().clone(),
        other => panic!("expected a descriptor, got {other:?}"),
    };

    assert_eq!(facts.shape, DescriptorShape::Wpkh);
    assert_eq!(facts.network, KeyNetwork::Mainnet);
    assert_eq!(facts.key_count, 1);
    assert_eq!(facts.wildcard_keys, 1);
}

#[test]
fn a_broken_descriptor_is_reported_as_a_descriptor_problem() {
    // The routing test. Falling back between parsers would tell someone who mistyped a
    // descriptor that it is not a valid extended key, which is true and useless.
    match analyse(&format!("wpkh({}/0/*)#aaaaaaaa", xpub())) {
        Analysis::Unreadable(Unreadable::Descriptor(_)) => {}
        other => panic!("expected a descriptor failure, got {other:?}"),
    }

    match analyse("wpkh(not-a-key)") {
        Analysis::Unreadable(Unreadable::Descriptor(DescriptorError::NotADescriptor)) => {}
        other => panic!("expected a descriptor failure, got {other:?}"),
    }
}

#[test]
fn a_broken_key_is_reported_as_a_key_problem() {
    let mut altered = xpub().to_owned();
    altered.push('Z');

    match analyse(&altered) {
        Analysis::Unreadable(Unreadable::Key(ExtendedKeyError::NotBase58)) => {}
        other => panic!("expected a key failure, got {other:?}"),
    }
}

#[test]
fn a_slip132_key_inside_a_descriptor_keeps_its_specific_error() {
    match analyse(&format!("wpkh({}/0/*)", key_with("zpub"))) {
        Analysis::Unreadable(Unreadable::Descriptor(DescriptorError::Slip132KeyInDescriptor)) => {}
        other => panic!("expected the SLIP-132 descriptor error, got {other:?}"),
    }
}

#[test]
fn ordinary_prose_is_reported_as_an_unreadable_key_not_as_secret_material() {
    // Short prose does not cross the mnemonic thresholds, so it reaches the parser and
    // fails there. That is the right place for it to fail.
    match analyse("this is just a sentence") {
        Analysis::Unreadable(Unreadable::Key(_)) => {}
        other => panic!("expected an unreadable key, got {other:?}"),
    }
}

#[test]
fn the_outcome_never_reproduces_the_input() {
    // Every variant, rendered through Debug, must not carry the value. This is the type
    // that crosses into the browser boundary, so it is the last place a wallet could leak
    // into a log or an error report.
    let key = xpub();
    let descriptor = format!("wpkh({key}/0/*)");
    let chunk = key.get(10..40).expect("long enough");

    for input in [key, descriptor.as_str(), "not a key", ""] {
        let rendered = format!("{:?}", analyse(input));
        assert!(
            !rendered.contains(chunk),
            "analysis of {:?} reproduced the key",
            &input[..input.len().min(12)]
        );
    }
}

#[test]
fn whitespace_around_either_form_is_tolerated() {
    assert!(matches!(
        analyse(&format!("  {}\n", xpub())),
        Analysis::Key(_)
    ));
    assert!(matches!(
        analyse(&format!("\n wpkh({}/0/*) \n", xpub())),
        Analysis::Descriptor(_)
    ));
}

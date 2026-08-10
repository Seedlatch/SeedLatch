//! Secret-material rejection — the highest-risk path in the product.
//!
//! Written before the implementation, per CLAUDE.md ("Tests first in `parse/`").
//!
//! # Why there is no real key material in this file
//!
//! Both detectors are **shape-based**: they never base58-decode, never verify a BIP-39
//! checksum, never derive anything. Verifying a checksum would mean a mistyped or
//! truncated seed fails the check and then gets *processed* — a false negative, which is
//! the failure that costs coins. So every private-key fixture below is deliberately
//! checksum-invalid: correct shape, not a usable key. Nothing in this repository is or
//! ever should be a real secret.
//!
//! Public fixtures (`fixtures/bip32-xpubs.txt`, `fixtures/bip39-english-mnemonics.txt`)
//! are genuine upstream vectors. See `data/PROVENANCE.md`.

use seedlatch::parse::{guard_input, scan_for_secret_material, Refusal, SecretMaterial};

const OFFICIAL_MNEMONICS: &str = include_str!("fixtures/bip39-english-mnemonics.txt");
const BIP32_XPUBS: &str = include_str!("fixtures/bip32-xpubs.txt");

fn mnemonics() -> Vec<&'static str> {
    OFFICIAL_MNEMONICS
        .lines()
        .filter(|l| !l.is_empty())
        .collect()
}

fn xpubs() -> Vec<&'static str> {
    BIP32_XPUBS.lines().filter(|l| !l.is_empty()).collect()
}

/// Asserts the input is rejected, and rejected for the stated reason.
#[track_caller]
fn assert_rejected(input: &str, expected: SecretMaterial) {
    let found = scan_for_secret_material(input)
        .unwrap_or_else(|| panic!("FAILED OPEN: nothing detected in a {expected:?} case"));
    assert!(
        found.contains(expected),
        "detected {:?}, expected to include {expected:?}",
        found.categories()
    );
    assert!(
        guard_input(input).is_err(),
        "guard_input accepted rejected material"
    );
}

#[track_caller]
fn assert_accepted(input: &str) {
    if let Some(found) = scan_for_secret_material(input) {
        panic!(
            "false positive: {:?} on input of {} bytes",
            found.categories(),
            input.len()
        );
    }
    assert!(guard_input(input).is_ok());
}

// ---------------------------------------------------------------------------
// Detector A — BIP-39 mnemonics
// ---------------------------------------------------------------------------

#[test]
fn official_bip39_vectors_are_all_detected() {
    let all = mnemonics();
    assert_eq!(all.len(), 24, "fixture changed unexpectedly");
    for m in all {
        assert_rejected(m, SecretMaterial::Bip39Mnemonic);
    }
}

#[test]
fn every_standard_word_count_is_detected() {
    // 12/18/24 come from the official vectors; 15/21 are constructed from wordlist
    // entries because upstream publishes no vectors at those lengths.
    let words: Vec<&str> = seedlatch::parse::wordlist::words().to_vec();
    for count in [12usize, 15, 18, 21, 24] {
        let phrase = words[..count].join(" ");
        assert_rejected(&phrase, SecretMaterial::Bip39Mnemonic);
    }
}

#[test]
fn detected_regardless_of_case() {
    for m in mnemonics() {
        assert_rejected(&m.to_uppercase(), SecretMaterial::Bip39Mnemonic);
        let mixed: String = m
            .chars()
            .enumerate()
            .map(|(i, c)| {
                if i % 2 == 0 {
                    c.to_ascii_uppercase()
                } else {
                    c
                }
            })
            .collect();
        assert_rejected(&mixed, SecretMaterial::Bip39Mnemonic);
    }
}

#[test]
fn detected_regardless_of_separator() {
    let m = mnemonics()[0];
    let words: Vec<&str> = m.split(' ').collect();
    for joiner in [
        "\n",
        "\r\n",
        "\t",
        ", ",
        ",",
        ";",
        "  ",
        " \u{00a0}",
        "\n\n",
    ] {
        assert_rejected(&words.join(joiner), SecretMaterial::Bip39Mnemonic);
    }
}

#[test]
fn detected_when_numbered_or_surrounded_by_prose() {
    let m = mnemonics()[0];
    let numbered: String = m
        .split(' ')
        .enumerate()
        .map(|(i, w)| format!("{}. {w}", i + 1))
        .collect::<Vec<_>>()
        .join("  ");
    assert_rejected(&numbered, SecretMaterial::Bip39Mnemonic);
    assert_rejected(
        &format!("here is my seed phrase please help me: {m}"),
        SecretMaterial::Bip39Mnemonic,
    );
    assert_rejected(
        &format!("{m}\n\n-- sent from my phone"),
        SecretMaterial::Bip39Mnemonic,
    );
}

#[test]
fn detected_when_one_word_is_mistyped() {
    // A seed with a typo fails its BIP-39 checksum but is still secret material.
    // This is exactly why detection must not verify checksums.
    for m in mnemonics().iter().take(6) {
        let mangled: Vec<String> = m
            .split(' ')
            .enumerate()
            .map(|(i, w)| {
                if i == 5 {
                    format!("{w}x")
                } else {
                    w.to_string()
                }
            })
            .collect();
        assert_rejected(&mangled.join(" "), SecretMaterial::Bip39Mnemonic);
    }
}

#[test]
fn detected_when_truncated_to_four_letters() {
    // BIP-39 words are uniquely identified by their first four letters, and several
    // devices accept 4-letter entry, so users write seeds down that way.
    for m in mnemonics().iter().take(6) {
        let truncated: Vec<&str> = m.split(' ').map(|w| &w[..w.len().min(4)]).collect();
        assert_rejected(&truncated.join(" "), SecretMaterial::Bip39Mnemonic);
    }
}

#[test]
fn detected_when_zero_width_characters_are_interleaved() {
    // Copying from some web pages injects these; they must not break tokenisation.
    let m = mnemonics()[0];
    for zw in ['\u{200b}', '\u{200c}', '\u{200d}', '\u{feff}', '\u{2060}'] {
        let poisoned: String = m.split(' ').collect::<Vec<_>>().join(&format!("{zw} "));
        assert_rejected(&poisoned, SecretMaterial::Bip39Mnemonic);
    }
}

#[test]
fn detected_when_only_part_of_the_phrase_was_pasted() {
    let m = mnemonics()[1];
    let words: Vec<&str> = m.split(' ').collect();
    assert_rejected(&words[..8].join(" "), SecretMaterial::Bip39Mnemonic);
}

// ---------------------------------------------------------------------------
// Detector A — negatives. A false positive here is safe; it is still a bug.
// ---------------------------------------------------------------------------

#[test]
fn genuine_xpubs_are_not_mistaken_for_mnemonics() {
    for x in xpubs() {
        assert_accepted(x);
    }
}

#[test]
fn descriptors_are_accepted() {
    let xpub = xpubs()[0];
    for d in [
        format!("wpkh({xpub}/0/*)"),
        format!("pkh([d34db33f/44h/0h/0h]{xpub}/0/*)"),
        format!("sh(wpkh({xpub}/0/*))"),
        format!("tr({xpub}/0/*)"),
        format!("wsh(sortedmulti(2,{}/0/*,{}/0/*))", xpubs()[1], xpubs()[2]),
        format!(
            "wsh(multi(2,{}/0/*,{}/0/*,{}/0/*))",
            xpubs()[3],
            xpubs()[4],
            xpubs()[5]
        ),
    ] {
        assert_accepted(&d);
    }
}

#[test]
fn english_prose_is_not_mistaken_for_a_mnemonic() {
    for text in [
        "I am trying to figure out whether my hardware wallet is affected by the entropy issue that was disclosed last week.",
        "The quick brown fox jumps over the lazy dog while the cat sleeps near the warm fire in the corner of the room.",
        "Please review the attached account balance report and confirm the total amount before we process the final payment today.",
        "my wallet uses a passphrase and I have three devices from two different vendors with a two of three multisig setup",
        "ability able about above absent absorb abstract",
    ] {
        assert_accepted(text);
    }
}

#[test]
fn short_and_empty_inputs_are_accepted() {
    for text in [
        "",
        "   ",
        "\n\t\n",
        "abandon",
        "abandon ability",
        "bc1qar0srrr7xfkvy5l643lydnw9re59gtzzwf5mdq",
    ] {
        assert_accepted(text);
    }
}

#[test]
fn wallet_export_json_is_accepted() {
    let xpub = xpubs()[0];
    let json = format!(
        r#"{{"descriptor":"wpkh([d34db33f/84h/0h/0h]{xpub}/0/*)","label":"main account cold storage savings"}}"#
    );
    assert_accepted(&json);
}

// ---------------------------------------------------------------------------
// Detector B — extended private keys
// ---------------------------------------------------------------------------

/// Shape-only, checksum-invalid. Never a usable key.
fn fake_xprv(prefix: &str) -> String {
    format!("{prefix}9zHkzFBQRRJRxCzTmxpNfBSGgeugmTt1TzM8DsAt3cctc78Ke1jkeLdYS8vqBhTX9dnLXBRRRnJHcHRhWCbXGGmpZ")
}

#[test]
fn extended_private_key_prefixes_are_detected() {
    // xprv/yprv/zprv/tprv are named in CLAUDE.md. uprv/vprv are the SLIP-132 testnet
    // multisig equivalents — a strict superset, in the fail-closed direction.
    for prefix in ["xprv", "yprv", "zprv", "tprv", "uprv", "vprv"] {
        assert_rejected(&fake_xprv(prefix), SecretMaterial::ExtendedPrivateKey);
    }
}

#[test]
fn extended_private_key_prefixes_are_detected_case_insensitively() {
    // SLIP-132 genuinely uses capitals (Yprv, Zprv, Uprv, Vprv for multisig), and a
    // panicking user may paste with mangled case. Matching case-insensitively costs
    // nothing and closes the gap.
    for prefix in ["XPRV", "Yprv", "Zprv", "TPrv", "xPRV", "vPrV"] {
        assert_rejected(&fake_xprv(prefix), SecretMaterial::ExtendedPrivateKey);
    }
}

#[test]
fn extended_private_key_inside_an_otherwise_valid_descriptor_is_detected() {
    // Explicitly called out in CLAUDE.md: "including inside an otherwise-valid descriptor".
    let key = fake_xprv("xprv");
    for d in [
        format!("wpkh({key}/0/*)"),
        format!("pkh([d34db33f/44h/0h/0h]{key}/0/*)"),
        format!("wsh(sortedmulti(2,{}/0/*,{key}/0/*))", xpubs()[0]),
        format!("wpkh({key}/0/*)#cjd0ct0v"),
    ] {
        assert_rejected(&d, SecretMaterial::ExtendedPrivateKey);
    }
}

#[test]
fn extended_private_key_detected_anywhere_in_the_input() {
    let key = fake_xprv("zprv");
    assert_rejected(
        &format!("my backup is {key} please check it"),
        SecretMaterial::ExtendedPrivateKey,
    );
    assert_rejected(
        &format!("\n\n\t{key}\n"),
        SecretMaterial::ExtendedPrivateKey,
    );
}

// ---------------------------------------------------------------------------
// Detector B — WIF
// ---------------------------------------------------------------------------

/// Shape-only WIF: correct leading byte and length, deliberately wrong checksum.
fn fake_wif(lead: char, len: usize) -> String {
    let filler = "abcdefghijkmnopqrstuvwxyzABCDEFGHJKLMNPQRSTUVWXYZ123456789";
    let mut s = String::from(lead);
    s.extend(filler.chars().cycle().take(len - 1));
    s
}

#[test]
fn wif_shapes_are_detected() {
    // Mainnet uncompressed '5' (51 chars), mainnet compressed 'K'/'L' (52),
    // testnet uncompressed '9' (51), testnet compressed 'c' (52).
    for (lead, len) in [('5', 51), ('K', 52), ('L', 52), ('9', 51), ('c', 52)] {
        assert_rejected(&fake_wif(lead, len), SecretMaterial::WifPrivateKey);
    }
}

#[test]
fn wif_inside_a_descriptor_is_detected() {
    let wif = fake_wif('L', 52);
    assert_rejected(&format!("wpkh({wif})"), SecretMaterial::WifPrivateKey);
    assert_rejected(
        &format!("sh(wpkh({wif}))#00000000"),
        SecretMaterial::WifPrivateKey,
    );
    assert_rejected(
        &format!("wsh(multi(1,{wif}))"),
        SecretMaterial::WifPrivateKey,
    );
}

#[test]
fn addresses_and_xpubs_are_not_mistaken_for_wif() {
    for text in [
        "1BvBMSEYstWetqTFn5Au4m4GFg7xJaNVN2",
        "3J98t1WpEZ73CNmQviecrnyiWrnqRhWNLy",
        "bc1qar0srrr7xfkvy5l643lydnw9re59gtzzwf5mdq",
        "bc1p5d7rjq7g6rdk2yhzks9smlaqtedr4dekq08ge8ztwac72sfr9rusxg3297",
    ] {
        assert_accepted(text);
    }
    for x in xpubs() {
        assert_accepted(x);
    }
}

// ---------------------------------------------------------------------------
// Detector B — raw hex
// ---------------------------------------------------------------------------

#[test]
fn sixty_four_character_hex_is_detected() {
    let h = "deadbeef".repeat(8);
    assert_eq!(h.len(), 64);
    assert_rejected(&h, SecretMaterial::RawHexPrivateKey);
    assert_rejected(&h.to_uppercase(), SecretMaterial::RawHexPrivateKey);
    assert_rejected(&format!("my key is {h}"), SecretMaterial::RawHexPrivateKey);
    // Including where it would otherwise look like a `tr()` x-only public key: 32 bytes
    // of hex is indistinguishable from a private key, so v0 refuses rather than guesses.
    assert_rejected(&format!("tr({h})"), SecretMaterial::RawHexPrivateKey);
}

#[test]
fn hex_of_other_lengths_is_not_flagged() {
    for h in [
        "d34db33f",       // key-origin fingerprint
        &"ab".repeat(20), // 40 chars — hash160
        &"ab".repeat(33), // 66 chars — compressed public key
        &"ab".repeat(31), // 62 chars
        &"ab".repeat(64), // 128 chars
    ] {
        assert_accepted(h);
    }
}

#[test]
fn descriptors_with_key_origin_fingerprints_are_accepted() {
    let xpub = xpubs()[0];
    assert_accepted(&format!("wpkh([d34db33f/84h/0h/0h]{xpub}/0/*)#cjd0ct0v"));
    assert_accepted(&format!("wpkh([00000000/84'/0'/0']{xpub}/0/*)"));
}

// ---------------------------------------------------------------------------
// Reporting discipline
// ---------------------------------------------------------------------------

#[test]
fn multiple_categories_are_all_reported() {
    let m = mnemonics()[0];
    let key = fake_xprv("xprv");
    let found = scan_for_secret_material(&format!("{m}\n{key}")).expect("must detect");
    assert!(found.contains(SecretMaterial::Bip39Mnemonic));
    assert!(found.contains(SecretMaterial::ExtendedPrivateKey));
}

#[test]
fn nothing_ever_echoes_the_input() {
    // CLAUDE.md: "Never echo the value, never include it in an error, panic message, or
    // console output." Checked against Display *and* Debug, since Debug reaches logs.
    let key = fake_xprv("xprv");
    let wif = fake_wif('L', 52);
    let hex = "deadbeef".repeat(8);
    let cases = [
        mnemonics()[0].to_string(),
        key.clone(),
        wif.clone(),
        hex.clone(),
    ];

    for input in cases {
        let found = scan_for_secret_material(&input).expect("must detect");
        let err = guard_input(&input).expect_err("must reject");
        let rendered = format!("{found}|{found:?}|{err}|{err:?}");

        // No whole-value leak.
        assert!(
            !rendered.contains(&input),
            "rendered output contains the raw input"
        );
        // No fragment leak either: check every substring of length 8 from the input.
        let bytes: Vec<char> = input.chars().collect();
        for window in bytes.windows(8) {
            let frag: String = window.iter().collect();
            if frag.trim().len() < 8 {
                continue;
            }
            assert!(
                !rendered.contains(&frag),
                "rendered output leaks an 8-character fragment of the input"
            );
        }
    }
}

#[test]
fn accepted_input_round_trips_unchanged() {
    let xpub = xpubs()[0];
    let d = format!("wpkh([d34db33f/84h/0h/0h]{xpub}/0/*)#cjd0ct0v");
    let accepted = guard_input(&d).expect("descriptor must be accepted");
    assert_eq!(accepted.as_str(), d);
}

#[test]
fn detector_never_panics_on_arbitrary_input() {
    // Library code reachable from user input must not panic (CLAUDE.md, coding rules).
    // Multi-byte and lone-surrogate-adjacent input is the usual way slicing bugs surface.
    for input in [
        "\u{1f4a9}".repeat(50),
        "日本語のテキストです".to_string(),
        "\0\0\0".to_string(),
        "é".repeat(200),
        "a\u{0301}".repeat(100),
        "🔑".repeat(12),
        (0u8..=127).map(|b| b as char).collect::<String>(),
        "abandon\u{0301} ability able about above absent absorb abstract absurd abuse access accident".to_string(),
    ] {
        let _ = scan_for_secret_material(&input);
        let _ = guard_input(&input);
    }
}

// ---------------------------------------------------------------------------
// Input size bound
// ---------------------------------------------------------------------------

#[test]
fn input_exactly_at_the_limit_is_still_examined() {
    // Off-by-one on a security bound is worth a test of its own.
    let at_limit = "a".repeat(seedlatch::parse::MAX_INPUT_BYTES);
    assert_eq!(at_limit.len(), seedlatch::parse::MAX_INPUT_BYTES);
    assert!(guard_input(&at_limit).is_ok());
}

#[test]
fn input_one_byte_over_the_limit_is_refused() {
    let over = "a".repeat(seedlatch::parse::MAX_INPUT_BYTES + 1);
    match guard_input(&over) {
        Err(Refusal::TooLarge {
            limit_bytes,
            actual_bytes,
        }) => {
            assert_eq!(limit_bytes, seedlatch::parse::MAX_INPUT_BYTES);
            assert_eq!(actual_bytes, over.len());
        }
        other => panic!("expected TooLarge, got {other:?}"),
    }
}

#[test]
fn oversized_input_is_refused_as_too_large_even_when_it_contains_a_seed() {
    // Documents the deliberate consequence of checking size first: the input is never
    // examined, so we cannot say a secret was in it — and the copy must not imply we can.
    // Refusing is still the fail-closed outcome; the input is not processed either way.
    let padding = "a".repeat(seedlatch::parse::MAX_INPUT_BYTES);
    let with_seed = format!("{padding}\n{}", mnemonics()[0]);

    match guard_input(&with_seed) {
        Err(Refusal::TooLarge { .. }) => {}
        other => panic!("expected TooLarge, got {other:?}"),
    }
}

#[test]
fn size_refusal_never_echoes_the_input() {
    let over = format!(
        "{}{}",
        "seedlatchmarker",
        "a".repeat(seedlatch::parse::MAX_INPUT_BYTES)
    );
    let err = guard_input(&over).expect_err("must refuse");
    let rendered = format!("{err}|{err:?}");
    assert!(!rendered.contains("seedlatchmarker"));
}

#[test]
fn a_realistic_worst_case_descriptor_is_nowhere_near_the_limit() {
    // The bound has to be generous enough that no real wallet identifier trips it.
    // A 20-of-20 multisig with full key origins is the largest thing anyone would paste.
    let key = xpubs()[0];
    let leg = format!("[d34db33f/48h/0h/0h/2h]{key}/0/*");
    let descriptor = format!(
        "wsh(sortedmulti(20,{}))#00000000",
        std::iter::repeat_n(leg, 20).collect::<Vec<_>>().join(",")
    );
    assert!(
        descriptor.len() * 10 < seedlatch::parse::MAX_INPUT_BYTES,
        "worst-case descriptor is {} bytes against a {} byte limit — too close",
        descriptor.len(),
        seedlatch::parse::MAX_INPUT_BYTES
    );
    assert_accepted(&descriptor);
}

#[test]
fn very_large_input_is_handled_without_stalling() {
    // Paste bombs must not take the tab down.
    let big = "abandon ".repeat(50_000);
    let _ = scan_for_secret_material(&big);
    let junk = "x".repeat(1_000_000);
    let _ = scan_for_secret_material(&junk);
}

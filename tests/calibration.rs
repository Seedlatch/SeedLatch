//! Threshold calibration, kept as a test so it cannot rot.
//!
//! Run `cargo test --test calibration -- --nocapture` to see the distribution rather than
//! the verdict. The printed table is the artefact an independent reviewer should attack:
//! add samples to `fixtures/negative-corpus.txt` and see how close they come to the line.
//!
//! # The finding this file exists to record
//!
//! 108 of 153 words a wallet questionnaire would plausibly use are in the BIP-39 English
//! wordlist — 71%. It is a list of ordinary English nouns and verbs, which is the exact
//! register such answers are written in.
//!
//! An earlier version of this comment claimed ordinary sentences were safe by a wide
//! margin, on the grounds that the function words holding them together are absent from
//! the wordlist. **That claim was wrong** and is kept here as a warning about inferring a
//! distribution from two dozen hand-written samples. `you`, `have`, `make`, `sure`, `some`,
//! `them` and `than` are all BIP-39 words. Scanning 658,092 tokens of public-domain novels
//! found runs of 8, 9 and 10 in ordinary prose, at 1.22 occurrences per 100,000 tokens —
//! about 1 in 4,000 for a realistic 20-token paste. Exact matching alone accounts for 0.91
//! of that 1.22, so shorthand matching is not the cause and tightening it would not help.
//! The verbatim counterexamples are in the corpus as `prose-long-run`.
//!
//! Terse note-style text is worse, and closes off the obvious fix entirely:
//!
//! ```text
//! home safe, office safe, deposit box, metal plate, paper copy, spare device
//! ```
//!
//! Twelve tokens, twelve wordlist words, run 12, density 1.00 — identical to a twelve-word
//! seed phrase in every dimension measured here. Raising the run trigger above 12 would
//! blind the detector to every twelve-word mnemonic, so no threshold separates them. That
//! is asserted in [`a_keyword_list_is_numerically_identical_to_a_seed_phrase`] so it cannot
//! be quietly re-litigated.
//!
//! Hence [`SECRET_INPUT_CATEGORIES`]: the categories asserted clean are the ones that can
//! plausibly reach the descriptor field, and those assertions are a regression bound on
//! *these samples*, not a claim about English. `questionnaire-terse`, `keyword-list` and
//! `prose-long-run` are measured and reported rather than asserted. The resolutions —
//! structured questionnaire controls, and conditional interstitial wording for the
//! descriptor field — are product decisions recorded in `spec.md` §3 and
//! `docs/security-model.md` §3.

use std::collections::BTreeMap;

use seedlatch::parse::{mnemonic_signals, scan_for_secret_material};

const CORPUS: &str = include_str!("fixtures/negative-corpus.txt");
const MNEMONICS: &str = include_str!("fixtures/bip39-english-mnemonics.txt");

/// Categories that must never produce a detection. These are the inputs that can plausibly
/// arrive in the descriptor field, which is the only free-text field the design permits.
const SECRET_INPUT_CATEGORIES: [&str; 7] = [
    "descriptor",
    "address",
    "questionnaire-prose",
    "support",
    "prose",
    "json",
    "near-miss",
];

fn corpus() -> Vec<(&'static str, &'static str)> {
    CORPUS
        .lines()
        .filter(|line| !line.trim().is_empty() && !line.starts_with('#'))
        .filter_map(|line| line.split_once('\t'))
        .map(|(category, text)| (category.trim(), text.trim()))
        .collect()
}

fn mnemonics() -> Vec<&'static str> {
    MNEMONICS.lines().filter(|l| !l.is_empty()).collect()
}

/// Categories that are measured and reported rather than asserted, because they contain
/// samples that legitimately fire. Listed explicitly so the set of *unasserted* samples
/// stays visible rather than growing by accident.
const MEASURED_ONLY_CATEGORIES: [&str; 3] =
    ["questionnaire-terse", "keyword-list", "prose-long-run"];

#[test]
fn corpus_is_well_formed() {
    let samples = corpus();
    assert!(
        samples.len() >= 80,
        "corpus shrank: {} samples",
        samples.len()
    );

    let categories: BTreeMap<&str, usize> =
        samples.iter().fold(BTreeMap::new(), |mut acc, (cat, _)| {
            *acc.entry(*cat).or_default() += 1;
            acc
        });

    for required in SECRET_INPUT_CATEGORIES {
        assert!(
            categories.contains_key(required),
            "corpus is missing category {required:?}"
        );
    }
    assert!(
        categories.get("questionnaire-terse").copied().unwrap_or(0) >= 40,
        "the terse block is the whole point of this corpus; keep it large"
    );

    // Without this, a mistyped category — `near_miss` for `near-miss` — silently drops a
    // sample out of every assertion in this file. It stays in the corpus, it looks
    // checked, and nothing checks it. A corpus whose samples can go quietly unasserted is
    // worse than a smaller one, because it reports confidence it has not earned.
    for (category, text) in &samples {
        assert!(
            SECRET_INPUT_CATEGORIES.contains(category)
                || MEASURED_ONLY_CATEGORIES.contains(category),
            "unknown corpus category {category:?} — sample would be silently unasserted: {:?}",
            text.chars().take(40).collect::<String>()
        );
    }
}

#[test]
fn nothing_reaching_the_descriptor_field_is_flagged() {
    for (category, text) in corpus() {
        if !SECRET_INPUT_CATEGORIES.contains(&category) {
            continue;
        }
        if let Some(found) = scan_for_secret_material(text) {
            let signals = mnemonic_signals(text);
            panic!(
                "false positive in category {category:?}: {:?}\n  \
                 run={} matched={}/{} density={:.2}\n  sample: {text:?}",
                found.categories(),
                signals.longest_run(),
                signals.exact_matches.max(signals.shorthand_matches),
                signals.total_tokens,
                signals.density(),
            );
        }
    }
}

#[test]
fn corpus_prose_margin_does_not_erode() {
    // A regression bound on *these samples*, not a claim about English in general.
    //
    // The general claim is false, and `prose-long-run` in the corpus holds the
    // counterexamples: scanning 658,092 tokens of public-domain novels found runs of 8, 9
    // and 10 consecutive wordlist words in ordinary prose, at a rate of 1.22 per 100,000
    // tokens. Exact matching alone accounts for 0.91 of those, so shorthand matching is
    // not the cause and tightening it would not help.
    //
    // What this test does is stop the margin on the curated samples getting *worse*
    // through a tokenizer or wordlist change.
    let worst = corpus()
        .into_iter()
        .filter(|(cat, _)| {
            matches!(
                *cat,
                "prose" | "questionnaire-prose" | "support" | "near-miss"
            )
        })
        .map(|(_, text)| mnemonic_signals(text).longest_run())
        .max()
        .unwrap_or(0);
    assert!(
        worst <= 7,
        "longest curated-prose run climbed to {worst} against a trigger of 8"
    );
}

#[test]
fn a_keyword_list_is_numerically_identical_to_a_seed_phrase() {
    // The finding that closes off "just raise the threshold" as an option, asserted so it
    // cannot be forgotten and re-litigated.
    let keyword_list = "home safe, office safe, deposit box, metal plate, paper copy, spare device";
    let seed = mnemonics()[0];

    let list = mnemonic_signals(keyword_list);
    let phrase = mnemonic_signals(seed);

    assert_eq!(list.total_tokens, 12);
    assert_eq!(phrase.total_tokens, 12);
    assert_eq!(list.exact_matches, list.total_tokens);
    assert_eq!(phrase.exact_matches, phrase.total_tokens);
    assert_eq!(list.longest_run(), phrase.longest_run());
    assert_eq!(
        list.density().to_bits(),
        phrase.density().to_bits(),
        "if these ever differ, there is a discriminator worth using"
    );

    // Both fire. That is correct for one of them and unavoidable for the other.
    assert!(list.triggers());
    assert!(phrase.triggers());
}

#[test]
fn every_realistic_paste_shape_is_caught_and_by_a_named_clause() {
    // Not just "is it caught" — *which* rule catches it. A shape that only one clause
    // covers is a shape that a threshold change could silently drop.
    let all = mnemonics();
    let twelve = all[0];
    let twentyfour = all[2];

    let shorthand: String = twentyfour
        .split(' ')
        .map(|w| &w[..w.len().min(4)])
        .collect::<Vec<_>>()
        .join(" ");
    let shorthand_typo: String = twentyfour
        .split(' ')
        .enumerate()
        .map(|(i, w)| {
            if i == 4 {
                "zzzz".to_string()
            } else {
                w[..w.len().min(4)].to_string()
            }
        })
        .collect::<Vec<_>>()
        .join(" ");
    let one_typo: String = twelve
        .split(' ')
        .enumerate()
        .map(|(i, w)| {
            if i == 5 {
                format!("{w}x")
            } else {
                w.to_string()
            }
        })
        .collect::<Vec<_>>()
        .join(" ");

    // (name, input, must_fire_run, must_fire_density)
    let cases: [(&str, &str, bool, bool); 6] = [
        ("clean 12-word", twelve, true, true),
        ("clean 24-word", twentyfour, true, true),
        ("one word mistyped", &one_typo, false, true),
        ("4-letter shorthand", &shorthand, true, true),
        ("4-letter + one typo", &shorthand_typo, false, true),
        (
            "partial, 8 words",
            &twelve.split(' ').take(8).collect::<Vec<_>>().join(" "),
            true,
            true,
        ),
    ];

    for (name, input, expect_run, expect_density) in cases {
        let s = mnemonic_signals(input);
        assert!(s.triggers(), "{name}: MISSED entirely — {s:?}");
        if expect_run {
            assert!(
                s.run_trigger(),
                "{name}: expected the run trigger to fire — {s:?}"
            );
        }
        if expect_density {
            assert!(
                s.density_trigger(),
                "{name}: expected the density trigger to fire — {s:?}"
            );
        }
    }
}

#[test]
fn four_letter_shorthand_is_caught_by_shorthand_matching_not_by_luck() {
    // Confirms the mechanism, not just the outcome: exact matching must be nearly blind to
    // a truncated phrase, and the shorthand counters must be the thing that catches it.
    let phrase = mnemonics()[2];
    let truncated: String = phrase
        .split(' ')
        .map(|w| &w[..w.len().min(4)])
        .collect::<Vec<_>>()
        .join(" ");

    let s = mnemonic_signals(&truncated);
    assert!(
        s.exact_longest_run < 8,
        "fixture is not actually testing shorthand: exact run is {}",
        s.exact_longest_run
    );
    assert_eq!(
        s.shorthand_matches, s.total_tokens,
        "every truncated word should match as shorthand"
    );
    assert!(s.triggers());
}

/// Measured false-positive rate of extended-private-key detection against synthetic
/// extended public keys.
///
/// Ignored by default because it is a million-iteration simulation, not a unit test. Run
/// it with `cargo test --test calibration -- --ignored --nocapture` when changing anything
/// in `private_key.rs`.
///
/// A plain `contains("xprv")` scan flags roughly 1 in 1,100 of these. The rule that
/// discounts a mid-token hit inside a well-formed public key takes that to zero. Both
/// numbers are reproduced here so the claim in the module docs is checkable.
#[test]
#[ignore = "million-iteration simulation; run explicitly"]
fn extended_private_key_false_positive_rate() {
    const BASE58: &[u8] = b"123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";
    const PREFIXES: [&str; 6] = ["xprv", "yprv", "zprv", "tprv", "uprv", "vprv"];
    const N: usize = 1_000_000;

    // xorshift64*, so the run is reproducible without a dependency.
    let mut state: u64 = 0x2545_F491_4F6C_DD1D;
    let mut next = move || {
        state ^= state >> 12;
        state ^= state << 25;
        state ^= state >> 27;
        state.wrapping_mul(0x2545_F491_4F6C_DD1D)
    };

    let mut naive_hits = 0usize;
    let mut actual_hits = 0usize;

    for _ in 0..N {
        let mut key = String::with_capacity(111);
        key.push_str("xpub");
        for _ in 4..111 {
            let idx = (next() % BASE58.len() as u64) as usize;
            key.push(BASE58[idx] as char);
        }

        let lowered = key.to_lowercase();
        if PREFIXES.iter().any(|p| lowered.contains(p)) {
            naive_hits += 1;
        }
        if scan_for_secret_material(&key).is_some() {
            actual_hits += 1;
        }
    }

    println!(
        "\nEXTENDED PRIVATE KEY FALSE POSITIVES over {N} synthetic extended public keys\n  \
         naive substring scan : {naive_hits} (1 in {})\n  \
         shipped detector     : {actual_hits}\n",
        N.checked_div(naive_hits).unwrap_or(0)
    );

    assert!(
        naive_hits > 300,
        "the naive rate should be around 1 in 1,100; got {naive_hits} in {N}. \
         If this collapsed, the simulation is wrong, not the finding."
    );
    assert_eq!(
        actual_hits, 0,
        "the shipped detector produced {actual_hits} false positives on public keys"
    );
}

/// Prints the distribution. Not an assertion — the numbers are the deliverable.
#[test]
fn report_distribution() {
    let mut by_category: BTreeMap<&str, Vec<&str>> = BTreeMap::new();
    for (category, text) in corpus() {
        by_category.entry(category).or_default().push(text);
    }

    println!("\nNEGATIVE CORPUS DISTRIBUTION");
    println!("triggers: run >= 8, or matched >= 8 at density >= 0.75\n");
    println!(
        "{:<22}{:>4}{:>9}{:>10}{:>10}",
        "category", "n", "max run", "max dens", "flagged"
    );
    println!("{}", "-".repeat(55));

    for (category, texts) in &by_category {
        let mut max_run = 0;
        let mut max_density: f64 = 0.0;
        let mut flagged = 0;
        for text in texts {
            let s = mnemonic_signals(text);
            max_run = max_run.max(s.longest_run());
            if s.exact_matches.max(s.shorthand_matches) >= 8 {
                max_density = max_density.max(s.density());
            }
            if scan_for_secret_material(text).is_some() {
                flagged += 1;
            }
        }
        println!(
            "{:<22}{:>4}{:>9}{:>10.2}{:>10}",
            category,
            texts.len(),
            max_run,
            max_density,
            flagged
        );
    }
    println!("{}", "-".repeat(55));
    println!(
        "\nCategories asserted clean: {}\n\
         `questionnaire-terse` is measured, not asserted — see the module docs and\n\
         docs/security-model.md \u{a7}3 for why no threshold can separate it.\n",
        SECRET_INPUT_CATEGORIES.join(", ")
    );
}

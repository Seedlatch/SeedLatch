//! Address derivation and the gap limit.
//!
//! The address tests are known-answer: SLIP-0132 publishes the first address for each of its
//! three Bitcoin vectors, and those are vendored in `tests/fixtures/`. A derivation test
//! that checks our output against our own output proves only that it is deterministic.

use seedlatch::derive::{
    AddressPlan, Chain, DeriveError, GapScan, SingleSigScript, BATCH_SIZE, GAP_LIMIT,
    MAX_ADDRESSES_PER_CHAIN,
};
use seedlatch::parse::descriptor::parse_descriptor;
use seedlatch::parse::extended_key::{parse_extended_key, ScriptType};
use seedlatch::parse::guard_input;

const PUBKEYS: &str = include_str!("fixtures/slip132-pubkeys.txt");
const ADDRESSES: &str = include_str!("fixtures/slip132-first-addresses.txt");

/// `(key, derivation path, first address)` for the three published vectors, in file order.
fn vectors() -> Vec<(&'static str, &'static str, &'static str)> {
    let keys = PUBKEYS.lines().map(str::trim).filter(|l| !l.is_empty());
    let rows = ADDRESSES.lines().map(str::trim).filter(|l| !l.is_empty());

    keys.zip(rows)
        .map(|(key, row)| {
            let (path, address) = row.split_once(' ').expect("path and address");
            (key, path, address)
        })
        .collect()
}

/// The script type each published path uses. Taken from the path in the fixture, not from
/// the key: an `xpub` does not say, which is the whole point of the ambiguity flag.
fn script_for(path: &str) -> SingleSigScript {
    if path.starts_with("m/44") {
        SingleSigScript::Pkh
    } else if path.starts_with("m/49") {
        SingleSigScript::ShWpkh
    } else if path.starts_with("m/84") {
        SingleSigScript::Wpkh
    } else {
        panic!("unmapped derivation path in fixture: {path}")
    }
}

fn plan_for(key_text: &str, script: SingleSigScript) -> AddressPlan {
    let accepted = guard_input(key_text).expect("public key");
    let key = parse_extended_key(&accepted).expect("decodes");
    AddressPlan::from_key(&key, script).expect("plan")
}

#[test]
fn the_published_first_addresses_are_reproduced_exactly() {
    let vectors = vectors();
    assert_eq!(vectors.len(), 3, "fixtures must line up");

    for (key, path, expected) in vectors {
        let plan = plan_for(key, script_for(path));
        let derived = plan
            .address(Chain::External, 0)
            .expect("first receive address");

        assert_eq!(derived.to_string(), expected, "{path} from {}", &key[..4]);
    }
}

#[test]
fn the_change_chain_differs_from_the_receive_chain() {
    // A wallet whose receive addresses look empty can hold its whole balance in change, so
    // both are scanned — and they must not be the same addresses.
    for (key, path, _) in vectors() {
        let plan = plan_for(key, script_for(path));
        let external = plan.address(Chain::External, 0).expect("external");
        let internal = plan.address(Chain::Internal, 0).expect("internal");
        assert_ne!(external, internal, "{path}");
    }
}

#[test]
fn consecutive_indices_give_different_addresses() {
    let (key, path, _) = vectors()[2];
    let plan = plan_for(key, script_for(path));
    let a = plan.address(Chain::External, 0).expect("0");
    let b = plan.address(Chain::External, 1).expect("1");
    assert_ne!(a, b);
}

#[test]
fn a_bare_multisig_key_cannot_be_enumerated() {
    // A Zpub is one cosigner. Its addresses depend on the other keys and the threshold, so
    // completing it with a guess would produce addresses belonging to no wallet at all.
    // Constructed by re-versioning, since no Zpub vectors are published.
    let (xpub, _, _) = vectors()[0];
    let accepted = guard_input(xpub).expect("public key");
    let key = parse_extended_key(&accepted).expect("decodes");

    // The mapping refuses before any plan is built.
    assert_eq!(SingleSigScript::implied_by(ScriptType::MultisigP2wsh), None);
    assert_eq!(
        SingleSigScript::implied_by(ScriptType::MultisigP2wshInP2sh),
        None
    );

    // And an xpub, which is ambiguous rather than multisig, also refuses to imply one.
    assert_eq!(SingleSigScript::implied_by(key.script_type()), None);
}

#[test]
fn only_the_unambiguous_single_sig_versions_imply_a_script_type() {
    assert_eq!(
        SingleSigScript::implied_by(ScriptType::P2wpkh),
        Some(SingleSigScript::Wpkh)
    );
    assert_eq!(
        SingleSigScript::implied_by(ScriptType::P2wpkhInP2sh),
        Some(SingleSigScript::ShWpkh)
    );
    assert_eq!(SingleSigScript::implied_by(ScriptType::P2pkhOrP2sh), None);
}

#[test]
fn a_descriptor_without_a_wildcard_is_not_enumerable() {
    let (xpub, _, _) = vectors()[0];
    let text = format!("wpkh({xpub})");
    let accepted = guard_input(&text).expect("no secret material");
    let parsed = parse_descriptor(&accepted).expect("parses");

    assert_eq!(
        AddressPlan::from_descriptor(&parsed).err(),
        Some(DeriveError::NotEnumerable)
    );
}

#[test]
fn a_descriptor_plan_reproduces_the_published_address() {
    // The same answer through the other door: a descriptor written by hand around the
    // published key must derive the published address.
    let (xpub, _, expected) = vectors()[0];
    let text = format!("pkh({xpub}/0/*)");
    let accepted = guard_input(&text).expect("no secret material");
    let parsed = parse_descriptor(&accepted).expect("parses");
    let plan = AddressPlan::from_descriptor(&parsed).expect("plan");

    assert_eq!(
        plan.address(Chain::External, 0)
            .expect("address")
            .to_string(),
        expected
    );
}

#[test]
fn debug_does_not_reproduce_the_wallet() {
    let (key, path, _) = vectors()[0];
    let plan = plan_for(key, script_for(path));
    let rendered = format!("{plan:?}");

    assert!(rendered.contains("redacted"));
    assert!(!rendered.contains(key.get(10..40).expect("long enough")));
}

// ---- gap limit ------------------------------------------------------------

/// Drive a scan against a predicate saying which indices are used.
fn run(used: impl Fn(u32) -> bool) -> GapScan {
    let mut scan = GapScan::new();
    while let Some((start, count)) = scan.next_batch() {
        let results: Vec<bool> = (start..start + count).map(&used).collect();
        scan.record(&results);
    }
    scan
}

#[test]
fn an_empty_wallet_stops_at_the_gap_limit() {
    let scan = run(|_| false);
    assert!(scan.is_complete());
    assert!(!scan.is_truncated());
    assert_eq!(scan.examined(), GAP_LIMIT);
}

#[test]
fn a_used_address_resets_the_run() {
    // Used at 0, then nothing. The scan must look GAP_LIMIT past the last used address,
    // not GAP_LIMIT from the start.
    let scan = run(|i| i == 0);
    assert!(scan.is_complete());
    // The gap closes GAP_LIMIT past the last used address, and not one request later.
    assert_eq!(
        scan.examined(),
        1 + GAP_LIMIT,
        "no overshoot past what closes the gap"
    );
}

#[test]
fn a_used_address_just_inside_the_gap_extends_the_scan() {
    let near = run(|i| i == GAP_LIMIT - 1);
    let far = run(|_| false);
    assert!(
        near.examined() > far.examined(),
        "a hit at the edge of the gap must extend the scan"
    );
}

#[test]
fn a_wallet_longer_than_the_ceiling_is_marked_truncated() {
    // Every address used, so the gap never closes. The scan must stop anyway rather than
    // loop against someone else's server, and must say that it stopped early.
    let scan = run(|_| true);
    assert!(scan.is_complete());
    assert!(
        scan.is_truncated(),
        "stopping at the ceiling is not the same as finishing"
    );
    assert_eq!(scan.examined(), MAX_ADDRESSES_PER_CHAIN);
}

#[test]
fn an_unrecorded_batch_is_offered_again_rather_than_skipped() {
    // A dropped response must not advance the scan past addresses nobody looked at.
    let mut scan = GapScan::new();
    let first = scan.next_batch().expect("a batch");
    let again = scan.next_batch().expect("the same batch");
    assert_eq!(first, again);
    assert_eq!(scan.examined(), 0);
}

#[test]
fn a_short_response_only_advances_over_what_it_covered() {
    // Recording five results for a batch of twenty must not mark the other fifteen unused.
    let mut scan = GapScan::new();
    let (_, count) = scan.next_batch().expect("a batch");
    assert_eq!(count, BATCH_SIZE);

    scan.record(&[false; 5]);
    assert_eq!(scan.examined(), 5);
    assert!(!scan.is_complete());
}

#[test]
fn recording_without_an_outstanding_batch_changes_nothing() {
    let mut scan = GapScan::new();
    scan.record(&[true; 10]);
    assert_eq!(scan.examined(), 0);
    assert!(!scan.is_complete());
}

#[test]
fn a_single_path_descriptor_refuses_the_chain_it_does_not_cover() {
    // Regression. This returned the receive address for BOTH chains, silently, so a scanner
    // would have queried the same chain twice and reported change as checked without ever
    // looking at it. A missed balance that looks examined is the worst shape of wrong.
    let (xpub, _, _) = vectors()[0];
    let text = format!("wpkh({xpub}/0/*)");
    let accepted = guard_input(&text).expect("no secret material");
    let parsed = parse_descriptor(&accepted).expect("parses");
    let plan = AddressPlan::from_descriptor(&parsed).expect("plan");

    assert_eq!(plan.chain_count(), 1, "one path written, one chain covered");
    assert!(plan.address(Chain::External, 0).is_ok());
    assert_eq!(
        plan.address(Chain::Internal, 0).err(),
        Some(DeriveError::ChainNotInDescriptor),
        "the chain it does not cover must be refused, not substituted"
    );
}

#[test]
fn a_multipath_descriptor_covers_both_chains_with_different_addresses() {
    let (xpub, _, _) = vectors()[0];
    let text = format!("wpkh({xpub}/<0;1>/*)");
    let accepted = guard_input(&text).expect("no secret material");
    let parsed = parse_descriptor(&accepted).expect("parses");
    let plan = AddressPlan::from_descriptor(&parsed).expect("plan");

    assert_eq!(plan.chain_count(), 2);
    let external = plan.address(Chain::External, 0).expect("external");
    let internal = plan.address(Chain::Internal, 0).expect("internal");
    assert_ne!(external, internal);
}

#[test]
fn chains_reports_only_what_can_actually_be_scanned() {
    // A caller iterating chains() cannot ask for a chain that does not exist, which is the
    // structural version of the bug above.
    let (xpub, path, _) = vectors()[0];

    let single_text = format!("wpkh({xpub}/0/*)");
    let accepted = guard_input(&single_text).expect("clean");
    let parsed = parse_descriptor(&accepted).expect("parses");
    let single = AddressPlan::from_descriptor(&parsed).expect("plan");
    assert_eq!(single.chains().count(), 1);

    let from_key = plan_for(xpub, script_for(path));
    assert_eq!(
        from_key.chains().count(),
        2,
        "a bare key covers both chains"
    );

    for plan in [&single, &from_key] {
        for chain in plan.chains() {
            assert!(
                plan.address(chain, 0).is_ok(),
                "every chain reported must be derivable"
            );
        }
    }
}

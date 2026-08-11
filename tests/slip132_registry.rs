//! The SLIP-132 version-byte table is verified against the vendored registry, not trusted.
//!
//! # Why this test exists rather than a code review
//!
//! Version bytes are security-relevant derivation data, and `CLAUDE.md` invariant 8 forbids
//! writing that from memory or inference. One wrong nibble means the wrong script type,
//! which means deriving addresses the user does not own, checking balances that are not
//! theirs, and reporting on a wallet that does not exist — and the user could act on it.
//!
//! A transcription error of that kind is invisible to review: `0x049d7cb2` and `0x049d7cb3`
//! look identical at a glance, and both look plausible. So the table in
//! `src/parse/extended_key.rs` is checked here against `data/slip132-versions.txt`, which is
//! hash-pinned in `data/SHA256SUMS` and extracted verbatim from SLIP-0132
//! (`data/PROVENANCE.md`). The constants are convenience; the pinned file is the authority.

use seedlatch::parse::extended_key::{
    lookup, KeyNetwork, ScriptType, Slip132Version, SLIP132_VERSIONS,
};

/// The registry as vendored. Hash-pinned, and CI verifies the hash before this test runs.
const REGISTRY: &str = include_str!("../data/slip132-versions.txt");

#[derive(Debug)]
struct Row {
    coin: String,
    public: (String, [u8; 4]),
    private: (String, [u8; 4]),
    encoding: String,
}

fn parse_version_cell(cell: &str) -> (String, [u8; 4]) {
    // Cells look like: `0x0488b21e` - `xpub`
    let cleaned = cell.replace('`', "");
    let (hex_part, prefix_part) = cleaned
        .split_once('-')
        .unwrap_or_else(|| panic!("cell has no separator: {cell}"));

    let hex = hex_part.trim().trim_start_matches("0x");
    assert_eq!(hex.len(), 8, "version bytes must be 4 bytes: {cell}");

    let mut bytes = [0u8; 4];
    for (i, byte) in bytes.iter_mut().enumerate() {
        let pair = hex.get(i * 2..i * 2 + 2).expect("checked length above");
        *byte = u8::from_str_radix(pair, 16).expect("registry hex must parse");
    }

    let prefix = prefix_part.trim().to_owned();
    assert_eq!(prefix.len(), 4, "prefix must be 4 characters: {cell}");
    (prefix, bytes)
}

/// Every data row of the vendored table.
fn registry_rows() -> Vec<Row> {
    REGISTRY
        .lines()
        .filter(|line| line.starts_with("Bitcoin"))
        .map(|line| {
            let cells: Vec<&str> = line.split('|').map(str::trim).collect();
            assert!(cells.len() >= 5, "unexpected row shape: {line}");
            Row {
                coin: cells[0].to_owned(),
                public: parse_version_cell(cells[1]),
                private: parse_version_cell(cells[2]),
                encoding: cells[3].to_owned(),
            }
        })
        .collect()
}

fn expected_network(coin: &str) -> KeyNetwork {
    match coin {
        "Bitcoin" => KeyNetwork::Mainnet,
        "Bitcoin Testnet" => KeyNetwork::Testnet,
        other => panic!("unexpected coin in a Bitcoin-only extract: {other}"),
    }
}

/// Exact match, never `contains`. "P2WPKH in P2SH" contains "P2WPKH", and
/// "Multi-signature P2WSH in P2SH" contains "Multi-signature P2WSH", so a substring test
/// would silently classify the nested forms as the bare ones — which is the exact confusion
/// SLIP-132 exists to remove.
fn expected_script_type(encoding: &str) -> ScriptType {
    match encoding {
        "P2PKH or P2SH" => ScriptType::P2pkhOrP2sh,
        "P2WPKH in P2SH" => ScriptType::P2wpkhInP2sh,
        "P2WPKH" => ScriptType::P2wpkh,
        "Multi-signature P2WSH in P2SH" => ScriptType::MultisigP2wshInP2sh,
        "Multi-signature P2WSH" => ScriptType::MultisigP2wsh,
        other => panic!("unmapped address encoding: {other}"),
    }
}

fn find(bytes: [u8; 4]) -> &'static Slip132Version {
    SLIP132_VERSIONS
        .iter()
        .find(|entry| entry.bytes == bytes)
        .unwrap_or_else(|| panic!("version {bytes:02x?} is in the registry but not in the table"))
}

#[test]
fn registry_extract_has_the_expected_shape() {
    let rows = registry_rows();
    assert_eq!(rows.len(), 10, "5 Bitcoin rows and 5 Bitcoin Testnet rows");
    assert_eq!(rows.iter().filter(|r| r.coin == "Bitcoin").count(), 5);
    assert_eq!(
        rows.iter().filter(|r| r.coin == "Bitcoin Testnet").count(),
        5
    );
}

#[test]
fn every_registry_row_matches_the_table() {
    for row in registry_rows() {
        let network = expected_network(&row.coin);
        let script_type = expected_script_type(&row.encoding);

        for (prefix, bytes, is_private) in [
            (&row.public.0, row.public.1, false),
            (&row.private.0, row.private.1, true),
        ] {
            let entry = find(bytes);
            assert_eq!(entry.prefix, prefix.as_str(), "prefix for {bytes:02x?}");
            assert_eq!(entry.network, network, "network for {prefix}");
            assert_eq!(entry.script_type, script_type, "script type for {prefix}");
            assert_eq!(entry.is_private, is_private, "private flag for {prefix}");
        }
    }
}

#[test]
fn the_table_contains_nothing_the_registry_does_not() {
    let rows = registry_rows();
    assert_eq!(
        SLIP132_VERSIONS.len(),
        rows.len() * 2,
        "one public and one private entry per registry row, and nothing invented"
    );

    for entry in &SLIP132_VERSIONS {
        let known = rows.iter().any(|row| {
            (row.public.1 == entry.bytes && !entry.is_private)
                || (row.private.1 == entry.bytes && entry.is_private)
        });
        assert!(known, "table entry {} is not in the registry", entry.prefix);
    }
}

#[test]
fn version_bytes_are_unique_across_the_whole_table() {
    // A duplicate would make `lookup` return whichever entry came first, silently choosing
    // one script type over another for the same input.
    for (i, a) in SLIP132_VERSIONS.iter().enumerate() {
        for b in SLIP132_VERSIONS.iter().skip(i + 1) {
            assert_ne!(
                a.bytes, b.bytes,
                "{} and {} share version bytes",
                a.prefix, b.prefix
            );
        }
    }
}

#[test]
fn lookup_returns_the_registry_entry_for_every_known_version() {
    for row in registry_rows() {
        for (prefix, bytes) in [row.public, row.private] {
            let found = lookup(bytes).unwrap_or_else(|| panic!("lookup failed for {prefix}"));
            assert_eq!(found.prefix, prefix.as_str());
            assert_eq!(found.bytes, bytes);
        }
    }
}

#[test]
fn lookup_refuses_versions_outside_the_bitcoin_registry() {
    // Litecoin Ltub, Lyncoin Lpub and Polis ppub are real registered versions for other
    // coins. They are deliberately absent: this tool reads Bitcoin, and an unrecognised
    // version must be refused rather than interpreted as the nearest Bitcoin equivalent.
    for bytes in [
        [0x01, 0x9d, 0xa4, 0x62], // Ltub
        [0x01, 0x9c, 0x35, 0x4f], // Lpub
        [0x03, 0xe2, 0x5d, 0x7e], // ppub
        [0x00, 0x00, 0x00, 0x00],
        [0xff, 0xff, 0xff, 0xff],
    ] {
        assert!(lookup(bytes).is_none(), "{bytes:02x?} must not resolve");
    }
}

#[test]
fn public_and_private_versions_never_collide() {
    // The parser refuses an extended private key by version bytes rather than by prefix
    // letter. That only works if no public version equals a private one.
    let publics: Vec<[u8; 4]> = SLIP132_VERSIONS
        .iter()
        .filter(|e| !e.is_private)
        .map(|e| e.bytes)
        .collect();

    for entry in SLIP132_VERSIONS.iter().filter(|e| e.is_private) {
        assert!(
            !publics.contains(&entry.bytes),
            "{} shares version bytes with a public form",
            entry.prefix
        );
    }
}

#[test]
fn the_capitalised_multisig_forms_are_present_and_distinct() {
    // CLAUDE.md invariant 1 names these as the ones that are easy to miss, and the approved
    // interstitial copy tells multisig holders their Ypub and Zpub are accepted. `ypub` and
    // `Ypub` are different version bytes meaning different script types; folding their case
    // would derive the wrong addresses.
    for (lower, upper) in [
        ("ypub", "Ypub"),
        ("zpub", "Zpub"),
        ("upub", "Upub"),
        ("vpub", "Vpub"),
    ] {
        let a = SLIP132_VERSIONS
            .iter()
            .find(|e| e.prefix == lower)
            .expect("lowercase form");
        let b = SLIP132_VERSIONS
            .iter()
            .find(|e| e.prefix == upper)
            .expect("capitalised form");
        assert_ne!(a.bytes, b.bytes, "{lower} and {upper} must differ");
        assert_ne!(
            a.script_type, b.script_type,
            "{lower} and {upper} are different script types"
        );
    }
}

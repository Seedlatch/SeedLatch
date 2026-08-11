//! SLIP-132 version bytes: what the four bytes at the front of an extended key mean.
//!
//! # Why this table exists here rather than in a dependency
//!
//! `rust-bitcoin` does not implement SLIP-132. Verified against the vendored sources of
//! `bitcoin 0.32.102` and `miniscript 13.1.0`: neither mentions `slip132` anywhere, and
//! `bitcoin::bip32` knows exactly four version constants — mainnet and testnet, public and
//! private, all BIP-32. `Xpub::from_str` therefore rejects every `ypub`, `Ypub`, `zpub`,
//! `Zpub`, `upub`, `Upub`, `vpub` and `Vpub` outright.
//!
//! So the mapping is ours to hold, and it is held as data checked against a pinned copy of
//! the standard rather than as constants someone typed. See `tests/slip132_registry.rs`:
//! every entry below is verified against `data/slip132-versions.txt`, which is hash-pinned
//! and extracted verbatim from SLIP-0132.
//!
//! # The version bytes are the truth; the prefix letter is a rendering of them
//!
//! `ypub` and `Ypub` are not a spelling difference. They are `0x049d7cb2` and `0x0295b43f`,
//! which are different script types — single-signature P2WPKH-in-P2SH and multi-signature
//! P2WSH-in-P2SH. Folding their case means deriving the wrong script, which means addresses
//! the user does not own and balances that are not theirs. That is why `AcceptedInput` holds
//! the input verbatim and why nothing downstream of it may normalise case.
//!
//! # What these bytes cannot tell anyone
//!
//! They do not identify the coin. Fifteen non-Bitcoin rows of the same registry share
//! Bitcoin's public version bytes — Groestlcoin duplicates all ten exactly — and one
//! collision disagrees about the script type as well: `0x045f1cf6` is Bitcoin Testnet `vpub`
//! meaning P2WPKH, and Kylacoin Testnet `vpub` meaning P2PKH or P2SH.
//!
//! This table is therefore read as *"interpreted as Bitcoin, these bytes mean this"*. A
//! version outside it — Litecoin's `Ltub`, Lyncoin's `Lpub` — resolves to nothing and is
//! refused, which is the fail-closed direction. A Groestlcoin key is indistinguishable from
//! a Bitcoin one and no amount of care here changes that. `data/PROVENANCE.md` records it.

// Through miniscript's re-export (`pub use {bitcoin, hex}` in its lib.rs) rather than as a
// second direct dependency. `bitcoin` is already in the tree either way; declaring it again
// would add a version number to keep in step with miniscript's for no benefit.
use miniscript::bitcoin::NetworkKind;

/// Which Bitcoin network a version belongs to.
///
/// Deliberately not `bitcoin::Network`: that enum distinguishes testnet from signet and
/// regtest, and SLIP-132 does not. Claiming a `tpub` is specifically testnet3 rather than
/// signet would be inventing a distinction the input does not carry.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum KeyNetwork {
    Mainnet,
    Testnet,
}

impl KeyNetwork {
    /// The `rust-bitcoin` view of the same distinction.
    pub const fn network_kind(self) -> NetworkKind {
        match self {
            Self::Mainnet => NetworkKind::Main,
            Self::Testnet => NetworkKind::Test,
        }
    }
}

/// The address encoding a version implies, in SLIP-132's own terms.
///
/// [`Self::P2pkhOrP2sh`] is genuinely ambiguous and is named that way on purpose. A plain
/// `xpub` does not say which of the two it is, so the tool must not pick one — that
/// ambiguity is the reason a bare extended key needs the script type stated by the user,
/// while a descriptor never does.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ScriptType {
    /// `xpub`/`tpub`. Ambiguous by construction — see the type note.
    P2pkhOrP2sh,
    /// `ypub`/`upub`. Single-signature, nested segwit.
    P2wpkhInP2sh,
    /// `zpub`/`vpub`. Single-signature, native segwit.
    P2wpkh,
    /// `Ypub`/`Upub`. Multi-signature, nested segwit.
    MultisigP2wshInP2sh,
    /// `Zpub`/`Vpub`. Multi-signature, native segwit.
    MultisigP2wsh,
}

impl ScriptType {
    /// Whether this version implies a multi-signature script.
    ///
    /// Only the capitalised forms do. This is the distinction a `Zpub` holder is relying on,
    /// and the audience most likely to have survived the defect this tool checks for.
    pub const fn is_multisig(self) -> bool {
        matches!(self, Self::MultisigP2wshInP2sh | Self::MultisigP2wsh)
    }
}

/// One registered version: four bytes, and what they mean read as Bitcoin.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Slip132Version {
    /// The four version bytes, big-endian as serialised.
    pub bytes: [u8; 4],
    /// The base58 prefix these bytes produce. Case-significant.
    pub prefix: &'static str,
    pub network: KeyNetwork,
    pub script_type: ScriptType,
    /// True for the `prv` forms. Present so a private key can be refused by its version
    /// bytes rather than by matching a prefix letter, which is a stronger check.
    pub is_private: bool,
}

/// Every Bitcoin and Bitcoin Testnet version in the SLIP-132 registry.
///
/// A `static` rather than a `const`: a `const` is inlined at each use site, so iterating one
/// borrows a temporary and no reference into it can outlive the expression. [`lookup`]
/// returns `&'static`, which requires a single fixed location.
///
/// Ordered as the registry orders them — mainnet then testnet, and within each, by the
/// derivation path SLIP-132 lists. Do not reorder to group public and private together; the
/// verification test reads the registry, not this order, but a diff against the standard
/// should stay easy for a human to check.
///
/// `rustfmt::skip` is deliberate. Formatting expands each entry to seven lines, turning
/// twenty rows into a hundred and forty and putting each version's bytes, prefix and script
/// type on separate screens. One row per registered version is the whole point: it is what
/// lets a reviewer read this against `data/slip132-versions.txt` line by line, which is the
/// only manual check that would catch a wrong nibble before the tests do.
#[rustfmt::skip]
pub static SLIP132_VERSIONS: [Slip132Version; 20] = [
    // Bitcoin
    Slip132Version { bytes: [0x04, 0x88, 0xb2, 0x1e], prefix: "xpub", network: KeyNetwork::Mainnet, script_type: ScriptType::P2pkhOrP2sh, is_private: false },
    Slip132Version { bytes: [0x04, 0x88, 0xad, 0xe4], prefix: "xprv", network: KeyNetwork::Mainnet, script_type: ScriptType::P2pkhOrP2sh, is_private: true },
    Slip132Version { bytes: [0x04, 0x9d, 0x7c, 0xb2], prefix: "ypub", network: KeyNetwork::Mainnet, script_type: ScriptType::P2wpkhInP2sh, is_private: false },
    Slip132Version { bytes: [0x04, 0x9d, 0x78, 0x78], prefix: "yprv", network: KeyNetwork::Mainnet, script_type: ScriptType::P2wpkhInP2sh, is_private: true },
    Slip132Version { bytes: [0x04, 0xb2, 0x47, 0x46], prefix: "zpub", network: KeyNetwork::Mainnet, script_type: ScriptType::P2wpkh, is_private: false },
    Slip132Version { bytes: [0x04, 0xb2, 0x43, 0x0c], prefix: "zprv", network: KeyNetwork::Mainnet, script_type: ScriptType::P2wpkh, is_private: true },
    Slip132Version { bytes: [0x02, 0x95, 0xb4, 0x3f], prefix: "Ypub", network: KeyNetwork::Mainnet, script_type: ScriptType::MultisigP2wshInP2sh, is_private: false },
    Slip132Version { bytes: [0x02, 0x95, 0xb0, 0x05], prefix: "Yprv", network: KeyNetwork::Mainnet, script_type: ScriptType::MultisigP2wshInP2sh, is_private: true },
    Slip132Version { bytes: [0x02, 0xaa, 0x7e, 0xd3], prefix: "Zpub", network: KeyNetwork::Mainnet, script_type: ScriptType::MultisigP2wsh, is_private: false },
    Slip132Version { bytes: [0x02, 0xaa, 0x7a, 0x99], prefix: "Zprv", network: KeyNetwork::Mainnet, script_type: ScriptType::MultisigP2wsh, is_private: true },
    // Bitcoin Testnet
    Slip132Version { bytes: [0x04, 0x35, 0x87, 0xcf], prefix: "tpub", network: KeyNetwork::Testnet, script_type: ScriptType::P2pkhOrP2sh, is_private: false },
    Slip132Version { bytes: [0x04, 0x35, 0x83, 0x94], prefix: "tprv", network: KeyNetwork::Testnet, script_type: ScriptType::P2pkhOrP2sh, is_private: true },
    Slip132Version { bytes: [0x04, 0x4a, 0x52, 0x62], prefix: "upub", network: KeyNetwork::Testnet, script_type: ScriptType::P2wpkhInP2sh, is_private: false },
    Slip132Version { bytes: [0x04, 0x4a, 0x4e, 0x28], prefix: "uprv", network: KeyNetwork::Testnet, script_type: ScriptType::P2wpkhInP2sh, is_private: true },
    Slip132Version { bytes: [0x04, 0x5f, 0x1c, 0xf6], prefix: "vpub", network: KeyNetwork::Testnet, script_type: ScriptType::P2wpkh, is_private: false },
    Slip132Version { bytes: [0x04, 0x5f, 0x18, 0xbc], prefix: "vprv", network: KeyNetwork::Testnet, script_type: ScriptType::P2wpkh, is_private: true },
    Slip132Version { bytes: [0x02, 0x42, 0x89, 0xef], prefix: "Upub", network: KeyNetwork::Testnet, script_type: ScriptType::MultisigP2wshInP2sh, is_private: false },
    Slip132Version { bytes: [0x02, 0x42, 0x85, 0xb5], prefix: "Uprv", network: KeyNetwork::Testnet, script_type: ScriptType::MultisigP2wshInP2sh, is_private: true },
    Slip132Version { bytes: [0x02, 0x57, 0x54, 0x83], prefix: "Vpub", network: KeyNetwork::Testnet, script_type: ScriptType::MultisigP2wsh, is_private: false },
    Slip132Version { bytes: [0x02, 0x57, 0x50, 0x48], prefix: "Vprv", network: KeyNetwork::Testnet, script_type: ScriptType::MultisigP2wsh, is_private: true },
];

/// Resolve four version bytes, read as Bitcoin.
///
/// Returns `None` for anything not in the Bitcoin registry — another coin's version, or
/// bytes that are not a registered version at all. Callers must refuse on `None` rather than
/// falling back to the nearest Bitcoin equivalent: a version this table does not recognise
/// is one whose script type is unknown, and guessing it derives addresses the user does not
/// own.
pub fn lookup(version: [u8; 4]) -> Option<&'static Slip132Version> {
    SLIP132_VERSIONS.iter().find(|entry| entry.bytes == version)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn multisig_is_exactly_the_capitalised_forms() {
        for entry in &SLIP132_VERSIONS {
            let capitalised = entry.prefix.starts_with(['Y', 'Z', 'U', 'V']);
            assert_eq!(
                entry.script_type.is_multisig(),
                capitalised,
                "{} disagrees about being multisig",
                entry.prefix
            );
        }
    }

    #[test]
    fn network_kind_matches_the_network() {
        assert_eq!(KeyNetwork::Mainnet.network_kind(), NetworkKind::Main);
        assert_eq!(KeyNetwork::Testnet.network_kind(), NetworkKind::Test);
    }
}

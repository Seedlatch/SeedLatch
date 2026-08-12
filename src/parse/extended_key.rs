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

use core::fmt;

use zeroize::Zeroizing;

// Through miniscript's re-export (`pub use {bitcoin, hex}` in its lib.rs) rather than as a
// second direct dependency. `bitcoin` is already in the tree either way; declaring it again
// would add a version number to keep in step with miniscript's for no benefit. `base58` is
// reachable the same way — `bitcoin` re-exports the `base58ck` crate under that name.
use miniscript::bitcoin::{base58, bip32::Xpub, Network, NetworkKind};

use super::AcceptedInput;

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
    /// Stable machine identifier for the browser boundary. Not user-facing copy.
    pub const fn key(self) -> &'static str {
        match self {
            Self::Mainnet => "mainnet",
            Self::Testnet => "testnet",
        }
    }

    /// The network to encode addresses for.
    ///
    /// `Testnet` rather than signet or regtest: SLIP-132 does not distinguish them, and
    /// testnet and signet share address prefixes anyway, so claiming one specifically would
    /// be inventing a distinction the input does not carry.
    pub const fn network(self) -> Network {
        match self {
            Self::Mainnet => Network::Bitcoin,
            Self::Testnet => Network::Testnet,
        }
    }

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
    /// Stable machine identifier for the browser boundary. Switch on this, never on a label.
    pub const fn key(self) -> &'static str {
        match self {
            Self::P2pkhOrP2sh => "p2pkh_or_p2sh",
            Self::P2wpkhInP2sh => "p2wpkh_in_p2sh",
            Self::P2wpkh => "p2wpkh",
            Self::MultisigP2wshInP2sh => "multisig_p2wsh_in_p2sh",
            Self::MultisigP2wsh => "multisig_p2wsh",
        }
    }

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

/// The BIP-32 public version for a network — the only versions `Xpub::decode` accepts.
///
/// Read out of the table rather than written down again. `xpub` and `tpub` already appear
/// above, and a second copy of four bytes is a second thing to keep correct: the two would
/// agree until someone edited one of them.
fn bip32_public_version(network: KeyNetwork) -> Option<[u8; 4]> {
    SLIP132_VERSIONS
        .iter()
        .find(|entry| {
            entry.network == network
                && entry.script_type == ScriptType::P2pkhOrP2sh
                && !entry.is_private
        })
        .map(|entry| entry.bytes)
}

/// Length of a serialised extended key, checksum already stripped.
///
/// 4 version + 1 depth + 4 parent fingerprint + 4 child number + 32 chain code + 33 key.
/// `Xpub::decode` rejects anything else, but the length is checked here so the failure is
/// this module's typed error rather than an opaque one from a dependency.
const SERIALISED_LEN: usize = 78;

/// Why an extended key was not accepted.
///
/// Carries no input, by construction. An extended public key is not secret material — it is
/// refused by nothing and the whole tool is built to accept it — but it *is* the user's
/// complete address and balance history, and an error string is exactly how that reaches a
/// log or a bug report.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum ExtendedKeyError {
    /// Not valid base58check: wrong alphabet, or the checksum did not verify. A single
    /// mistyped character lands here, which is what base58check is for.
    NotBase58,
    /// Decoded, but not the length of a serialised extended key. The length is a count, not
    /// content.
    WrongLength { actual: usize },
    /// Base58check-valid and the right length, but the version bytes are not in the Bitcoin
    /// registry — another coin's key, or not a registered version at all.
    UnrecognisedVersion,
    /// The version bytes say this is an extended **private** key.
    ///
    /// Reaching this is a detector failure, not a normal path: `guard_input` refuses private
    /// key material before anything gets here. It is checked anyway, by a different
    /// mechanism — version bytes after a base58check decode, rather than prefix shape before
    /// one — so the two would have to fail independently for a private key to be processed.
    ExtendedPrivateKey,
    /// Depth is zero — a master key — but the parent fingerprint or the child number is not.
    ///
    /// Self-contradictory: a master key has no parent and no index. BIP-32 lists both forms
    /// among its invalid test vectors, and **`rust-bitcoin` accepts them** — verified,
    /// `Xpub::decode` returns `Ok` for the "zero depth with non-zero parent fingerprint" and
    /// "zero depth with non-zero index" vectors. So this is checked here rather than assumed
    /// of the dependency. It matters because depth is reported to the user: a key that says
    /// it is a master key is a different finding from one that says it is an account key,
    /// and a key whose own metadata disagrees with itself should not be reported at all.
    InconsistentDepth,
    /// Well-formed base58check of the right length with a known public version, and
    /// `rust-bitcoin` still rejected the body.
    Malformed,
}

impl ExtendedKeyError {
    /// Stable machine identifier. Distinct from [`fmt::Display`], which is reviewed copy and
    /// changes when someone edits the wording; this must not.
    pub const fn key(&self) -> &'static str {
        match self {
            Self::NotBase58 => "not_base58",
            Self::WrongLength { .. } => "wrong_length",
            Self::UnrecognisedVersion => "unrecognised_version",
            Self::ExtendedPrivateKey => "extended_private_key",
            Self::InconsistentDepth => "inconsistent_depth",
            Self::Malformed => "malformed",
        }
    }
}

impl fmt::Display for ExtendedKeyError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::NotBase58 => f.write_str(
                "not a valid extended key: the characters or the checksum did not verify",
            ),
            Self::WrongLength { actual } => write!(
                f,
                "not a valid extended key: decoded to {actual} bytes, expected {SERIALISED_LEN}"
            ),
            Self::UnrecognisedVersion => f.write_str(
                "not a recognised Bitcoin extended key version; this tool reads Bitcoin only",
            ),
            Self::ExtendedPrivateKey => {
                f.write_str("that is an extended private key and is never accepted")
            }
            Self::InconsistentDepth => f.write_str(
                "not a valid extended key: it claims to be a master key but records a parent",
            ),
            Self::Malformed => f.write_str("not a valid extended key: the contents did not parse"),
        }
    }
}

impl std::error::Error for ExtendedKeyError {}

/// A decoded extended public key, together with what its version bytes said it was.
///
/// The [`Xpub`] inside has been rewritten to BIP-32 version bytes so `rust-bitcoin` will
/// accept it. That rewrite discards the script type, which is the entire reason the original
/// version is kept alongside: an `Xpub` on its own cannot say whether it came from a `zpub`
/// or a `Zpub`, and those are different wallets.
#[derive(Clone)]
pub struct ExtendedKey {
    xpub: Xpub,
    version: &'static Slip132Version,
}

impl ExtendedKey {
    /// The script type the version bytes declared. For `xpub`/`tpub` this is
    /// [`ScriptType::P2pkhOrP2sh`], which is ambiguous and must not be resolved by guessing.
    pub const fn script_type(&self) -> ScriptType {
        self.version.script_type
    }

    pub const fn network(&self) -> KeyNetwork {
        self.version.network
    }

    /// The prefix as presented, case intact. `Ypub` never comes back as `ypub`.
    pub const fn prefix(&self) -> &'static str {
        self.version.prefix
    }

    /// Depth in the derivation tree. 0 is a master key, which is worth reporting: an account
    /// key is normally at depth 3.
    pub const fn depth(&self) -> u8 {
        self.xpub.depth
    }

    /// The key with BIP-32 version bytes, for derivation. Script type is **not** recoverable
    /// from this — use [`Self::script_type`].
    pub const fn as_xpub(&self) -> &Xpub {
        &self.xpub
    }
}

impl fmt::Debug for ExtendedKey {
    /// Redacts the key itself. A derived `Debug` would print the public key and chain code,
    /// which together are the user's whole wallet, and derived `Debug` is how that ends up
    /// in a log by accident. The same reasoning as `AcceptedInput`.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ExtendedKey")
            .field("prefix", &self.version.prefix)
            .field("network", &self.version.network)
            .field("script_type", &self.version.script_type)
            .field("depth", &self.xpub.depth)
            .field("key", &"<redacted>")
            .finish()
    }
}

/// Decode a bare extended public key.
///
/// Takes [`AcceptedInput`], so it cannot be reached with input that has not been through the
/// secret-material guard — that ordering is enforced by the type rather than by remembering
/// to call things in sequence.
///
/// # What this does that `Xpub::from_str` cannot
///
/// `rust-bitcoin` implements BIP-32, not SLIP-132: `Xpub::decode` accepts exactly two public
/// versions and rejects the other eight outright. So the version bytes are read against the
/// pinned registry first, the script type is kept, and only then are the bytes rewritten to
/// the BIP-32 version for that network so the body can be parsed by a library rather than by
/// hand.
///
/// Leading and trailing whitespace is trimmed. A pasted key routinely arrives with a
/// newline, and refusing that would send someone to a "not recognised" screen for a key that
/// is entirely valid. Nothing else about the input is normalised — in particular **case is
/// never folded**, because case is what distinguishes `ypub` from `Ypub`.
pub fn parse_extended_key(input: &AcceptedInput) -> Result<ExtendedKey, ExtendedKeyError> {
    // Zeroized on drop. Not because an xpub is secret — it is not, and refusing to hold one
    // would defeat the tool — but because it is the user's entire address history, and this
    // crate does not leave that in freed memory when the cost of not doing so is one wrapper.
    let decoded = Zeroizing::new(
        base58::decode_check(input.as_str().trim()).map_err(|_| ExtendedKeyError::NotBase58)?,
    );

    if decoded.len() != SERIALISED_LEN {
        return Err(ExtendedKeyError::WrongLength {
            actual: decoded.len(),
        });
    }

    let version: [u8; 4] = decoded
        .get(..4)
        .and_then(|slice| slice.try_into().ok())
        .ok_or(ExtendedKeyError::Malformed)?;

    let entry = lookup(version).ok_or(ExtendedKeyError::UnrecognisedVersion)?;

    // Before anything else is done with the bytes. Invariant 1 has no exception for a
    // private key that arrived by an unexpected route.
    if entry.is_private {
        return Err(ExtendedKeyError::ExtendedPrivateKey);
    }

    let standard = bip32_public_version(entry.network).ok_or(ExtendedKeyError::Malformed)?;

    let mut rewritten = Zeroizing::new(decoded.to_vec());
    rewritten
        .get_mut(..4)
        .ok_or(ExtendedKeyError::Malformed)?
        .copy_from_slice(&standard);

    // Checked on the wire format rather than on the parsed type, because it is the wire
    // format the standard describes — depth at byte 4, parent fingerprint at 5..9, child
    // number at 9..13 — and because it has to happen whether or not the dependency looks.
    let depth = *rewritten.get(4).ok_or(ExtendedKeyError::Malformed)?;
    let parent_fingerprint = rewritten.get(5..9).ok_or(ExtendedKeyError::Malformed)?;
    let child_number = rewritten.get(9..13).ok_or(ExtendedKeyError::Malformed)?;
    if depth == 0 && (parent_fingerprint != [0; 4] || child_number != [0; 4]) {
        return Err(ExtendedKeyError::InconsistentDepth);
    }

    let xpub = Xpub::decode(&rewritten).map_err(|_| ExtendedKeyError::Malformed)?;

    Ok(ExtendedKey {
        xpub,
        version: entry,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::parse::{guard_input, Refusal, SecretMaterial};

    /// One published BIP-32 vector, used as a carrier. Depth 0 with a zero parent
    /// fingerprint and zero index, so re-versioning it stays internally consistent.
    fn carrier() -> &'static str {
        include_str!("../../tests/fixtures/bip32-xpubs.txt")
            .lines()
            .next()
            .expect("fixture is not empty")
    }

    /// The carrier re-serialised under a different version. **Constructed, not a known
    /// answer** — no published vectors exist for the capitalised multisig forms or for the
    /// testnet ones, so these test the decoder rather than the standard.
    fn reversioned(version: [u8; 4]) -> String {
        let mut bytes = base58::decode_check(carrier()).expect("carrier decodes");
        bytes[..4].copy_from_slice(&version);
        base58::encode_check(&bytes)
    }

    #[test]
    fn every_public_version_decodes_to_its_registered_meaning() {
        for entry in SLIP132_VERSIONS.iter().filter(|e| !e.is_private) {
            let text = reversioned(entry.bytes);
            assert!(
                text.starts_with(entry.prefix),
                "re-versioning should produce the {} prefix",
                entry.prefix
            );

            let accepted = guard_input(&text).expect("a public key carries no secret material");
            let key = parse_extended_key(&accepted).expect("must decode");

            assert_eq!(key.script_type(), entry.script_type, "{}", entry.prefix);
            assert_eq!(key.network(), entry.network, "{}", entry.prefix);
            assert_eq!(key.prefix(), entry.prefix, "case must survive");
        }
    }

    #[test]
    fn the_guard_refuses_every_private_version_including_the_capitalised_ones() {
        // `ExtendedKeyError::ExtendedPrivateKey` cannot be reached through the public API:
        // producing an `AcceptedInput` requires passing `guard_input`, and `guard_input`
        // refuses these. That is the design — the parse-layer check is a second, independent
        // mechanism for the case where the first one fails — so what is testable here is
        // that the first one holds, for all ten forms rather than the six lowercase ones.
        for entry in SLIP132_VERSIONS.iter().filter(|e| e.is_private) {
            let text = reversioned(entry.bytes);
            let refusal = guard_input(&text).expect_err("must be refused");

            match refusal {
                Refusal::SecretMaterial(found) => assert!(
                    found.contains(SecretMaterial::ExtendedPrivateKey),
                    "{} was refused, but not as an extended private key",
                    entry.prefix
                ),
                other => panic!("{} refused for the wrong reason: {other:?}", entry.prefix),
            }
        }
    }

    #[test]
    fn an_unregistered_version_is_refused_rather_than_approximated() {
        // Litecoin's Ltub. Well-formed base58check, correct length, real registered version
        // — for a different chain. Mapping it to the nearest Bitcoin equivalent would report
        // on a wallet that does not exist on the network being checked.
        let text = reversioned([0x01, 0x9d, 0xa4, 0x62]);
        let accepted = guard_input(&text).expect("carries no secret material");
        assert!(matches!(
            parse_extended_key(&accepted),
            Err(ExtendedKeyError::UnrecognisedVersion)
        ));
    }

    #[test]
    fn bip32_public_versions_resolve_for_both_networks() {
        assert_eq!(
            bip32_public_version(KeyNetwork::Mainnet),
            Some([0x04, 0x88, 0xb2, 0x1e])
        );
        assert_eq!(
            bip32_public_version(KeyNetwork::Testnet),
            Some([0x04, 0x35, 0x87, 0xcf])
        );
    }

    #[test]
    fn debug_does_not_reveal_the_key() {
        let accepted = guard_input(carrier()).expect("public key");
        let key = parse_extended_key(&accepted).expect("decodes");
        let rendered = format!("{key:?}");

        assert!(rendered.contains("redacted"));

        // `get`, not a slice expression: `clippy::string_slice` is denied crate-wide because
        // indexing a string panics on a non-character boundary, and a lint that carves out
        // an exception for tests is a lint that stops being enforced.
        let chunk = carrier().get(10..40).expect("carrier is long enough");
        assert!(!rendered.contains(chunk));
    }

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

//! Output descriptor parsing.
//!
//! # A descriptor answers the question a bare key cannot
//!
//! `src/parse/extended_key.rs` exists because an extended key's version bytes are the only
//! thing that says what script type it is, and for `xpub`/`tpub` they do not say. A
//! descriptor states it outright — `wpkh(...)` is native segwit and nothing else — which is
//! why a descriptor is never asked what it is. The structured control that resolves script
//! type for a bare key must not appear for a descriptor: the input already answered.
//!
//! # SLIP-132 does not apply inside a descriptor
//!
//! BIP-380 defines descriptor key expressions in terms of BIP-32 serialisation. `zpub` and
//! friends are not valid inside one, and `miniscript` refuses them — correctly. So the
//! SLIP-132 table is for bare keys only, and a `wpkh(zpub…)` is a parse failure rather than
//! a script-type disagreement. It is a real thing users paste, so it gets its own error.

use core::fmt;

use miniscript::bitcoin::NetworkKind;
use miniscript::descriptor::{DescriptorType, ShInner, WshInner};
use miniscript::{Descriptor, DescriptorPublicKey, ForEachKey};

use super::extended_key::KeyNetwork;
use super::AcceptedInput;

/// The script type a descriptor declares. Unambiguous, unlike a bare `xpub`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum DescriptorShape {
    /// A raw script with no standard wrapper. Legal, and unusual enough to be worth saying.
    Bare,
    Pkh,
    Wpkh,
    ShWpkh,
    Sh,
    ShWsh,
    Wsh,
    ShSortedMulti,
    WshSortedMulti,
    ShWshSortedMulti,
    Tr,
}

impl DescriptorShape {
    const fn from_type(kind: DescriptorType) -> Self {
        match kind {
            DescriptorType::Bare => Self::Bare,
            DescriptorType::Pkh => Self::Pkh,
            DescriptorType::Wpkh => Self::Wpkh,
            DescriptorType::ShWpkh => Self::ShWpkh,
            DescriptorType::Sh => Self::Sh,
            DescriptorType::ShWsh => Self::ShWsh,
            DescriptorType::Wsh => Self::Wsh,
            DescriptorType::ShSortedMulti => Self::ShSortedMulti,
            DescriptorType::WshSortedMulti => Self::WshSortedMulti,
            DescriptorType::ShWshSortedMulti => Self::ShWshSortedMulti,
            DescriptorType::Tr => Self::Tr,
        }
    }

    /// Whether this shape is one of the sorted-multi forms, for which a threshold is
    /// recoverable. General miniscript thresholds require walking the AST and are not
    /// reported yet — see [`DescriptorFacts::threshold`].
    pub const fn is_sorted_multi(self) -> bool {
        matches!(
            self,
            Self::ShSortedMulti | Self::WshSortedMulti | Self::ShWshSortedMulti
        )
    }
}

/// Why a descriptor was not accepted. Carries no input — same rule as everywhere else here.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum DescriptorError {
    /// Did not parse as a descriptor at all.
    NotADescriptor,
    /// Parsed, but uses a SLIP-132 key. BIP-380 key expressions are BIP-32 serialised, so
    /// `zpub` and its relatives are not valid inside a descriptor even though this tool
    /// accepts them on their own. Users paste these, so the distinction is worth making
    /// rather than reporting a generic failure.
    Slip132KeyInDescriptor,
    /// Keys disagree about which network they belong to. A descriptor mixing mainnet and
    /// testnet keys describes a wallet that cannot exist, and picking a majority would be
    /// guessing about which addresses to check.
    MixedNetworks,
    /// Contains no key expression to derive from.
    NoKeys,
    /// Has keys, but none of them say which network. A descriptor written with plain public
    /// keys rather than extended ones carries no network anywhere, and defaulting to mainnet
    /// would mean checking mainnet addresses for a wallet that might not be on mainnet.
    ///
    /// Distinct from [`Self::NoKeys`] because "there are no keys" and "the keys do not say"
    /// are different facts, and the first would be a false statement about this input.
    IndeterminateNetwork,
    /// Parsed, but `miniscript`'s own sanity check rejected it — unsatisfiable, or beyond
    /// consensus or standardness limits.
    Unsound,
}

impl fmt::Display for DescriptorError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::NotADescriptor => f.write_str("that is not a descriptor this tool can read"),
            Self::Slip132KeyInDescriptor => f.write_str(
                "that descriptor uses a SLIP-132 key; descriptors need the xpub or tpub form \
                 of the same key",
            ),
            Self::MixedNetworks => f.write_str("that descriptor mixes mainnet and testnet keys"),
            Self::NoKeys => f.write_str("that descriptor contains no keys"),
            Self::IndeterminateNetwork => f.write_str(
                "that descriptor uses plain public keys, so it does not say which network \
                 it is for",
            ),
            Self::Unsound => f.write_str("that descriptor parsed but is not a spendable script"),
        }
    }
}

impl std::error::Error for DescriptorError {}

/// What a descriptor says about itself. Parse facts only — no tier, no judgement.
///
/// Everything here is read directly out of the descriptor. Nothing is inferred, and nothing
/// depends on network access or user self-report, which is what makes it safe to report
/// without hedging (`docs/spec.md` §6.0: arithmetic does not hedge).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DescriptorFacts {
    pub shape: DescriptorShape,
    pub network: KeyNetwork,
    /// Number of key expressions. For a sorted-multi this is the *n* of *k*-of-*n*.
    pub key_count: usize,
    /// The *k* of *k*-of-*n*, when recoverable.
    ///
    /// `None` for anything that is not a sorted-multi. A `wsh(multi(2,...))` written as
    /// general miniscript has a threshold too, but recovering it means walking the AST, and
    /// reporting `None` is honest where reporting `1` would be wrong.
    pub threshold: Option<usize>,
    /// Keys with a `/*` wildcard — the ones that describe a range of addresses rather than
    /// a single one.
    pub wildcard_keys: usize,
    /// Keys carrying `[fingerprint/path]` origin information. Its absence is not an error,
    /// but it is the difference between knowing where a key came from and assuming.
    pub keys_with_origin: usize,
    /// Keys written as a single public key rather than an extended one. These describe
    /// exactly one address and cannot be enumerated.
    pub single_keys: usize,
}

/// A parsed descriptor, and the facts read from it.
#[derive(Clone)]
pub struct ParsedDescriptor {
    descriptor: Descriptor<DescriptorPublicKey>,
    facts: DescriptorFacts,
}

impl fmt::Debug for ParsedDescriptor {
    /// Redacts the descriptor, prints the facts.
    ///
    /// A derived `Debug` would render the descriptor in full — every key, every path — which
    /// is the user's entire wallet, and derived `Debug` is how that reaches a log without
    /// anyone deciding it should. The facts are safe: shapes and counts, no key material.
    /// Same reasoning as `ExtendedKey` and `AcceptedInput`.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ParsedDescriptor")
            .field("facts", &self.facts)
            .field("descriptor", &"<redacted>")
            .finish()
    }
}

impl ParsedDescriptor {
    pub const fn facts(&self) -> &DescriptorFacts {
        &self.facts
    }

    /// The descriptor itself, for derivation. Deliberately not `Display`ed anywhere by this
    /// type: rendering it reproduces the user's wallet, which is the thing errors and logs
    /// must never carry.
    pub const fn as_descriptor(&self) -> &Descriptor<DescriptorPublicKey> {
        &self.descriptor
    }
}

/// SLIP-132 prefixes that are valid on their own and invalid inside a descriptor.
///
/// `xpub` and `tpub` are absent because those are the BIP-32 forms BIP-380 actually allows.
const NON_BIP32_PUBLIC_PREFIXES: [&str; 8] = [
    "ypub", "zpub", "Ypub", "Zpub", "upub", "vpub", "Upub", "Vpub",
];

const fn network_of(kind: NetworkKind) -> KeyNetwork {
    match kind {
        NetworkKind::Main => KeyNetwork::Mainnet,
        NetworkKind::Test => KeyNetwork::Testnet,
    }
}

/// Parse a descriptor.
///
/// Takes [`AcceptedInput`], so the secret-material guard has already run. A descriptor
/// carrying an extended private key is refused there, and `DescriptorPublicKey` would refuse
/// it here too — two independent mechanisms, which is the intent.
pub fn parse_descriptor(input: &AcceptedInput) -> Result<ParsedDescriptor, DescriptorError> {
    let text = input.as_str().trim();

    let descriptor = match text.parse::<Descriptor<DescriptorPublicKey>>() {
        Ok(descriptor) => descriptor,
        Err(_) => {
            // Distinguish the case users actually hit. Checked only on the failure path, so
            // a valid descriptor never pays for it, and checked on the original case because
            // `Zpub` and `zpub` are different keys.
            return Err(
                if NON_BIP32_PUBLIC_PREFIXES.iter().any(|p| text.contains(p)) {
                    DescriptorError::Slip132KeyInDescriptor
                } else {
                    DescriptorError::NotADescriptor
                },
            );
        }
    };

    descriptor
        .sanity_check()
        .map_err(|_| DescriptorError::Unsound)?;

    let mut key_count = 0usize;
    let mut wildcard_keys = 0usize;
    let mut keys_with_origin = 0usize;
    let mut single_keys = 0usize;
    let mut networks: Vec<KeyNetwork> = Vec::new();

    descriptor.for_each_key(|key| {
        key_count += 1;
        if key.has_wildcard() {
            wildcard_keys += 1;
        }
        match key {
            DescriptorPublicKey::Single(single) => {
                single_keys += 1;
                if single.origin.is_some() {
                    keys_with_origin += 1;
                }
            }
            DescriptorPublicKey::XPub(xkey) => {
                if xkey.origin.is_some() {
                    keys_with_origin += 1;
                }
                networks.push(network_of(xkey.xkey.network));
            }
            DescriptorPublicKey::MultiXPub(multi) => {
                if multi.origin.is_some() {
                    keys_with_origin += 1;
                }
                networks.push(network_of(multi.xkey.network));
            }
        }
        true
    });

    if key_count == 0 {
        return Err(DescriptorError::NoKeys);
    }

    // A descriptor of bare public keys carries no network at all. Reporting one would be
    // inventing it, so it is refused rather than defaulted to mainnet — defaulting here
    // would mean checking mainnet addresses for a wallet that might be testnet.
    let first = *networks
        .first()
        .ok_or(DescriptorError::IndeterminateNetwork)?;
    if networks.iter().any(|n| *n != first) {
        return Err(DescriptorError::MixedNetworks);
    }

    let shape = DescriptorShape::from_type(descriptor.desc_type());

    Ok(ParsedDescriptor {
        facts: DescriptorFacts {
            shape,
            network: first,
            key_count,
            threshold: sorted_multi_threshold(&descriptor),
            wildcard_keys,
            keys_with_origin,
            single_keys,
        },
        descriptor,
    })
}

/// The *k* of a sorted-multi, or `None`.
///
/// Reads it from the descriptor rather than from the rendered string. Parsing the number out
/// of `sortedmulti(2,` would be a second parser for a format that is already parsed.
fn sorted_multi_threshold(descriptor: &Descriptor<DescriptorPublicKey>) -> Option<usize> {
    match descriptor {
        // sh(wsh(sortedmulti(...))) nests, and is the common form for legacy-compatible
        // multisig. Missing the nested case would report `None` for exactly the descriptors
        // a threshold matters most for.
        Descriptor::Sh(sh) => match sh.as_inner() {
            ShInner::SortedMulti(sorted) => Some(sorted.k()),
            ShInner::Wsh(wsh) => match wsh.as_inner() {
                WshInner::SortedMulti(sorted) => Some(sorted.k()),
                WshInner::Ms(_) => None,
            },
            ShInner::Wpkh(_) | ShInner::Ms(_) => None,
        },
        Descriptor::Wsh(wsh) => match wsh.as_inner() {
            WshInner::SortedMulti(sorted) => Some(sorted.k()),
            WshInner::Ms(_) => None,
        },
        Descriptor::Bare(_) | Descriptor::Pkh(_) | Descriptor::Wpkh(_) | Descriptor::Tr(_) => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::parse::guard_input;
    use miniscript::bitcoin::base58;

    /// A published mainnet xpub, re-serialised as `tpub`. Constructed: no testnet vectors
    /// are vendored, and the point here is the network field rather than the key.
    fn as_tpub(mainnet_xpub: &str) -> String {
        let mut bytes = base58::decode_check(mainnet_xpub).expect("vector decodes");
        bytes[..4].copy_from_slice(&[0x04, 0x35, 0x87, 0xcf]);
        base58::encode_check(&bytes)
    }

    fn xpub() -> &'static str {
        include_str!("../../tests/fixtures/bip32-xpubs.txt")
            .lines()
            .next()
            .expect("fixture is not empty")
    }

    fn facts(text: &str) -> Result<DescriptorFacts, DescriptorError> {
        let accepted = guard_input(text).expect("no secret material");
        parse_descriptor(&accepted).map(|parsed| parsed.facts.clone())
    }

    #[test]
    fn a_testnet_descriptor_reports_testnet() {
        let tpub = as_tpub(xpub());
        let facts = facts(&format!("wpkh({tpub}/0/*)")).expect("parses");
        assert_eq!(facts.network, KeyNetwork::Testnet);
    }

    #[test]
    fn mixing_mainnet_and_testnet_keys_is_refused() {
        // Such a wallet cannot exist. Picking a majority would be guessing which chain's
        // addresses to check, and the answer decides where the user looks for their coins.
        let mainnet = xpub();
        let testnet = as_tpub(mainnet);
        let descriptor = format!("wsh(sortedmulti(2,{mainnet}/0/*,{testnet}/0/*))");

        assert_eq!(facts(&descriptor), Err(DescriptorError::MixedNetworks));
    }

    #[test]
    fn plain_public_keys_carry_no_network_and_are_not_reported_as_keyless() {
        // 33-byte compressed public key, no extended key anywhere, so nothing in the
        // descriptor says which network it is for. It has a key, so NoKeys would be a false
        // statement about this input — the distinction the error variants exist to make.
        let pubkey = "020000000000000000000000000000000000000000000000000000000000000001";
        match facts(&format!("wpkh({pubkey})")) {
            Err(DescriptorError::IndeterminateNetwork) => {}
            Err(DescriptorError::NotADescriptor) => {
                // miniscript may reject this key outright as not on the curve, which is also
                // a correct refusal. Either way it must not be reported as keyless.
            }
            other => panic!("unexpected outcome: {other:?}"),
        }
    }
}

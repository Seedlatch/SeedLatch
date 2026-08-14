//! Address enumeration, and the gap limit that bounds it.
//!
//! # Scope, stated because the neighbouring one is blocked
//!
//! This is enumeration of **the user's own wallet**, to look up balances for addresses they
//! already own. `CLAUDE.md` blocks *tripwire* work — path derivation for funded canary
//! addresses, and the monitoring around it — pending independent review. That is a different
//! activity that happens to share a verb. Nothing here funds, monitors or alerts.
//!
//! # Two things this module deliberately cannot do
//!
//! **A bare multisig key cannot be enumerated at all.** A `Ypub` or `Zpub` is one cosigner
//! of a multi-signature wallet. Addresses depend on every cosigner key and on the threshold,
//! so a single one of them determines nothing — and picking a plausible completion would
//! produce addresses belonging to no wallet at all. It is refused, and the user needs the
//! full descriptor.
//!
//! **A bare `xpub` cannot be enumerated without being told the script type.** SLIP-132
//! records `xpub` as "P2PKH or P2SH", and BIP-49's original draft kept the `xpub` prefix for
//! nested segwit, so the same key really is used for several script types in the wild. The
//! caller supplies the answer; this module will not guess one.
//!
//! Both refusals are the same rule as everywhere else here: derive nothing that the input
//! does not determine, because the failure mode is checking a wallet the user does not own
//! and telling them what is in it.

use core::fmt;

use miniscript::bitcoin::secp256k1::{Secp256k1, VerifyOnly};
use miniscript::bitcoin::{Address, Network};
use miniscript::{Descriptor, DescriptorPublicKey};

use crate::parse::descriptor::ParsedDescriptor;
use crate::parse::extended_key::{ExtendedKey, ScriptType};

/// Consecutive unused addresses that end a scan.
///
/// Twenty, from `CLAUDE.md` §Network. It is a convention rather than a law — a wallet that
/// skipped further ahead would have funds past the gap — but scanning further costs the
/// endpoint operator more requests and tells them more about the wallet, and an unbounded
/// scan against a public instance is the thing the limit exists to prevent.
pub const GAP_LIMIT: u32 = 20;

/// Indices resolved per round.
///
/// **A round is not one request.** Esplora has no bulk address endpoint — `/address/:address`
/// takes exactly one address, verified against its published API — so a round of twenty is
/// twenty HTTP requests. What batching buys is deciding *once* whether to continue, rather
/// than issuing one request, waiting, and deciding twenty times; an empty chain is then one
/// round of twenty parallel-capped requests instead of twenty sequential round trips.
///
/// An earlier version of this note claimed a round was a single round trip. It is not, and
/// the difference matters: it is the number that has to be weighed against the endpoint's
/// capacity, and it is twenty times larger than that claim implied.
pub const BATCH_SIZE: u32 = GAP_LIMIT;

/// Hard ceiling on addresses examined per chain, whatever the gap says.
///
/// A wallet with continuous history longer than this exists, and for it the scan is
/// incomplete — which the report must say rather than quietly presenting a partial answer.
/// The alternative is an unbounded loop against someone else's server.
pub const MAX_ADDRESSES_PER_CHAIN: u32 = 1000;

/// Which chain of a wallet — the two BIP-44 defines below the account level.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Chain {
    /// Addresses handed out to receive payments. `0`.
    External,
    /// Addresses the wallet pays change back to. `1`.
    ///
    /// Scanned as well as the external chain, because a wallet whose receive addresses look
    /// empty can still hold its entire balance in change.
    Internal,
}

impl Chain {
    pub const fn index(self) -> u32 {
        match self {
            Self::External => 0,
            Self::Internal => 1,
        }
    }

    pub const fn key(self) -> &'static str {
        match self {
            Self::External => "external",
            Self::Internal => "internal",
        }
    }

    pub const BOTH: [Self; 2] = [Self::External, Self::Internal];
}

/// A single-signature script type, which is the only kind a bare key can be enumerated as.
///
/// Separate from [`ScriptType`] on purpose: that enum describes what a SLIP-132 version says,
/// including the multisig forms, and this one describes what can actually be turned into
/// addresses from one key. The gap between them is not an oversight, it is the reason a bare
/// `Zpub` is refused.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum SingleSigScript {
    /// Legacy `pkh(...)`.
    Pkh,
    /// Nested segwit `sh(wpkh(...))`.
    ShWpkh,
    /// Native segwit `wpkh(...)`.
    Wpkh,
    /// Taproot `tr(...)`.
    Tr,
}

impl SingleSigScript {
    /// The descriptor function this script type is written with.
    const fn wrap(self) -> (&'static str, &'static str) {
        match self {
            Self::Pkh => ("pkh(", ")"),
            Self::ShWpkh => ("sh(wpkh(", "))"),
            Self::Wpkh => ("wpkh(", ")"),
            Self::Tr => ("tr(", ")"),
        }
    }

    pub const fn key(self) -> &'static str {
        match self {
            Self::Pkh => "pkh",
            Self::ShWpkh => "sh_wpkh",
            Self::Wpkh => "wpkh",
            Self::Tr => "tr",
        }
    }

    /// The script type a SLIP-132 version determines on its own, if it determines one.
    ///
    /// `None` for `xpub`/`tpub`, which SLIP-132 records as ambiguous, and `None` for the
    /// capitalised multisig forms, which determine a script type but not a wallet. In both
    /// cases the caller must supply more than the key carries.
    pub const fn implied_by(script_type: ScriptType) -> Option<Self> {
        match script_type {
            ScriptType::P2wpkhInP2sh => Some(Self::ShWpkh),
            ScriptType::P2wpkh => Some(Self::Wpkh),
            ScriptType::P2pkhOrP2sh
            | ScriptType::MultisigP2wshInP2sh
            | ScriptType::MultisigP2wsh => None,
        }
    }
}

/// Why addresses could not be produced.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum DeriveError {
    /// The key is one cosigner of a multisig wallet. Its addresses depend on the other
    /// cosigners and the threshold, neither of which a single key carries.
    MultisigKeyAlone,
    /// The descriptor has no wildcard, so it describes exactly one address and there is
    /// nothing to enumerate.
    NotEnumerable,
    /// The descriptor does not describe the requested chain.
    ///
    /// `wpkh(xpub/0/*)` covers one chain. `wpkh(xpub/<0;1>/*)` covers two. Asking a
    /// single-path descriptor for its change chain has no answer, and **substituting the one
    /// it does have is the dangerous option**: the caller would scan the same chain twice,
    /// double the requests against a rate-limited endpoint, and report change as checked
    /// when it was never looked at. A missed balance that looks examined is worse than a
    /// refusal that says so.
    ChainNotInDescriptor,
    /// The descriptor cannot be turned into an address — a `bare(...)` script has no
    /// address form.
    NoAddressForm,
    /// The index is beyond what BIP-32 allows for a non-hardened step.
    IndexOutOfRange,
    /// Derivation failed inside the library.
    Underivable,
}

impl DeriveError {
    pub const fn key(&self) -> &'static str {
        match self {
            Self::MultisigKeyAlone => "multisig_key_alone",
            Self::NotEnumerable => "not_enumerable",
            Self::ChainNotInDescriptor => "chain_not_in_descriptor",
            Self::NoAddressForm => "no_address_form",
            Self::IndexOutOfRange => "index_out_of_range",
            Self::Underivable => "underivable",
        }
    }
}

impl fmt::Display for DeriveError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::MultisigKeyAlone => f.write_str(
                "that key is one signer of a multi-signature wallet; its addresses depend on \
                 the other keys too, so the full descriptor is needed",
            ),
            Self::NotEnumerable => {
                f.write_str("that describes a single address, so there is nothing to scan")
            }
            Self::ChainNotInDescriptor => f.write_str(
                "that descriptor covers only one chain, so there is no change chain to scan",
            ),
            Self::NoAddressForm => f.write_str("that script has no address form"),
            Self::IndexOutOfRange => f.write_str("that address index is out of range"),
            Self::Underivable => f.write_str("addresses could not be derived from that"),
        }
    }
}

impl std::error::Error for DeriveError {}

/// Everything needed to produce addresses for one wallet.
///
/// Holds one secp256k1 context for the life of the scan. Constructing one per address is the
/// obvious mistake: it is expensive, and in a 32-bit WASM heap it is expensive in the
/// dimension that runs out first.
pub struct AddressPlan {
    /// One entry per chain the descriptor covers, expanded **once** at construction.
    ///
    /// A multipath `<0;1>` descriptor expands to two; a single-path one to a single entry.
    /// Expanding per address meant cloning the descriptor and re-expanding it on every
    /// lookup — forty times for one empty wallet, and in a 32-bit WASM heap that is churn in
    /// the dimension that runs out first.
    paths: Vec<Descriptor<DescriptorPublicKey>>,
    network: Network,
    secp: Secp256k1<VerifyOnly>,
}

impl fmt::Debug for AddressPlan {
    /// Redacts. The descriptor is every key and path the user owns.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("AddressPlan")
            .field("network", &self.network)
            .field("descriptor", &"<redacted>")
            .finish()
    }
}

impl AddressPlan {
    /// From a descriptor the user supplied. The script type is whatever the descriptor says.
    pub fn from_descriptor(parsed: &ParsedDescriptor) -> Result<Self, DeriveError> {
        let facts = parsed.facts();
        if facts.wildcard_keys == 0 {
            return Err(DeriveError::NotEnumerable);
        }
        Ok(Self {
            paths: expand(parsed.as_descriptor())?,
            network: facts.network.network(),
            secp: Secp256k1::verification_only(),
        })
    }

    /// From a bare extended key, with the script type supplied by the caller.
    ///
    /// The caller must resolve ambiguity rather than this function guessing it — see
    /// [`SingleSigScript::implied_by`], which returns `None` exactly when a choice is needed.
    ///
    /// The descriptor is built by formatting and re-parsing rather than by assembling one by
    /// hand. That routes it through the same vetted parser every other descriptor goes
    /// through, so a mistake produces a parse failure here instead of a subtly wrong wallet
    /// later.
    pub fn from_key(key: &ExtendedKey, script: SingleSigScript) -> Result<Self, DeriveError> {
        if key.script_type().is_multisig() {
            return Err(DeriveError::MultisigKeyAlone);
        }

        let (open, close) = script.wrap();
        // The key serialises with BIP-32 version bytes, which is what a descriptor requires.
        // `<0;1>` is the multipath form: one descriptor covering both chains.
        let text = format!("{open}{}/<0;1>/*{close}", key.as_xpub());

        let descriptor = text
            .parse::<Descriptor<DescriptorPublicKey>>()
            .map_err(|_| DeriveError::Underivable)?;

        Ok(Self {
            paths: expand(&descriptor)?,
            network: key.network().network(),
            secp: Secp256k1::verification_only(),
        })
    }

    /// The address at a position, or why there isn't one.
    ///
    /// A chain the descriptor does not cover is [`DeriveError::ChainNotInDescriptor`], never
    /// a substitution. An earlier version returned the only path it had whenever there was
    /// just one, so `wpkh(xpub/0/*)` answered both chains with the same address — the
    /// scanner would have queried it twice and reported change as checked without looking.
    pub fn address(&self, chain: Chain, index: u32) -> Result<Address, DeriveError> {
        let chosen = self
            .paths
            .get(chain.index() as usize)
            .ok_or(DeriveError::ChainNotInDescriptor)?;

        chosen
            .at_derivation_index(index)
            .map_err(|_| DeriveError::IndexOutOfRange)?
            .derived_descriptor(&self.secp)
            .address(self.network)
            .map_err(|_| DeriveError::NoAddressForm)
    }

    /// How many chains this plan covers. A single-path descriptor covers one.
    ///
    /// A caller scanning "both chains" must read this rather than assuming two: for a
    /// one-chain descriptor there is no change chain to scan, and [`Self::address`] will say
    /// so rather than answering with the chain it does have.
    pub fn chain_count(&self) -> usize {
        self.paths.len()
    }

    /// The chains this plan can actually produce addresses for.
    pub fn chains(&self) -> impl Iterator<Item = Chain> + '_ {
        Chain::BOTH
            .into_iter()
            .take(self.paths.len().min(Chain::BOTH.len()))
    }
}

/// Expand a descriptor into one entry per chain, once.
fn expand(
    descriptor: &Descriptor<DescriptorPublicKey>,
) -> Result<Vec<Descriptor<DescriptorPublicKey>>, DeriveError> {
    let paths = descriptor
        .clone()
        .into_single_descriptors()
        .map_err(|_| DeriveError::Underivable)?;

    if paths.is_empty() {
        return Err(DeriveError::Underivable);
    }
    Ok(paths)
}

/// The gap-limit policy, as a state machine with no network in it.
///
/// Separated from the lookups on purpose: this is the part with the rules, and it is
/// testable by feeding it used/unused patterns. Anything that talks to an endpoint can then
/// be a thin loop around it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GapScan {
    next: u32,
    unused_run: u32,
    issued: Option<(u32, u32)>,
    complete: bool,
    truncated: bool,
}

impl Default for GapScan {
    fn default() -> Self {
        Self::new()
    }
}

impl GapScan {
    pub const fn new() -> Self {
        Self {
            next: 0,
            unused_run: 0,
            issued: None,
            complete: false,
            truncated: false,
        }
    }

    /// The next indices to look up, as `(start, count)`, or `None` when the scan is done.
    ///
    /// Returns the same batch again if [`Self::record`] has not been called for it, so a
    /// dropped response cannot advance the scan past addresses that were never checked.
    pub fn next_batch(&mut self) -> Option<(u32, u32)> {
        if self.complete {
            return None;
        }
        if let Some(batch) = self.issued {
            return Some(batch);
        }

        let remaining = MAX_ADDRESSES_PER_CHAIN.saturating_sub(self.next);
        if remaining == 0 {
            self.complete = true;
            self.truncated = true;
            return None;
        }

        // Ask for exactly what could still close the gap, never a fixed twenty.
        //
        // A fixed batch overshoots: with one used address at index 0, the gap closes at 21,
        // and a second full round examined 40 — nineteen requests that could not change any
        // outcome. Two chains and several candidate script types multiply that into roughly
        // a hundred and fifty needless requests against someone else's server.
        //
        // `GAP_LIMIT - unused_run` is the smallest number that could possibly end the scan.
        // If any of them turn out to be used the run resets and the next round asks again,
        // so the request count is minimal and the number of rounds is bounded by the number
        // of used addresses rather than by the range.
        let needed = GAP_LIMIT.saturating_sub(self.unused_run).max(1);
        let batch = (self.next, needed.min(BATCH_SIZE).min(remaining));
        self.issued = Some(batch);
        Some(batch)
    }

    /// Record results for the batch just issued, in index order.
    ///
    /// `used[i]` is whether the address at `start + i` has any history. Extra results are
    /// ignored and a short slice records only what it covers, so a truncated response
    /// cannot mark unexamined addresses as unused.
    pub fn record(&mut self, used: &[bool]) {
        let Some((start, count)) = self.issued.take() else {
            return;
        };

        let covered = used.len().min(count as usize);
        for &is_used in used.iter().take(covered) {
            if is_used {
                self.unused_run = 0;
            } else {
                self.unused_run += 1;
            }
        }

        self.next = start.saturating_add(u32::try_from(covered).unwrap_or(u32::MAX).min(count));

        if self.unused_run >= GAP_LIMIT {
            self.complete = true;
        }
        if self.next >= MAX_ADDRESSES_PER_CHAIN {
            self.complete = true;
            self.truncated = true;
        }
    }

    pub const fn is_complete(&self) -> bool {
        self.complete
    }

    /// Whether the scan stopped at the ceiling rather than at the gap.
    ///
    /// A truncated scan has not proved the wallet ends where it stopped looking, and the
    /// report has to say so rather than presenting a partial answer as a whole one.
    pub const fn is_truncated(&self) -> bool {
        self.truncated
    }

    /// Addresses examined so far.
    pub const fn examined(&self) -> u32 {
        self.next
    }
}

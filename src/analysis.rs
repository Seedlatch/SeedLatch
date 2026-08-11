//! The single entry point: guard, then parse, in one call.
//!
//! # Why this is one function rather than two
//!
//! The interim `check` ran the guard and stopped, which left the accepted branch with
//! nowhere to go — so the frontend would have had to take the value back into JavaScript and
//! pass it in again to be parsed. That is two crossings and a JavaScript-held copy of the
//! user's complete address and balance history, which is exactly what `parse` tells the
//! frontend not to do. [`analyse`] crosses once: input goes in, facts come out, and the
//! input never comes back.
//!
//! # Why the logic is here and not in `src/wasm.rs`
//!
//! `src/wasm.rs` is `cfg(target_arch = "wasm32")`, and building for wasm32 needs a clang
//! that can emit wasm — which this crate's `secp256k1-sys` dependency requires and which not
//! every development machine has. On a machine without it the browser boundary cannot be
//! compiled at all, so anything living there is verified only by CI.
//!
//! So everything decidable lives here, where `cargo test` reaches it, and `wasm.rs` is left
//! with nothing but the conversion into flat wasm-bindgen fields. That is not a style
//! preference: it is the difference between logic covered by 100+ assertions and logic whose
//! first compile happens on a push.

use crate::parse::descriptor::{
    parse_descriptor, DescriptorError, DescriptorFacts, ParsedDescriptor,
};
use crate::parse::extended_key::{
    parse_extended_key, ExtendedKey, ExtendedKeyError, KeyNetwork, ScriptType,
};
use crate::parse::{guard_input, Refusal};

/// What a bare extended public key says about itself.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct KeyFacts {
    /// The SLIP-132 prefix as presented, case intact.
    pub prefix: &'static str,
    pub network: KeyNetwork,
    pub script_type: ScriptType,
    /// Depth in the derivation tree. 0 is a master key; an account key is normally 3.
    pub depth: u8,
    /// True when the version bytes do not determine the script type — `xpub` and `tpub`,
    /// which SLIP-132 records as "P2PKH or P2SH".
    ///
    /// The frontend must ask the user when this is set, and must never guess: choosing
    /// wrongly derives addresses they do not own. A descriptor never sets it, because a
    /// descriptor states its script type outright.
    pub script_type_ambiguous: bool,
}

/// Passed the guard, but could not be read.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Unreadable {
    /// Routed to the bare-key parser and refused there.
    Key(ExtendedKeyError),
    /// Routed to the descriptor parser and refused there.
    Descriptor(DescriptorError),
}

/// The outcome of analysing an input. Carries facts, never the input.
#[derive(Debug, Clone)]
pub enum Analysis {
    /// Refused before anything was parsed — secret material, or too large to examine.
    Refused(Refusal),
    /// Accepted by the guard and then not readable as either form.
    Unreadable(Unreadable),
    /// A bare extended public key.
    Key(KeyFacts),
    /// An output descriptor. Carries the parsed descriptor, which derivation will need.
    Descriptor(Box<ParsedDescriptor>),
}

impl Analysis {
    /// The descriptor facts, when this is a descriptor.
    pub fn descriptor_facts(&self) -> Option<&DescriptorFacts> {
        match self {
            Self::Descriptor(parsed) => Some(parsed.facts()),
            _ => None,
        }
    }
}

fn facts_of(key: &ExtendedKey) -> KeyFacts {
    KeyFacts {
        prefix: key.prefix(),
        network: key.network(),
        script_type: key.script_type(),
        depth: key.depth(),
        script_type_ambiguous: key.script_type() == ScriptType::P2pkhOrP2sh,
    }
}

/// Guard the input, then read it. One crossing, one call.
///
/// # Routing
///
/// Every descriptor form is a function call — `wpkh(…)`, `sh(…)`, `tr(…)`, `addr(…)`,
/// `raw(…)` — and a bare extended key contains no parentheses at all. So the presence of `(`
/// decides which parser runs.
///
/// The alternative, trying one and falling back to the other, reports whichever error came
/// last rather than the one that matches what the user pasted: a mistyped descriptor would
/// be told it is not a valid extended key. Routing first means the refusal names the thing
/// they were actually trying to give us.
pub fn analyse(raw: &str) -> Analysis {
    let accepted = match guard_input(raw) {
        Ok(accepted) => accepted,
        Err(refusal) => return Analysis::Refused(refusal),
    };

    if accepted.as_str().trim().contains('(') {
        match parse_descriptor(&accepted) {
            Ok(parsed) => Analysis::Descriptor(Box::new(parsed)),
            Err(error) => Analysis::Unreadable(Unreadable::Descriptor(error)),
        }
    } else {
        match parse_extended_key(&accepted) {
            Ok(key) => Analysis::Key(facts_of(&key)),
            Err(error) => Analysis::Unreadable(Unreadable::Key(error)),
        }
    }
}

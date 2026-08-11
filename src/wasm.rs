//! The browser boundary.
//!
//! Compiled only for `wasm32`. Native builds — including the whole test suite — do not carry
//! `wasm-bindgen`, which keeps `cargo audit` on the native path honest about what the tests
//! actually compile.
//!
//! # What crosses this boundary
//!
//! Input goes **in**. Facts come **out**. The input never comes back. [`AnalysisResult`] has
//! nowhere to put a value, which is deliberate: JavaScript is where a copy becomes
//! unreachable, since JS strings are immutable and garbage-collected and neither this crate
//! nor the frontend can force a collection.
//!
//! # This file contains no decisions, on purpose
//!
//! Building for wasm32 requires a clang that can emit wasm, because `secp256k1-sys` vendors
//! libsecp256k1 as C. A development machine without one cannot compile this file at all — so
//! every line here is verified for the first time by CI, on a push.
//!
//! Everything decidable therefore lives in [`crate::analysis`], where `cargo test` reaches
//! it. What is left is a conversion from a typed enum into flat fields, with no branching
//! that is not exhaustive over that enum. When this file needs logic, that is the signal to
//! put the logic in `analysis` and call it from here.
//!
//! # Why the fields are flat and stringly typed
//!
//! `wasm-bindgen` does not carry data-bearing enums across the boundary. So each variant's
//! payload is spread across fields that are populated only for that variant, and the variant
//! itself is a string. The TypeScript side narrows them. Field names are single words
//! wherever possible, because multi-word Rust names arrive camelCased and the mapping is one
//! more thing to get wrong.

use wasm_bindgen::prelude::*;

use crate::analysis::{analyse as analyse_input, Analysis, Unreadable};
use crate::parse::Refusal;

/// One category of secret material. Carries no value, by construction.
#[wasm_bindgen(getter_with_clone)]
#[derive(Debug, Clone)]
pub struct DetectedCategory {
    /// Stable identifier — `bip39_mnemonic`, `extended_private_key`, `wif_private_key`,
    /// `raw_hex_private_key`. Switch on this, not on the label.
    pub key: String,
    /// Reviewed user-facing wording. Drafted in `docs/spec.md` §6.1. Changes when copy does.
    pub label: String,
}

/// The outcome of analysing an input.
#[wasm_bindgen(getter_with_clone)]
#[derive(Debug, Clone, Default)]
pub struct AnalysisResult {
    /// `""` when the input was read. Otherwise `"secret_material"`, `"too_large"` or
    /// `"unreadable"`.
    pub refusal: String,
    /// Populated only for `"secret_material"`.
    pub categories: Vec<DetectedCategory>,
    /// Populated only for `"too_large"`. Bytes.
    pub limit: u32,
    /// Populated only for `"too_large"`. Bytes.
    pub size: u32,
    /// Populated only for `"unreadable"`: a stable machine key for why, such as
    /// `not_base58` or `slip132_key_in_descriptor`. Never the input.
    pub reason: String,

    /// `"key"` or `"descriptor"` — which of the two the input was read as, or, when
    /// `refusal` is `"unreadable"`, which parser it was routed to and refused by.
    ///
    /// Empty only when the guard refused before any parser ran, since in that case no
    /// routing decision was made and claiming one would be inventing it.
    pub form: String,
    /// `"mainnet"` or `"testnet"`. Empty unless something was read.
    pub network: String,
    /// For a key, the script type (`p2wpkh`, …). For a descriptor, the shape (`wsh_sortedmulti`, …).
    pub shape: String,

    /// Key only: the SLIP-132 prefix as presented, case intact.
    pub prefix: String,
    /// Key only: depth in the derivation tree. 0 is a master key.
    pub depth: u32,
    /// **Key only, and the frontend must act on it.** True when the version bytes do not
    /// determine the script type — `xpub` and `tpub`. The user has to be asked; guessing
    /// derives addresses they do not own. Never true for a descriptor, which states its
    /// script type outright, so the question must not be shown for one.
    pub ask: bool,

    /// Descriptor only: number of key expressions. The *n* of *k*-of-*n*.
    pub keys: u32,
    /// Descriptor only: the *k* of *k*-of-*n*, or **0 when not recoverable**.
    ///
    /// A real threshold is at least 1, so 0 is unambiguous as "unknown". General miniscript
    /// thresholds are not recovered yet, and reporting 1 for them would let a 2-of-3 read as
    /// a single point of failure.
    pub threshold: u32,
    /// Descriptor only: keys carrying a `/*` wildcard.
    pub wildcards: u32,
    /// Descriptor only: keys carrying `[fingerprint/path]` origin information.
    pub origins: u32,
    /// Descriptor only: keys written as a plain public key rather than an extended one.
    pub singles: u32,
}

#[wasm_bindgen]
impl AnalysisResult {
    /// Whether the input was read. Convenience for the common branch.
    #[wasm_bindgen(getter)]
    pub fn accepted(&self) -> bool {
        self.refusal.is_empty()
    }
}

fn clamp(value: usize) -> u32 {
    u32::try_from(value).unwrap_or(u32::MAX)
}

/// Guard the input and read it, in one crossing.
///
/// Call this and nothing else. On any non-empty `refusal` the caller must clear the field
/// and show the blocking interstitial; `docs/spec.md` §6.1 has the copy, and the size
/// refusal deliberately reports no categories because nothing was examined.
#[wasm_bindgen]
pub fn analyse(input: &str) -> AnalysisResult {
    match analyse_input(input) {
        Analysis::Refused(Refusal::SecretMaterial(found)) => AnalysisResult {
            refusal: String::from("secret_material"),
            categories: found
                .categories()
                .iter()
                .map(|category| DetectedCategory {
                    key: category.key().to_owned(),
                    label: category.label().to_owned(),
                })
                .collect(),
            ..AnalysisResult::default()
        },

        Analysis::Refused(Refusal::TooLarge {
            limit_bytes,
            actual_bytes,
        }) => AnalysisResult {
            refusal: String::from("too_large"),
            limit: clamp(limit_bytes),
            size: clamp(actual_bytes),
            ..AnalysisResult::default()
        },

        Analysis::Unreadable(unreadable) => AnalysisResult {
            refusal: String::from("unreadable"),
            reason: String::from(match &unreadable {
                Unreadable::Key(error) => error.key(),
                Unreadable::Descriptor(error) => error.key(),
            }),
            form: String::from(match &unreadable {
                Unreadable::Key(_) => "key",
                Unreadable::Descriptor(_) => "descriptor",
            }),
            ..AnalysisResult::default()
        },

        Analysis::Key(facts) => AnalysisResult {
            form: String::from("key"),
            network: String::from(facts.network.key()),
            shape: String::from(facts.script_type.key()),
            prefix: String::from(facts.prefix),
            depth: u32::from(facts.depth),
            ask: facts.script_type_ambiguous,
            ..AnalysisResult::default()
        },

        Analysis::Descriptor(parsed) => {
            let facts = parsed.facts();
            AnalysisResult {
                form: String::from("descriptor"),
                network: String::from(facts.network.key()),
                shape: String::from(facts.shape.key()),
                keys: clamp(facts.key_count),
                threshold: facts.threshold.map_or(0, clamp),
                wildcards: clamp(facts.wildcard_keys),
                origins: clamp(facts.keys_with_origin),
                singles: clamp(facts.single_keys),
                ..AnalysisResult::default()
            }
        }
    }
}

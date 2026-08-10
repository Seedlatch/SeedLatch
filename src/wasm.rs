//! The browser boundary.
//!
//! Compiled only for `wasm32`. Native builds — including the whole test suite — do not
//! carry `wasm-bindgen`, which keeps `cargo audit` on the native path honest about what
//! the tests actually compile.
//!
//! # What crosses this boundary
//!
//! Input goes **in**. A verdict comes **out**. The input never comes back.
//!
//! [`CheckResult`] holds categories and sizes and has nowhere to put a value. That is
//! deliberate: JavaScript is where a copy becomes unreachable, since JS strings are
//! immutable and garbage-collected and neither this crate nor the frontend can force a
//! collection.
//!
//! # [`check`] is the interim shape. `analyse` supersedes it in week 2.
//!
//! `check` runs the guard and stops. The accepted path therefore has nowhere to go yet, so
//! **the frontend must not be built around handing an accepted value back to JavaScript and
//! passing it in again to be parsed** — that is two crossings and a JS-held copy of the
//! user's complete wallet history, and it contradicts what `parse` tells the frontend to do.
//!
//! Week 2 replaces this with a single `analyse(input)` that runs guard-then-parse inside
//! WASM and returns a report. The ordering guarantee then rests on `AcceptedInput` being
//! unconstructible except through `guard_input`, rather than on the frontend remembering to
//! call things in the right order.

use wasm_bindgen::prelude::*;

use crate::parse::{self, Refusal};

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

/// The verdict on an input.
#[wasm_bindgen(getter_with_clone)]
#[derive(Debug, Clone)]
pub struct CheckResult {
    /// Empty when accepted. Otherwise `"secret_material"` or `"too_large"`.
    ///
    /// A string rather than an enum because wasm-bindgen does not carry data-bearing enums
    /// across the boundary; the TypeScript declaration narrows it to a union.
    pub refusal: String,
    /// Populated only when `refusal == "secret_material"`.
    pub categories: Vec<DetectedCategory>,
    /// Populated only when `refusal == "too_large"`.
    pub limit: u32,
    /// Populated only when `refusal == "too_large"`.
    pub size: u32,
}

#[wasm_bindgen]
impl CheckResult {
    /// Whether the input may proceed.
    #[wasm_bindgen(getter)]
    pub fn accepted(&self) -> bool {
        self.refusal.is_empty()
    }
}

fn clamp(value: usize) -> u32 {
    u32::try_from(value).unwrap_or(u32::MAX)
}

/// Run the input guard.
///
/// Call this **before** anything else touches the input — before storing it in a variable
/// that outlives the handler, before rendering it, before any network request. On a refusal
/// the caller must clear the field and show the blocking interstitial.
///
/// Note that an oversized input is refused *without being examined*, so `categories` is
/// empty for `"too_large"` and the copy must not imply otherwise. See `guard_input`.
#[wasm_bindgen]
pub fn check(input: &str) -> CheckResult {
    match parse::guard_input(input) {
        Ok(_accepted) => CheckResult {
            refusal: String::new(),
            categories: Vec::new(),
            limit: 0,
            size: 0,
        },
        Err(Refusal::SecretMaterial(found)) => CheckResult {
            refusal: String::from("secret_material"),
            categories: found
                .categories()
                .iter()
                .map(|category| DetectedCategory {
                    key: category.key().to_owned(),
                    label: category.label().to_owned(),
                })
                .collect(),
            limit: 0,
            size: 0,
        },
        Err(Refusal::TooLarge {
            limit_bytes,
            actual_bytes,
        }) => CheckResult {
            refusal: String::from("too_large"),
            categories: Vec::new(),
            limit: clamp(limit_bytes),
            size: clamp(actual_bytes),
        },
    }
}

//! Seedlatch — structural exposure checker for Bitcoin descriptors and extended public keys.
//!
//! Everything here runs on the user's device. Nothing in this crate transmits, persists,
//! or logs user input. See `CLAUDE.md` for the invariants this code is required to hold.
//!
//! v0 is **structural only**: it reports how many independent things must be correct for a
//! wallet to be safe. It makes no vendor-specific claim and cannot tell anyone whether a
//! seed was well generated — no public key can.

#![forbid(unsafe_code)]
#![deny(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::todo,
    clippy::unimplemented,
    clippy::string_slice,
    missing_debug_implementations
)]
#![cfg_attr(test, allow(clippy::unwrap_used, clippy::expect_used, clippy::panic))]

pub mod classify;
pub mod derive;
pub mod parse;
pub mod report;

#[cfg(target_arch = "wasm32")]
pub mod wasm;

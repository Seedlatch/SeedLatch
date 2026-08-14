//! Structural classification — week 4.
//!
//! Not implemented. Descriptor parsing, which it depends on, is done — see
//! `src/parse/descriptor.rs` and `src/analysis.rs`. What is missing is this module, not its
//! input.
//!
//! (An earlier version of this note said the dependency was blocked on approval. That was
//! true when it was written and stopped being true when `miniscript` landed. A stale
//! "blocked" tells a reader not to start on work that is in fact unblocked.)
//!
//! Tiers are `SINGLE_POINT_OF_FAILURE`, `PARTIALLY_MITIGATED`, `STRUCTURALLY_MITIGATED`,
//! derived from descriptor shape and clearly-labelled self-report only. Never a numeric
//! score, never a vendor-specific claim, and `UNKNOWN_PROVENANCE` attaches to every result
//! regardless of tier — no structure proves a key was well generated.
//!
//! Where two tiers are both defensible, the more severe one is assigned. A false negative
//! is what stops someone migrating.

//! Structural classification — week 4.
//!
//! Not implemented. Requires descriptor parsing first, which is blocked on dependency
//! approval.
//!
//! Tiers are `SINGLE_POINT_OF_FAILURE`, `PARTIALLY_MITIGATED`, `STRUCTURALLY_MITIGATED`,
//! derived from descriptor shape and clearly-labelled self-report only. Never a numeric
//! score, never a vendor-specific claim, and `UNKNOWN_PROVENANCE` attaches to every result
//! regardless of tier — no structure proves a key was well generated.
//!
//! Where two tiers are both defensible, the more severe one is assigned. A false negative
//! is what stops someone migrating.

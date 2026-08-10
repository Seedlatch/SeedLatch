//! Path enumeration — week 3.
//!
//! Not implemented. Blocked on dependency approval (`bdk`, `rust-miniscript`,
//! `rust-bitcoin`) per `CLAUDE.md` invariant 6.
//!
//! When it is built, it must hold to the spec's limits: purposes `44h`, `49h`, `84h`,
//! `86h` and `48h/…/2h`; a gap limit of 20 consecutive unused addresses per chain rather
//! than a fixed range; batching, capped concurrency, visible progress and a working
//! cancel. This engine is reused by monitoring later, so it gets built clean or not at all.
//!
//! Reproducing any known-vulnerable derivation is permanently out of scope in this
//! repository — that code is attack-equivalent.

# Vendor and firmware data

**This file is intentionally empty in v0, and nothing reads it.**

v0 is structural only. It makes no vendor-specific claim: it never states or implies that a
given device or firmware version is affected. The underlying entropy figures are still
disputed between Coinkite, Block and independent analysts (business notes §2.1, an
external private document), which is
itself the reason not to build verdicts on them yet.

## Rules for this file, when it eventually has content

1. Firmware versions, affected date ranges, vendor defaults and derivation conventions come
   from here and **nowhere else**. Never hardcode them from memory or inference anywhere in
   the codebase — the "no invented security-relevant data" invariant in `CLAUDE.md`.
2. Every entry carries its source, the date it was retrieved, and who verified it.
3. Anything not sourced does not go in.
4. Adding content here is a scope change, not a data update: it converts the product from
   structural assessment to vendor-specific claims, with the liability that implies. It
   needs the legal review (business notes §8.5 gate 1, external) first.

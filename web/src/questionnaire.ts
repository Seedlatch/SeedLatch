/**
 * The structured questionnaire. Semantics fixed in `docs/spec.md` §3.2.
 *
 * There is no free-text field here and there must never be one. A terse keyword answer is
 * numerically identical to a seed phrase — `home safe, office safe, deposit box, metal
 * plate, paper copy, spare device` is twelve tokens, twelve BIP-39 words, run of twelve,
 * density 1.00, exactly like a twelve-word mnemonic — so no detector threshold separates
 * them. Structured controls delete the failure class instead of moving it.
 *
 * See `docs/security-model.md` §3 for the measurements.
 *
 * Everything here is clearly-labelled unverified self-report. It feeds the structural
 * narrative and never a verdict.
 */

export const MIN_DEVICES = 1;
export const MAX_DEVICES = 20;

/** Fixed list. No "other" with a text box — that reintroduces the field we removed. */
export const VENDORS = [
  'coldcard',
  'trezor',
  'ledger',
  'bitbox',
  'jade',
  'foundation',
  'seedsigner',
  'specter',
  'other',
] as const;

export type Vendor = (typeof VENDORS)[number];

/**
 * `unsure` is a real answer, not a missing one, and it is not the same as `yes`.
 * See {@link passphraseCountsAsMitigation}.
 */
export type PassphraseAnswer = 'yes' | 'no' | 'unsure';

export interface Questionnaire {
  readonly deviceCount: number;
  readonly vendors: readonly Vendor[];
  readonly passphrase: PassphraseAnswer;
}

export type ValidationError =
  | { readonly field: 'deviceCount'; readonly reason: 'out_of_range' | 'not_an_integer' }
  | {
      readonly field: 'vendors';
      readonly reason: 'unknown_vendor' | 'none_selected' | 'more_vendors_than_devices';
    };

export type Validated<T> =
  | { readonly ok: true; readonly value: T }
  | { readonly ok: false; readonly errors: readonly ValidationError[] };

/**
 * Whether a reported passphrase may be counted as mitigation when assigning a tier.
 *
 * `unsure` takes the same branch as `no`. This is the more-severe-tier rule from
 * `spec.md` §5: an unverified passphrase is not mitigation, and treating it as one would
 * put a wallet in a better tier than the evidence supports. A false negative is what stops
 * someone migrating.
 *
 * The UI must say this out loud — "we treat 'unsure' the same as 'no'" — rather than
 * leaving the user to guess what their answer did.
 */
export function passphraseCountsAsMitigation(answer: PassphraseAnswer): boolean {
  switch (answer) {
    case 'yes':
      return true;
    case 'no':
    case 'unsure':
      return false;
    default:
      // The value arrives from a DOM control, so the union is a claim about the runtime
      // rather than an enforcement of it — the same reasoning as the default arm in
      // `guardField`. Without this the function returns `undefined` on an unexpected value,
      // which happens to be falsy and so happens to land on the safe side. Safety by
      // accident is not safety: it survives only until someone inverts the caller's test.
      return false;
  }
}

/**
 * Validate raw control values.
 *
 * Out-of-range device counts are **rejected, not clamped**. Clamping silently changes the
 * user's answer, and the answer feeds a report they may act on.
 *
 * # Why the vendor rules are stricter than "is it in the list"
 *
 * §5 derives tiers partly from **vendor diversity** — how many independent manufacturers
 * would have to be wrong at once. Every rule below exists because breaking it inflates that
 * number, and an inflated diversity assigns a *less* severe tier. That is the direction that
 * costs coins: a false negative is what stops someone migrating.
 *
 * - **Duplicates are collapsed before anything counts them.** `[ledger, ledger]` is one
 *   manufacturer, and counting it as two claims an independence that is not there.
 * - **An empty selection is refused, not treated as zero.** A wallet has devices; a blank
 *   answer is an unanswered question, and letting it through would feed a diversity of zero
 *   into a tier calculation as though it were a measurement.
 * - **More distinct vendors than devices is refused.** It cannot be true — each device has
 *   one manufacturer — so it is a mis-click or a malformed submission, and the safe reading
 *   of an impossible answer is to ask again rather than to pick an interpretation.
 *
 * These are input rules. They do not change what any tier means.
 */
export function validate(input: {
  deviceCount: number;
  vendors: readonly string[];
  passphrase: PassphraseAnswer;
}): Validated<Questionnaire> {
  const errors: ValidationError[] = [];

  const countIsUsable =
    Number.isInteger(input.deviceCount) &&
    input.deviceCount >= MIN_DEVICES &&
    input.deviceCount <= MAX_DEVICES;

  if (!Number.isInteger(input.deviceCount)) {
    errors.push({ field: 'deviceCount', reason: 'not_an_integer' });
  } else if (!countIsUsable) {
    errors.push({ field: 'deviceCount', reason: 'out_of_range' });
  }

  const known = new Set<string>(VENDORS);
  if (input.vendors.some((vendor) => !known.has(vendor))) {
    errors.push({ field: 'vendors', reason: 'unknown_vendor' });
  }

  // Collapse first, then judge. Every check below is about distinct manufacturers, and a
  // repeated selection is one manufacturer however many times it was clicked.
  const distinct = [...new Set(input.vendors)] as readonly Vendor[];

  if (distinct.length === 0) {
    errors.push({ field: 'vendors', reason: 'none_selected' });
  } else if (countIsUsable && distinct.length > input.deviceCount) {
    // Only meaningful against a usable count; otherwise this would pile a second complaint
    // onto an answer whose first problem is that the count is not a number.
    errors.push({ field: 'vendors', reason: 'more_vendors_than_devices' });
  }

  if (errors.length > 0) {
    return { ok: false, errors };
  }

  return {
    ok: true,
    value: {
      deviceCount: input.deviceCount,
      // The de-duplicated list, not the raw one. Anything downstream counting these is
      // counting manufacturers, and it should not have to know to collapse them itself.
      vendors: distinct,
      passphrase: input.passphrase,
    },
  };
}

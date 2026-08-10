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
  | { readonly field: 'vendors'; readonly reason: 'unknown_vendor' };

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
  }
}

/**
 * Validate raw control values.
 *
 * Out-of-range device counts are **rejected, not clamped**. Clamping silently changes the
 * user's answer, and the answer feeds a report they may act on.
 */
export function validate(input: {
  deviceCount: number;
  vendors: readonly string[];
  passphrase: PassphraseAnswer;
}): Validated<Questionnaire> {
  const errors: ValidationError[] = [];

  if (!Number.isInteger(input.deviceCount)) {
    errors.push({ field: 'deviceCount', reason: 'not_an_integer' });
  } else if (input.deviceCount < MIN_DEVICES || input.deviceCount > MAX_DEVICES) {
    errors.push({ field: 'deviceCount', reason: 'out_of_range' });
  }

  const known = new Set<string>(VENDORS);
  if (input.vendors.some((vendor) => !known.has(vendor))) {
    errors.push({ field: 'vendors', reason: 'unknown_vendor' });
  }

  if (errors.length > 0) {
    return { ok: false, errors };
  }

  return {
    ok: true,
    value: {
      deviceCount: input.deviceCount,
      vendors: input.vendors as readonly Vendor[],
      passphrase: input.passphrase,
    },
  };
}

/**
 * The input guard: the only path by which a pasted value reaches anything else.
 *
 * This file contains no user-facing copy. The interstitial wording is reviewed text,
 * drafted in `docs/spec.md` §6.1, and the module that renders it does not exist yet.
 *
 * # Types come from the generated module, not from a hand-written declaration
 *
 * An earlier revision declared the boundary by hand in `core.d.ts`, because CI type-checked
 * without a WASM build. That declaration was wrong in ways the type checker could not
 * notice, because a `declare module` is believed rather than checked: it described
 * `CheckResult` as a plain interface when wasm-bindgen actually generates a **class holding
 * a WASM allocation that must be freed**. The frontend was written against a shape that did
 * not exist.
 *
 * So the generated `web/pkg/seedlatch.d.ts` is now the only description of this boundary,
 * and CI builds the WASM module before type-checking. There is nothing left to drift.
 *
 * # The accepted branch deliberately carries no value
 *
 * An earlier revision returned `{ kind: 'accepted', value: raw }`. That would have had
 * JavaScript hold the descriptor and pass it back into WASM to be parsed: two crossings and
 * a JS-held copy of the user's complete address and balance history, which is exactly what
 * `src/parse/mod.rs` tells the frontend not to do.
 *
 * Week 2 introduces a single `analyse(input)` entry that runs guard-then-parse inside WASM
 * and returns a report — one crossing, input never returned — with ordering guaranteed by
 * `AcceptedInput` being unconstructible except through `guard_input`.
 *
 * # Order of operations, and why it is this order
 *
 * 1. Read the field value.
 * 2. Hand it straight to WASM.
 * 3. Clear the field — **before** anything renders, not after a modal is dismissed.
 * 4. Copy the verdict out as plain values, free the WASM objects, report the reason.
 *
 * Step 3 comes before any paint because the realistic failure is a user who pastes a seed
 * phrase, sees a modal, panics, and leaves the tab open with the phrase still in the DOM.
 */

import { analyse, type AnalysisResult } from '#core';

/**
 * A category, copied out of WASM into an ordinary object.
 *
 * Deliberately not the generated `DetectedCategory`, which is a WASM-backed class: handing
 * those to callers would make every caller responsible for freeing them, and the one that
 * forgets leaks silently. Nothing owned by WASM escapes this module.
 *
 * `key` is a plain string rather than a union. The generated boundary types it as `string`,
 * so narrowing it here would be a claim the runtime does not enforce — the same mistake as
 * the hand-written declaration. Compare it if you need to; an unrecognised key simply gets
 * no special treatment, which is the safe direction.
 */
export interface Category {
  readonly key: string;
  readonly label: string;
}

/**
 * What the input turned out to be. Facts only — no tier, no judgement.
 *
 * Still no value: every field here was computed from the input, and none of them is the
 * input. `analyse` runs guard-then-parse inside WASM in one crossing, so JavaScript never
 * holds the descriptor at all.
 */
export interface Facts {
  /** `'key'` or `'descriptor'`. */
  readonly form: string;
  /** `'mainnet'` or `'testnet'`. */
  readonly network: string;
  /** Script type for a key, shape for a descriptor. */
  readonly shape: string;
  /** Key only: the SLIP-132 prefix as presented, case intact. */
  readonly prefix: string;
  /** Key only: depth in the derivation tree. 0 is a master key. */
  readonly depth: number;
  /**
   * **The script type could not be determined from the input** — an `xpub` or `tpub`, which
   * SLIP-132 records as "P2PKH or P2SH".
   *
   * When this is true the user must be asked, using the structured controls. Never guess:
   * the wrong choice derives addresses they do not own, and then reports a balance that is
   * not theirs. It is never true for a descriptor, so the question must not be shown for
   * one — a descriptor already stated its script type, and asking would invent an ambiguity
   * the input does not have.
   */
  readonly ask: boolean;
  /** Descriptor only: the *n* of *k*-of-*n*. */
  readonly keys: number;
  /** Descriptor only: the *k* of *k*-of-*n*, or **0 when not recoverable**. */
  readonly threshold: number;
  readonly wildcards: number;
  readonly origins: number;
  readonly singles: number;
}

export type GuardOutcome =
  | { readonly kind: 'accepted'; readonly facts: Facts }
  | { readonly kind: 'secret-material'; readonly categories: readonly Category[] }
  /**
   * Refused on size, **without being examined**. There are no categories because nothing
   * was looked at, and the copy must not suggest otherwise.
   */
  | { readonly kind: 'too-large'; readonly limit: number; readonly size: number }
  /**
   * Passed the guard and then could not be read as either a descriptor or an extended key.
   *
   * This is **not** the secret-material interstitial and must not render as one: nothing
   * alarming was found, the input was simply not something this tool reads. `form` says
   * which parser it was routed to and `reason` is a stable machine key such as
   * `not_base58` or `slip132_key_in_descriptor` — never the input.
   *
   * The copy for this screen is not written or approved yet. See `buildInterstitial`.
   */
  | { readonly kind: 'unreadable'; readonly form: string; readonly reason: string };

/** Copy categories out of WASM and release the wrappers. */
function takeCategories(result: AnalysisResult): Category[] {
  // Each access to `.categories` constructs a fresh array of WASM-backed wrappers, so it
  // is read exactly once and every wrapper in it is freed.
  const wrapped = result.categories;
  try {
    return wrapped.map((category) => ({ key: category.key, label: category.label }));
  } finally {
    for (const category of wrapped) {
      category.free();
    }
  }
}

/**
 * Guard a value read from a form field, clearing the field as an unconditional side effect.
 *
 * The field is cleared whether or not the input was refused. There is no case where leaving
 * a pasted wallet identifier sitting in the DOM is useful, and making it unconditional
 * removes the branch where someone later adds an early return above it.
 */
export function guardField(field: HTMLInputElement | HTMLTextAreaElement): GuardOutcome {
  let result: AnalysisResult;
  try {
    // Hand off first, clear immediately after. Nothing between these two statements.
    //
    // One call, not two. `analyse` runs the guard and the parser inside WASM and returns
    // facts, so the accepted value never comes back across the boundary to be passed in
    // again — which would mean two crossings and a JavaScript-held copy of the user's
    // complete address and balance history.
    result = analyse(field.value);
  } finally {
    // `finally`, not a following statement: if `check` throws — the WASM module failed to
    // initialise, memory ran out, anything — an exception must not leave a pasted recovery
    // phrase sitting in the DOM while the error propagates.
    field.value = '';
  }

  try {
    switch (result.refusal) {
      case 'secret_material':
        return { kind: 'secret-material', categories: takeCategories(result) };
      case 'too_large':
        return { kind: 'too-large', limit: result.limit, size: result.size };
      case 'unreadable':
        return { kind: 'unreadable', form: result.form, reason: result.reason };
      case '':
        return {
          kind: 'accepted',
          facts: {
            form: result.form,
            network: result.network,
            shape: result.shape,
            prefix: result.prefix,
            depth: result.depth,
            ask: result.ask,
            keys: result.keys,
            threshold: result.threshold,
            wildcards: result.wildcards,
            origins: result.origins,
            singles: result.singles,
          },
        };
      default:
        // `refusal` is typed `string` by the generated boundary, so this is reachable, and
        // it would be reachable even if it were narrowed — a TypeScript union is a claim
        // about the runtime, not an enforcement of it. Without this arm the function would
        // fall through and return `undefined`, and a caller checking `outcome.kind` would
        // see nothing and treat unguarded input as fine. Anything unrecognised is refused.
        return { kind: 'secret-material', categories: [] };
    }
  } finally {
    // The verdict is a WASM allocation. Every path through the switch has already copied
    // out the plain values it needs, so it is always safe to release here, and doing it in
    // `finally` means a future branch cannot forget.
    result.free();
  }
}

/**
 * What this codebase can and cannot promise about clearing memory.
 *
 * Rust-side buffers holding a copy are `Zeroizing`, and the lowercase buffer is
 * preallocated so it cannot reallocate and strand a copy in freed memory.
 *
 * None of that reaches JavaScript. JS strings are immutable and garbage-collected, so a
 * pasted phrase can sit in the heap until the collector runs, and no web page can force
 * that. Clearing the field is the whole of what is available.
 *
 * The UI must state this rather than implying a guarantee. Exported so the copy that says
 * so has something to point at, and so that deleting the claim requires deleting this.
 */
export const BROWSER_MEMORY_LIMITATION =
  'browser may retain a copy of pasted input until garbage collection; not controllable from a page';

/**
 * Recovery from the interstitial. `docs/spec.md` §6.1.
 *
 * A full reload, not a JavaScript state reset. Nothing persists — no localStorage, no
 * sessionStorage, no cookies, no cache — so a reload is a genuine clean slate, and it also
 * gives the browser its best chance to release the pasted string, which a soft reset does
 * not.
 *
 * Non-dismissible must not mean stuck: about one in four thousand secret-material refusals
 * is a prose false positive, and every size refusal is someone who simply pasted too much.
 */
export function startOver(): void {
  window.location.reload();
}

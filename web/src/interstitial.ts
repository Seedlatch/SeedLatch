/**
 * The blocking interstitial: the screen a refusal produces.
 *
 * The wording is reviewed copy from `docs/spec.md` §6.1 and is reproduced here verbatim.
 * **Do not edit these strings unprompted.** If a sentence here and a sentence there ever
 * disagree, the spec is right and this file is a bug.
 *
 * # This module cannot echo the pasted value, and that is structural
 *
 * It renders from a [`GuardOutcome`], which has nowhere to put a value — the accepted branch
 * carries none and the refusal branches carry a category, a limit and a size. So "never
 * render the pasted value" is not a rule anyone has to remember here; there is no expression
 * that could do it.
 *
 * Nothing in this file uses `innerHTML`, `insertAdjacentHTML`, or any other string-to-markup
 * path. Copy is a list of typed segments rendered into text nodes, so a future edit that
 * pastes a value into the copy produces visible angle brackets rather than markup — and more
 * to the point, the value is not in scope to paste.
 *
 * # Why a native `<dialog>` rather than a div and a focus-trap implementation
 *
 * §6.1 requires: focus starts on the only button, focus is trapped, Escape does not dismiss,
 * clicking outside does not dismiss, and the rest of the page is unreachable. `showModal()`
 * provides four of those five in the browser itself — inert background, contained focus, a
 * backdrop that ignores clicks, and top-layer rendering that does not depend on our
 * stylesheet loading. A hand-written trap would be our own code standing between a
 * frightened user and the one control on the screen.
 *
 * Escape is the exception: `showModal()` deliberately allows it, so it is cancelled
 * explicitly below. That is the only dismissal path that needs code, and it is one line
 * rather than an implementation.
 */

import { startOver, type Category, type GuardOutcome } from './guard';

/**
 * A run of copy. Deliberately not a string with markup in it — see the module note.
 *
 * `code` is for the literal key prefixes (`pub`, `prv`, `Ypub`, `Zpub`) and for `tr()` and
 * `xpub` in the hexadecimal note. Those are case-significant strings the reader may need to
 * compare against their own wallet, so they are marked as code rather than left to a font
 * that might render `l` and `1` alike.
 */
type Segment =
  | { readonly kind: 'text'; readonly value: string }
  | { readonly kind: 'strong'; readonly value: string }
  | { readonly kind: 'code'; readonly value: string };

const t = (value: string): Segment => ({ kind: 'text', value });
const b = (value: string): Segment => ({ kind: 'strong', value });
const c = (value: string): Segment => ({ kind: 'code', value });

type Paragraph = readonly Segment[];

/**
 * Both variants render through one shape.
 *
 * An earlier revision gave only the secret-material variant a `note` field and narrowed with
 * `'note' in copy`. That narrowing widens the property to `unknown` on the branch that lacks
 * it, so the null check silently stopped proving anything — the renderer would have been
 * handed `undefined` and the type checker would have said so in a way easy to wave through
 * with a cast. One shape, always present, `null` when there is nothing to say.
 */
interface InterstitialCopy {
  readonly heading: string;
  readonly paragraphs: readonly Paragraph[];
  /** §6.1: omit the line entirely when empty — hence `null`, never an empty paragraph. */
  readonly note: Paragraph | null;
}

/**
 * Join category labels the way `join_with_and` in `src/parse/mod.rs` does, including the
 * empty case.
 *
 * The empty case is reachable. `guardField` refuses anything with an unrecognised `refusal`
 * string and reports it as secret material with no categories, which is the fail-closed
 * direction — so this renders the screen for "something was refused and we cannot name it"
 * rather than producing the sentence "looks like ." with a hole in it.
 */
function joinWithAnd(items: readonly string[]): string {
  const last = items[items.length - 1];
  if (last === undefined) return 'secret key material';

  const rest = items.slice(0, -1);
  return rest.length === 0 ? last : `${rest.join(', ')} and ${last}`;
}

/**
 * Bytes in the units §6.1 writes them in: `4.2 MB`, not `4404019`.
 *
 * Binary divisors, decimal labels — which is what the spec's own worked example uses, since
 * 4,404,019 bytes is 4.2 MiB and 4.4 MB. Matching the example matters more than the naming
 * argument: the limit is `100 * 1024`, so a decimal divisor would render it as `102.4 KB`
 * and the copy would be telling the user a limit that is not the one the code enforces.
 *
 * The size is not secret material. The user knows what they pasted, and it never leaves the
 * device — `docs/spec.md` §6.1.
 */
export function formatBytes(bytes: number): string {
  if (!Number.isFinite(bytes) || bytes < 0) return 'an unknown amount';
  if (bytes < 1024) return `${bytes} ${bytes === 1 ? 'byte' : 'bytes'}`;

  const units = ['KB', 'MB', 'GB', 'TB'] as const;
  let value = bytes / 1024;
  let unit: string = units[0];
  for (let i = 1; i < units.length && value >= 1024; i += 1) {
    value /= 1024;
    unit = units[i] ?? unit;
  }

  // One decimal, but `100 KB` rather than `100.0 KB` — the limit is an exact figure and
  // dressing it with a false decimal makes arithmetic look like an estimate. §6.0.
  const rounded = Math.round(value * 10) / 10;
  return `${Number.isInteger(rounded) ? rounded : rounded.toFixed(1)} ${unit}`;
}

/**
 * The one category that needs a way forward the generic copy cannot give — §6.1.
 *
 * Keyed on `SecretMaterial::key`, not on the label: the label is reviewed copy and changes
 * when someone edits the wording, the key is a stable identifier and does not. Switching on
 * the label would silently stop matching the first time the copy is revised.
 *
 * Without this, a `tr()` descriptor carrying a raw x-only *public* key is a dead end — the
 * user pasted a good public descriptor, is told it looks like a private key, correctly
 * concludes it was not, follows "start over and paste a descriptor", and hits the same wall.
 */
const CATEGORY_NOTES: Readonly<Record<string, Paragraph>> = {
  raw_hex_private_key: [
    t('32 bytes of hexadecimal is a private key or a public one, and nothing in the value '),
    t('itself distinguishes them. If yours was a public key inside a '),
    c('tr()'),
    t(' descriptor, use the '),
    c('xpub'),
    t(' form of the same descriptor — this tool reads that.'),
  ],
};

/**
 * Copy for a secret-material refusal. `docs/spec.md` §6.1.
 *
 * Worded conditionally on purpose. The detector reads shape, not meaning: a comma-separated
 * keyword list is numerically identical to a twelve-word seed phrase, and ordinary prose
 * crosses the run threshold about once per 4,000 realistic pastes. Both stay detected — that
 * is correct, fail-closed behaviour — but the product must not *assert* that someone pasted
 * a secret when it cannot know. §6.0: judgements hedge.
 *
 * The paragraph order is load-bearing and was arrived at by fixing three specific failures;
 * see §6.1 "Two things an earlier draft got wrong". In particular the fork header comes
 * before either branch is argued, so the reassuring branch is reachable in one read without
 * softening the urgent one, and the browser-memory limitation sits on the same claim it
 * qualifies rather than four paragraphs below it.
 */
function secretMaterialCopy(categories: readonly Category[]): InterstitialCopy {
  const label = joinWithAnd(categories.map((category) => category.label));

  // At most one note, even when several categories are present: the notes answer "what do I
  // do instead", and stacking them on a screen that already carries urgent instructions
  // buries the instructions. The hexadecimal case is the only one defined.
  const noted = categories.find((category) => category.key in CATEGORY_NOTES);
  const note = noted === undefined ? null : (CATEGORY_NOTES[noted.key] ?? null);

  return {
    heading: "We didn't accept that",
    paragraphs: [
      [
        t('What you pasted looks like '),
        b(label),
        t('. This check reads shape, not meaning, so it '),
        t("can't be certain — it refuses anything that might be secret rather than guessing."),
      ],
      [
        b('Nothing left your device.'),
        t(' It was checked for secret material and nothing else: not parsed as a wallet, '),
        t('no addresses worked out, no balances looked up. Nothing sent, nothing saved, '),
        t('nothing written to a log.'),
      ],
      // This paragraph is the prose form of BROWSER_MEMORY_LIMITATION in `guard.ts`.
      // CLAUDE.md requires the limitation be stated rather than implied away, and an
      // earlier draft buried it four paragraphs below "the box is now empty" in unbolded
      // italics — the most skippable element on the screen, qualifying the one claim that
      // invites the wrong generalisation.
      [
        b("We've cleared the box — that's the limit of what we can reach."),
        t(' Your browser may still be holding a copy of anything you pasted, until it '),
        t('decides to let go, and no web page can force that. Start over reloads this page, '),
        t('which gives it the best chance to.'),
      ],
      [b('Only you can tell which of these just happened.')],
      [
        b('If it was a secret'),
        t(' — a recovery phrase, a private key, anything that can spend — treat it as '),
        t('exposed, and move your coins to a wallet created fresh on a device you trust. '),
        t('Do that before anything else. Not because of this page, but because something '),
        t('that has been on a clipboard is one keystroke away from a note, a chat, a '),
        t('screenshot or a support ticket.'),
      ],
      [
        b("If it wasn't"),
        t(' — a sentence, a note, a list of words — then nothing has gone wrong here. This '),
        t('check is deliberately strict and it stops harmless things too. Choose Start over '),
        t('and paste a descriptor or an extended public key instead.'),
      ],
      // States the rule rather than enumerating prefixes. An earlier draft listed
      // "xpub, ypub, zpub, tpub" and omitted the SLIP-132 multisig forms, so a Zpub holder
      // read a list containing zpub but not Zpub and would reasonably conclude their key
      // was not accepted — and that is the audience most likely to have survived the defect.
      [
        t('This tool only ever needs public information: a descriptor, or an extended '),
        t('public key — any of the '),
        c('pub'),
        t(' forms, including the capitalised '),
        c('Ypub'),
        t(' and '),
        c('Zpub'),
        t(' that multisig wallets use. Anything with '),
        c('prv'),
        t(' in it is the private version and this tool will never accept one. A public key '),
        t("shows your balance and every address you own, which is why we don't send it "),
        t('anywhere either — but it cannot spend anything.'),
      ],
    ],
    note,
  };
}

/**
 * Copy for a size refusal. `docs/spec.md` §6.1, second variant.
 *
 * **This one does not hedge, and the difference is deliberate.** Detection is a judgement
 * that can be wrong; size is arithmetic. We know exactly what happened and there is nothing
 * to soften. §6.0.
 *
 * The final paragraph exists because the size check runs *before* the scan, by necessity —
 * bounding allocation is the whole point of it. Someone who pastes a 200 KB backup
 * containing their seed gets no secret-material warning, because none was computed. Saying
 * so plainly is the only honest option; the alternative is a silence they would reasonably
 * read as "it was fine".
 */
function tooLargeCopy(limit: number, size: number): InterstitialCopy {
  return {
    heading: "That's too big to check",
    // No category note: nothing was examined, so there is no category to annotate.
    note: null,
    paragraphs: [
      // Both figures are rendered from the values the code actually enforced, rather than
      // written into the copy. A hardcoded "100 KB" here is a second statement of
      // MAX_INPUT_BYTES that nothing checks, and it would go stale silently.
      [
        t(`The box takes up to ${formatBytes(limit)}. What you pasted was `),
        b(formatBytes(size)),
        t(', so we stopped without looking at it — not a sample, not the first part, '),
        t('none of it.'),
      ],
      // Also the prose form of BROWSER_MEMORY_LIMITATION in `guard.ts`.
      [
        b('Nothing left your device'),
        t(', because nothing was read in the first place. The box is now empty. Your '),
        t('browser may still be holding a copy of anything you pasted, and no web page can '),
        t('reach that; Start over reloads this page, which gives it the best chance to let '),
        t('go.'),
      ],
      [
        t('A descriptor or an extended public key is small — a few hundred characters, or '),
        t('a few thousand for a large multisig. Something this size is usually a whole '),
        t('file. If you have a wallet backup or an export, open it and copy out just the '),
        t('descriptor line.'),
      ],
      [
        b("One thing we can't tell you:"),
        t(" we don't know what was in it, because we didn't look. If that file held a "),
        t('recovery phrase or a private key, we have no way of knowing and no way of '),
        t('warning you. Check for yourself before you paste it anywhere else.'),
      ],
    ],
  };
}

function renderParagraph(segments: Paragraph, emphasised = false): HTMLParagraphElement {
  const paragraph = document.createElement('p');
  const host: HTMLElement = emphasised ? document.createElement('em') : paragraph;

  for (const segment of segments) {
    if (segment.kind === 'text') {
      host.appendChild(document.createTextNode(segment.value));
    } else {
      const element = document.createElement(segment.kind === 'strong' ? 'strong' : 'code');
      element.textContent = segment.value;
      host.appendChild(element);
    }
  }

  if (host !== paragraph) paragraph.appendChild(host);
  return paragraph;
}

/**
 * Build the interstitial for a refusal, without showing it.
 *
 * Returns `null` for an accepted outcome. Accepted input has no interstitial, and returning
 * an empty dialog would let a caller show a blank blocking modal over a working page.
 *
 * Exported separately from [`showInterstitial`] so the DOM can be inspected without a
 * top-layer modal in the way — a rendered node is testable, a `showModal()` call is not.
 */
export function buildInterstitial(outcome: GuardOutcome): HTMLDialogElement | null {
  // `unreadable` returns null alongside `accepted`, and that is a gap rather than a
  // decision: the input was refused, so the user needs to be told something, but the copy
  // for that screen has not been written or reviewed. Writing it here would put unreviewed
  // user-facing wording into the product, which §6.1 exists to prevent.
  //
  // What it must NOT do is fall through to one of the two screens below. Neither applies:
  // nothing alarming was found, and nothing was too large. Showing the secret-material
  // interstitial to someone who mistyped an xpub would tell them their key may be
  // compromised, which is false and is exactly the alarm this product cannot afford to
  // spend wrongly.
  if (outcome.kind === 'accepted' || outcome.kind === 'unreadable') return null;

  const copy =
    outcome.kind === 'secret-material'
      ? secretMaterialCopy(outcome.categories)
      : tooLargeCopy(outcome.limit, outcome.size);

  const dialog = document.createElement('dialog');
  dialog.className = 'interstitial';
  dialog.dataset['variant'] = outcome.kind;

  const heading = document.createElement('h2');
  heading.className = 'interstitial__heading';
  heading.textContent = copy.heading;
  // Names the dialog for assistive technology. A screen-reader user who lands in a modal
  // they cannot dismiss should hear what it is before they hear the button.
  heading.id = 'interstitial-heading';
  dialog.setAttribute('aria-labelledby', heading.id);
  dialog.appendChild(heading);

  const body = document.createElement('div');
  body.className = 'interstitial__body';
  const [lead, ...rest] = copy.paragraphs;
  if (lead !== undefined) body.appendChild(renderParagraph(lead));
  // The note belongs to the first paragraph's claim, so it follows it rather than trailing
  // the screen. Only the secret-material variant has one; §6.1 says omit the line entirely
  // when empty, so an absent note produces no element at all rather than an empty <p>.
  if (copy.note !== null) {
    const note = renderParagraph(copy.note, true);
    note.className = 'interstitial__note';
    body.appendChild(note);
  }
  for (const paragraph of rest) body.appendChild(renderParagraph(paragraph));
  dialog.appendChild(body);

  // The only interactive element on the screen. §6.1: no call to action, no booking link,
  // no mailing list, here or anywhere this leads. This screen tells someone their secret may
  // be compromised and that they should move their funds now; a warning is worth acting on
  // quickly only if it comes from a party with nothing to gain by issuing it.
  const button = document.createElement('button');
  button.type = 'button';
  button.className = 'interstitial__start-over';
  button.textContent = 'Start over';
  button.addEventListener('click', startOver);
  dialog.appendChild(button);

  // Escape is the one dismissal `showModal()` allows, and §6.1 forbids it: someone who has
  // just pasted a seed phrase should not be able to clear this by reflex. Cancelling is
  // acceptable rather than hostile only because the button holds focus from the moment the
  // dialog opens, so a keyboard user is one Enter from recovery.
  dialog.addEventListener('cancel', (event) => {
    event.preventDefault();
  });

  return dialog;
}

/**
 * Show the interstitial for a refusal. Returns whether one was shown.
 *
 * The caller has already cleared the input field — `guardField` does it unconditionally, in
 * a `finally`, before this is reached. That ordering is required: the field is empty before
 * anything paints, not after the modal is dismissed.
 */
export function showInterstitial(
  outcome: GuardOutcome,
  container: HTMLElement = document.body,
): boolean {
  const dialog = buildInterstitial(outcome);
  if (dialog === null) return false;

  container.appendChild(dialog);

  if (typeof dialog.showModal === 'function') {
    dialog.showModal();
  } else {
    // No `showModal` means no top layer, no inert background and no native focus trap. The
    // refusal has already happened and the field is already clear, so the correct fallback
    // is a visible screen with reduced containment rather than a silent one: a user who is
    // shown nothing concludes their paste was accepted.
    dialog.setAttribute('open', '');
  }

  // Explicit rather than relying on autofocus heuristics. §6.1 requires the button to hold
  // focus on open, and it is what makes suppressing Escape acceptable.
  const button = dialog.querySelector<HTMLButtonElement>('.interstitial__start-over');
  button?.focus();

  return true;
}

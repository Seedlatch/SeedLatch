#!/usr/bin/env node
// Refuse to build if a personal identifier appears in the files given as arguments.
//
// # Why this exists as a script and not as a grep in the workflow
//
// It replaces a pile of ad-hoc greps that were rewritten slightly differently each time they
// were needed. Six of those were wrong, and the failure modes were all the same shape:
//
//   * a pattern that did not survive shell quoting, so it matched every line;
//   * a trailing backslash, so grep errored while the surrounding script printed a
//     reassuring zero;
//   * `[A-Za-z]:/` for a Windows drive letter, which matches the `s:/` in every https:// URL;
//   * `[A-Za-z]:\` likewise matching the `r:\` in an escaped `error:\n`;
//   * awk field positions shifted by one added format specifier, so every commit passed.
//
// **Every one of those failures reported clean.** Not one produced a false alarm that would
// have been investigated. A scanner whose failure mode is silence is indistinguishable from
// a repository with nothing in it, which is the property that makes it worth replacing with
// something that tests itself.
//
// # The self-test is the point, not a nicety
//
// Every pattern carries inputs it must flag and inputs it must ignore, and those run before
// any file is read. If a pattern stops working the script fails there, loudly, instead of
// sweeping a tree and reporting nothing found.
//
// # Output is redacted
//
// Reports file names and counts, never the matched text. This runs in CI on a public
// repository, and the thing it catches is by definition the thing that must not be printed —
// `CLAUDE.md` invariant 7, rule 2.

import { readFileSync } from 'node:fs';
import { relative, isAbsolute, basename, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';

/**
 * How a file is named in output.
 *
 * Inside the working tree, the relative path — that is what a reader needs to find it. From
 * anywhere else, the bare file name.
 *
 * The second case is not fussiness. Making the path relative is not enough on its own: a
 * file outside the tree relativises to something like `..\..\..\AppData\Local\Temp\...`,
 * which carries the account name and the directory layout. A gate that redacts the match and
 * then prints an identifier in the file name has moved the leak, not removed it. CI only
 * ever passes tree-relative paths, so this matters for local runs — which is exactly when
 * someone is scanning a build directory to check whether it is safe to publish.
 */
function displayPath(file) {
  const rel = isAbsolute(file) ? relative(process.cwd(), file) : file;
  return rel.startsWith('..') ? basename(rel) : rel;
}

/**
 * Each pattern states what it must catch and what it must leave alone.
 *
 * `ignores` entries are the specific false positives that have actually bitten, kept as
 * regression cases: a future "simplification" of one of these regexes fails here.
 */
const PATTERNS = [
  {
    name: 'windows drive path',
    re: /(^|[^A-Za-z])[A-Za-z]:[\\/]/,
    catches: ['see C:\\Users\\somebody\\x', '{"s":"C:\\\\Users\\\\x"}', 'D:/build/out'],
    ignores: [
      'Original error:\\n more', // the escaped-newline false positive
      'case x: default:\\n next',
      'fetch https://example.com/x', // the https:// false positive
      'ratio 3:1 and 4:2',
    ],
  },
  {
    name: 'posix home path',
    re: /\/(home|Users)\/[A-Za-z0-9._-]+/,
    catches: ['at /home/builder/src', 'from /Users/someone/proj'],
    ignores: ['/home/', '/usr/share/doc', 'Users of this tool'],
  },
  {
    name: 'cargo or rustup directory',
    re: /[\\/]\.(cargo|rustup)[\\/]/,
    catches: ['x/.cargo/registry/src', 'C:\\Users\\a\\.rustup\\toolchains'],
    ignores: ['CARGO_HOME is unset', 'the .cargo directory', 'cargo build --release'],
  },
  {
    name: 'temp or scratch directory',
    re: /[\\/](AppData|scratchpad)[\\/]/,
    catches: ['C:\\Users\\a\\AppData\\Local', 'tmp/scratchpad/probe'],
    ignores: ['application data', 'a scratchpad for notes'],
  },
  {
    name: 'non-pseudonymous email',
    // Any address that is not the project's published noreply identity.
    re: /\b[A-Za-z0-9._%+-]+@(?!users\.noreply\.github\.com\b)[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b/,
    catches: ['write to someone@example.com', 'a.person@mail.co.uk'],
    ignores: [
      '315577937+antoncorvin@users.noreply.github.com',
      'the @media query',
      'user@ is not an address',
    ],
  },
];

/** Run every pattern against its own examples. Returns a list of failures. */
function selfTest() {
  const failures = [];
  for (const { name, re, catches, ignores } of PATTERNS) {
    for (const sample of catches) {
      if (!re.test(sample)) failures.push(`${name}: failed to catch a case it must catch`);
    }
    for (const sample of ignores) {
      if (re.test(sample)) failures.push(`${name}: fired on a case it must ignore`);
    }
  }
  return failures;
}

const files = process.argv.slice(2);

const selfTestFailures = selfTest();
if (selfTestFailures.length > 0) {
  console.error('::error::identifier patterns failed their own self-test');
  for (const failure of selfTestFailures) console.error(`  ${failure}`);
  console.error('The samples are deliberately not printed alongside the tree scan.');
  process.exit(1);
}

// A gate with nothing to check proved nothing and must not report green.
if (files.length === 0) {
  console.error('::error::no files given - this check would pass without examining anything');
  process.exit(1);
}

let filesWithHits = 0;
let totalHits = 0;

// This file necessarily contains what it hunts for: the planted positives above are
// identifier-shaped by construction, which is what makes them positives. Scanning itself
// would report five patterns' worth of matches on every run, and a gate that always fails
// gets switched off.
//
// Self-exclusion rather than a filter in the workflow, so the exception travels with the
// thing it applies to and cannot be widened by editing a glob somewhere else. It is exactly
// one file, matched by resolved path rather than by name.
//
// The cost is that this file is not scanned, so a real identifier could hide in it. Two
// things bound that: it is short enough to read, and every sample in it is visibly synthetic
// — `somebody`, `builder`, `example.com`. If it ever grows past reading in one sitting, the
// answer is to assemble the samples from fragments at runtime so no identifier-shaped string
// appears in the source, and drop this exclusion.
const selfPath = fileURLToPath(import.meta.url);

for (const file of files) {
  if (resolve(file) === selfPath) continue;

  let text;
  try {
    text = readFileSync(file, 'utf8');
  } catch {
    // Unreadable is a failure, not a skip: a file that cannot be read has not been cleared.
    console.error(`::error::${file} could not be read`);
    process.exit(1);
  }

  // Binary files arrive as replacement characters rather than text; scan them anyway, since
  // a path compiled into an artefact is exactly the case that matters.
  const hits = new Map();
  for (const { name, re } of PATTERNS) {
    const global = new RegExp(re.source, `${re.flags}g`);
    const count = (text.match(global) ?? []).length;
    if (count > 0) hits.set(name, count);
  }

  if (hits.size > 0) {
    filesWithHits += 1;
    const shown = displayPath(file);
    const summary = [...hits].map(([name, n]) => `${name} x${n}`).join(', ');
    console.error(`::error::${shown}: ${summary}`);
    for (const n of hits.values()) totalHits += n;
  }
}

if (filesWithHits > 0) {
  console.error(
    `\n${totalHits} identifier match(es) in ${filesWithHits} file(s). Values are deliberately ` +
      'not printed: this log is public, and the match is the thing that must not appear in it.',
  );
  console.error('Reproduce locally with: node scripts/check-identifiers.mjs <files>');
  process.exit(1);
}

console.log(
  `checked ${files.length} file(s) against ${PATTERNS.length} self-tested patterns; no identifiers found`,
);

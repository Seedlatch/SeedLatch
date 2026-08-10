#!/usr/bin/env node
// Fail if a build artefact contains an absolute filesystem path.
//
// This exists because the shipped `.wasm` did. Rust embeds source locations for panic
// messages using the path the compiler saw, and for registry crates that is an absolute
// path on the build machine — so the module downloaded by every user carried the
// maintainer's operating-system account name, in a project published under a pseudonym.
//
// The patterns below describe the *shape* of a leak, never a specific name. Writing the
// username into the detector to keep it out of the artefact would defeat the purpose.
//
// Usage: node scripts/check-artifact-paths.mjs <file>...

import { readFileSync } from 'node:fs';

const PATTERNS = [
  [/[A-Za-z]:[\\/]{1,2}(Users|Documents|home)/i, 'Windows absolute path'],
  [/[\\/]home[\\/][a-z0-9._-]+/i, 'Unix home directory'],
  [/[\\/]Users[\\/][a-z0-9._-]+/i, 'macOS/Windows user directory'],
  [/\.cargo[\\/]registry/i, 'cargo registry path'],
  [/[\\/]\.rustup[\\/]/i, 'rustup toolchain path'],
  [/node_modules[\\/].*[\\/]node_modules/i, 'nested node_modules path'],
];

/** Printable ASCII runs of 4+ characters, the same thing `strings` extracts. */
function printableRuns(buffer) {
  const runs = [];
  let current = '';
  for (const byte of buffer) {
    if (byte >= 0x20 && byte < 0x7f) {
      current += String.fromCharCode(byte);
    } else {
      if (current.length >= 4) runs.push(current);
      current = '';
    }
  }
  if (current.length >= 4) runs.push(current);
  return runs;
}

const files = process.argv.slice(2);
if (files.length === 0) {
  console.error('usage: check-artifact-paths.mjs <file>...');
  process.exit(2);
}

let failures = 0;

for (const file of files) {
  let buffer;
  try {
    buffer = readFileSync(file);
  } catch {
    console.error(`  MISSING  ${file} — build it before checking`);
    failures += 1;
    continue;
  }

  const hits = [];
  for (const run of printableRuns(buffer)) {
    for (const [pattern, label] of PATTERNS) {
      if (pattern.test(run)) {
        hits.push({ label, run });
        break;
      }
    }
  }

  if (hits.length === 0) {
    console.log(`  clean    ${file} (${buffer.length} bytes)`);
    continue;
  }

  failures += 1;
  console.error(`  LEAK     ${file} — ${hits.length} absolute path(s)`);
  // Print the shape and a redacted excerpt. The whole point is not to reprint the
  // identifier into a CI log, which is as public as the artefact.
  for (const { label, run } of hits.slice(0, 10)) {
    const redacted = run
      .replace(/([\\/](?:Users|home)[\\/])[^\\/]+/gi, '$1<redacted>')
      .replace(/^[A-Za-z]:/, '<drive>:');
    console.error(`             ${label}: ${redacted.slice(0, 120)}`);
  }
}

if (failures > 0) {
  console.error(
    '\nAbsolute paths in a published artefact are an identity leak and a reproducibility\n' +
      'defect: the same source built by two people produces different bytes. Build through\n' +
      'scripts/build-wasm.sh, which sets --remap-path-prefix.',
  );
  process.exit(1);
}

console.log('\nNo absolute paths in any checked artefact.');

// Generates Starlight content from the canonical Markdown in /docs, keeping
// /docs as the single source of truth (its files stay pristine and their
// GitHub-relative links keep working). Run automatically before dev/build.
//
// For each page it: derives the title from the leading H1, injects Starlight
// frontmatter, drops the duplicate H1, and rewrites intra-doc links to site
// routes under the configured base.
//
// Parity history comes from git TAGS, not from committed snapshot files: every
// `v*` tag carrying docs/parity.md is a snapshot git already holds. An earlier
// version of this comment said APIM needed to keep snapshot files first, which
// had the mechanism backwards and is why the picker was missing for so long.
import { readdirSync, readFileSync, writeFileSync, rmSync, mkdirSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { collectParity, writeParityHistory, parityManifest } from './parity-versions.mjs';

const here = dirname(fileURLToPath(import.meta.url));
const DOCS_SRC = join(here, '..', '..', 'docs');
const OUT = join(here, '..', 'src', 'content', 'docs');
export const BASE = '/azure-apim-emulator/docs/';
const REPO_ROOT = join(here, '..', '..');
const PARITY = collectParity(REPO_ROOT);
const IS_RELEASE = /^v\d+\.\d+\.\d+$/.test(PARITY.version);
const PARITY_RE = /(^|\/)parity\.md$/;

// The numbered design chapters, the live parity ledger, the home page, and the
// generated schema reference.
const DOC_RE = /^(\d{2}-[a-z0-9-]+|parity|index)\.md$/;
const GENERATED_RE = /^[a-z0-9-]+\.md$/;

// `](NN-slug.md#anchor)` or `](parity.md)` -> `](/azure-apim-emulator/slug/#anchor)`
const LINK_RE = /\]\((?:\.\/|docs\/)?(\d{2}-[a-z0-9-]+|parity|index)\.md(#[^)]*)?\)/g;
// `](generated/name.md)` -> `](/azure-apim-emulator/generated/name/)`
const GEN_LINK_RE = /\]\((?:\.\/|docs\/)?generated\/([a-z0-9-]+)\.md(#[^)]*)?\)/g;

function rewriteLinks(md) {
  return md
    .replace(GEN_LINK_RE, (_m, slug, anchor) => `](${BASE}generated/${slug}/${anchor ?? ''})`)
    .replace(LINK_RE, (_m, slug, anchor) =>
      `](${BASE}${slug === 'index' ? '' : slug + '/'}${anchor ?? ''})`);
}

// "01 - Charter and parity definition" -> "Charter and parity definition".
function cleanTitle(h1) {
  return h1.replace(/^\d+[a-z]?\s*[—:-]\s*/i, '').trim();
}

// Backslashes must be escaped before quotes, or a title ending in one would
// escape the closing quote and produce unparseable frontmatter.
function yamlEscape(s) {
  return '"' + s.replace(/\\/g, '\\\\').replace(/"/g, '\\"') + '"';
}

// A banner on the live parity page naming the version it describes. Without it
// a reader cannot tell a released ledger from the tip of main.
function parityStamp() {
  const what = IS_RELEASE
    ? `release **${PARITY.version}**`
    : `**${PARITY.version}** (the live tip of \`main\`)`;
  return `:::note\nThis ledger describes ${what}. Earlier releases are under [parity history](${BASE}parity-history/).\n:::\n\n`;
}

function convert(srcPath, name, editPath) {
  const raw = readFileSync(srcPath, 'utf8');
  const lines = raw.split('\n');
  const h1Index = lines.findIndex((l) => /^#\s+/.test(l));
  const title = h1Index >= 0
    ? cleanTitle(lines[h1Index].replace(/^#\s+/, ''))
    : name.replace(/\.md$/, '');
  // Drop the H1 (Starlight renders the frontmatter title) and a trailing blank.
  if (h1Index >= 0) {
    lines.splice(h1Index, lines[h1Index + 1]?.trim() === '' ? 2 : 1);
  }
  let body = rewriteLinks(lines.join('\n').replace(/^\n+/, ''));
  if (PARITY_RE.test(name)) body = parityStamp() + body;
  // Point "Edit this page" at the real source in /docs — the generated copy
  // under src/content/docs/ is git-ignored.
  const editUrl = `https://github.com/calvinchengx/azure-apim-emulator/edit/main/docs/${editPath}`;
  return `---\ntitle: ${yamlEscape(title)}\neditUrl: ${yamlEscape(editUrl)}\n---\n\n` + body;
}

rmSync(OUT, { recursive: true, force: true });
mkdirSync(join(OUT, 'generated'), { recursive: true });

const names = readdirSync(DOCS_SRC).filter((n) => DOC_RE.test(n)).sort();
for (const name of names) {
  writeFileSync(join(OUT, name), convert(join(DOCS_SRC, name), name, name));
}

let generated = [];
try {
  generated = readdirSync(join(DOCS_SRC, 'generated')).filter((n) => GENERATED_RE.test(n)).sort();
} catch {
  generated = [];
}
for (const name of generated) {
  writeFileSync(join(OUT, 'generated', name),
    convert(join(DOCS_SRC, 'generated', name), name, `generated/${name}`));
}

const info = writeParityHistory(OUT, PARITY, { convertBody: rewriteLinks });
const DATA = join(here, '..', 'src', 'data');
mkdirSync(DATA, { recursive: true });
writeFileSync(join(DATA, 'parity-versions.json'), JSON.stringify(parityManifest(PARITY), null, 2) + '\n');
console.log(
  `sync-docs: wrote ${names.length} docs + ${generated.length} generated to src/content/docs/ ` +
    `(parity ${info.version}; ${info.snapshots.length} tagged snapshot(s))`,
);

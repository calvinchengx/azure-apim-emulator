// Generates Starlight content from the canonical Markdown in /docs, keeping
// /docs as the single source of truth (its files stay pristine and their
// GitHub-relative links keep working). Run automatically before dev/build.
//
// For each page it: derives the title from the leading H1, injects Starlight
// frontmatter, drops the duplicate H1, and rewrites intra-doc links to site
// routes under the configured base.
//
// This is the family's sync script minus the parity-version history, which
// keyvault and fabric generate from release tags. APIM has not released yet,
// so there is nothing to snapshot; add it back when it does.
import { readdirSync, readFileSync, writeFileSync, rmSync, mkdirSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';

const here = dirname(fileURLToPath(import.meta.url));
const DOCS_SRC = join(here, '..', '..', 'docs');
const OUT = join(here, '..', 'src', 'content', 'docs');
export const BASE = '/azure-apim-emulator/';

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
  const body = rewriteLinks(lines.join('\n').replace(/^\n+/, ''));
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

console.log(`sync-docs: wrote ${names.length} docs + ${generated.length} generated to src/content/docs/`);

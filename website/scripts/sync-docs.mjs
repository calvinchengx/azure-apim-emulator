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

// The page's own meta description, taken from the first real paragraph.
//
// WHY. Starlight falls back to the SITE description when a page declares none,
// so every page of a site shipped the same `<meta name="description">` --
// checked on three pages of this site and they were byte-identical. Google
// discards duplicate descriptions and writes its own snippet, so 300+ pages
// across this family were competing with one sentence between them.
//
// FIRST PARAGRAPH, not a summary. It is the one sentence the author already
// wrote to introduce the page, and deriving it means it cannot go stale. Skips
// headings, code fences, tables, quotes, images, lists and HTML, which are all
// things that read badly as a search snippet.
//
// Absent rather than empty when nothing suitable is found: Starlight then falls
// back to the site description, which is the old behaviour and no worse.
function description(raw) {
  const lines = raw.split('\n');
  let inFence = false;
  const para = [];
  for (const line of lines) {
    const t = line.trim();
    if (/^(```|~~~)/.test(t)) { inFence = !inFence; continue; }
    if (inFence) continue;
    if (para.length === 0) {
      if (!t) continue;
      if (/^(#|>|\||-|\*|\d+\.|!\[|<)/.test(t)) continue;
      para.push(t);
    } else {
      if (!t || /^(#|>|\||```|~~~)/.test(t)) break;
      para.push(t);
    }
  }
  if (para.length === 0) return null;
  // Markdown emphasis, links and code marks read as noise in a snippet.
  let text = para
    .join(' ')
    .replace(/\[([^\]]+)\]\([^)]*\)/g, '$1')
    .replace(/[`*_]/g, '')
    .replace(/\s+/g, ' ')
    .trim();
  // 25, not 40. "Seven services, one discipline." is 30 characters and is a
  // better description than the site-wide sentence it would otherwise inherit:
  // distinctive and short beats generic and long, for a snippet.
  if (text.length < 25) return null;
  // Search engines truncate around 160; cut on a sentence, else on a word.
  if (text.length > 160) {
    const stop = text.lastIndexOf('. ', 160);
    text = stop > 80 ? text.slice(0, stop + 1)
                     : text.slice(0, text.lastIndexOf(' ', 157)) + '\u2026';
  }
  return text;
}

const entries = [];

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
  const desc = description(raw);
  // Top-level docs only. `generated/` holds machine-produced operation and
  // policy inventories: thousands of rows that answer no question a reader
  // asks, and pointing a model at them buries the pages that do.
  if (editPath === name) entries.push({ slug: name.replace(/\.md$/, ''), title, desc });
  return (
    `---\ntitle: ${yamlEscape(title)}\n` +
    (desc ? `description: ${yamlEscape(desc)}\n` : '') +
    `editUrl: ${yamlEscape(editUrl)}\n---\n\n` + body
  );
}


// ---------------------------------------------------------------------------
// llms.txt for this site.
//
// A PROPOSED convention (llmstxt.org), not a standard: a markdown file at a
// site root giving a model a short, link-dense map of what the site holds, so
// a crawler need not infer the shape from HTML. No major provider has
// committed to consuming it. It is cheap and cannot hurt; it is not a
// substitute for the per-page descriptions above, which affect search today.
//
// GENERATED FROM THE SAME PASS that writes the pages, so the title, the
// description and the URL of every entry are the ones actually published. A
// hand-written index of a docs tree is wrong within a fortnight.
//
// Written to public/, which Astro copies to the root of the built site, so it
// lands beside the pages it describes at whatever `base` this site uses.
const LLMS_TITLE = 'Azure APIM Emulator';
const LLMS_BLURB = 'A local emulator of the Azure API Management management plane, gateway and policy engine, with real challenge-based authentication against entra-emulator. Every green parity claim names the test that proves it.';

function writeLlms(entries) {
  const origin = 'https://calvinchengx.github.io';
  const out = [`# ${LLMS_TITLE}`, '', `> ${LLMS_BLURB}`, '', '## Documentation', ''];
  for (const e of entries) {
    const url = `${origin}${BASE}${e.slug}/`;
    out.push(e.desc ? `- [${e.title}](${url}): ${e.desc}` : `- [${e.title}](${url})`);
  }
  out.push('');
  const dir = join(here, '..', 'public');
  mkdirSync(dir, { recursive: true });
  writeFileSync(join(dir, 'llms.txt'), out.join('\n'));
  return entries.length;
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
const llms = writeLlms(entries);
console.log(
  `sync-docs: wrote ${names.length} docs + ${generated.length} generated to src/content/docs/ ` +
    `(parity ${info.version}; ${info.snapshots.length} tagged snapshot(s))`,
);

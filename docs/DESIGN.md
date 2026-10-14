# Site design — `docs/index.html`

The visual identity for the GitHub Pages landing page. It exists so the page can be
extended (or rebuilt) without inventing a second look: every colour, size and motif below
is already in use on the page.

## The concept

**A printed permission record.** The page is the artefact the product produces — a
notarised audit document — so the page *is* the demo. Cool paper, ink typography, hairline
rules, monospace ledger tables, and one rubber stamp. Nothing on the page is decorative
unless it also carries meaning.

Corollary: the page makes **zero third-party requests**. Fonts are self-hosted, charts are
inline SVG, there is no analytics and no web font CDN. The product is one static binary
with no daemon; a landing page that phoned home would contradict the claim.

## Palette

Three paper surfaces, three ink weights, four signals.

| Token | Value | Use |
| --- | --- | --- |
| `--paper` | `#e7e8e3` | page ground — cool grey paper, deliberately not cream |
| `--paper-raised` | `#f1f2ee` | mocks, cards lifted off the ground |
| `--paper-form` | `#fbfbf8` | the form/record boxes — the whitest thing on the page |
| `--ink` | `#14181a` | headings, rules that mean "border", button fills |
| `--ink-2` | `#3c4441` | body copy |
| `--ink-3` | `#585f58` | captions, column labels — 5.3:1 on `--paper`, AA |
| `--rule` | `#c2c6bc` | hairline rules |
| `--rule-soft` | `#d7dad2` | inner table rules |
| `--allow` | `#2f6b45` | allowed / survived |
| `--ask` | `#7d580d` | requires approval — ochre, never amber |
| `--deny` | `#a02e20` | denied, and the stamp |
| `--skip` | `#5d6468` | not executed (a missing binary is not a block) |

Signals are **meaning-bearing only**. If a colour does not say allow/ask/deny/skip, it is
ink or paper. Every text/background pair above clears WCAG AA (axe reports 0 violations;
re-check with the command in Verification).

## Type

| Role | Family | Notes |
| --- | --- | --- |
| Display, `h1`–`h3` | Fraunces (variable, self-hosted) | `h1` is `clamp(2.5rem, 5.1vw, 4.15rem)`, weight 600, `-.032em` tracking |
| Body | Public Sans | `clamp(15.5px, 1.02vw, 17px)` / 1.62 |
| Data, commands, labels | JetBrains Mono | anything a terminal would print, plus every number |

Rules that hold the identity together:

- The hero's third line is Fraunces **italic** (`h1 em`, weight 500, `'opsz' 144`). That is
  the only display italic on the page; body italic is reserved for quoted agent speech and
  code comments. Do not add a second display voice.
- Numbers are always mono with `font-variant-numeric: tabular-nums` (`.num, table,
  .stat-val, .ledger td`). Counts must line up in columns.
- `text-wrap: balance` on headings, `text-wrap: pretty` on paragraphs. No manual `<br>`
  in prose.
- Anything the shell would print is wrapped in `translate="no"` — commands, rule names,
  paths, JSON.
- No ALL-CAPS tracked eyebrows, no `A · B · C` meta strings for decoration. The `·`
  separator appears only inside real record strings (dates, ledger details).

## Layout

- `--wrap-max: 1220px`, `--gutter: clamp(20px, 4.2vw, 60px)`.
- Sections are `.clause`s: a two-column grid of `--margin-col` (150px, 108px under 1080px)
  and the content. The narrow column holds `§01 … §09` and the section name — a document's
  running head, not a badge.
- `.clause` carries the gutter with `padding-inline: max(var(--gutter), calc(50% -
  (var(--wrap-max)/2) + var(--gutter)))` so the hairline `border-top` stays full-bleed
  while the content aligns with `.wrap` blocks (hero, install, stats, footer). Keep that
  formula — a plain `max-width` on `.clause` would break the rule across the page.
- Body measure is `--measure: 62ch`. Tables and charts may run wider; prose may not.
- Breakpoints: 1080 (margin column shrinks, hero stacks), 860 (clauses go single-column,
  nav becomes a horizontally scrollable strip), 560 (stamp re-anchors into the record's
  blank ruled band, hero actions stack).
- Anything that scrolls sideways (`.table-scroll`, `.nav-scroll`) fades whichever edges
  still have content off-screen: `site.js` toggles `.scrolls` (more to see right) and
  `.scrolls-start` (content scrolled past on the left), and `--fade` sets the band width
  per element. The mask lives on the scroller itself, never on an element carrying a
  border — the nav's `border-top` sits on the non-scrolling `.nav` wrapper so the hairline
  stays full-bleed.

## Motifs

- **The decision record** (`.record`) — a form with a ruled body, a head strip
  (`DECISION RECORD · AV-1 · date`) and a footer (`agentvault verify` / `✓ OK`). Only real
  transcript text goes inside it.
- **The stamp** (`.stamp`) — one per page, `DENIED`, rotated `-7deg`, `--deny` outline. It
  lands once on load (`stamp-land`) and never animates again.
- **Verdict text** (`.v-allow` / `.v-ask` / `.v-deny`) — colour plus the literal word; the
  colour is never the only signal.
- **The ledger** (`.ledger`) — action, target, verdict, rule, eval, source. Tabular mono
  numbers, hairline row rules, no zebra striping, no rounded container.
- **The evidence exhibit** (`.evidence`) — a real screenshot pasted into the document:
  1px ink border, no radius, no shadow, caption in `--ink-3` underneath.
- **Anti-motif:** no nested boxes. A section is a rule plus its content. One container per
  region, maximum.

## Motion

Exactly one thing animates on load, and only under `prefers-reduced-motion:
no-preference`: the stamp lands (`stamp-land`, 620ms, once). Everything else is a
`~150ms` colour transition on an interactive element. `--ease: cubic-bezier(.22,.61,.36,1)`.
Under `reduce`, scroll behaviour is `auto` and durations collapse to `0.001ms`.

## Numbers on the page

Every measured figure is generated, never typed. `scripts/gen_site_proof.py --write` reads
`docs/redteam/CORPUS_RESULTS.json` and `LEGIT_RESULTS.json` and replaces the four blocks
between `<!-- BEGIN GENERATED: BARS | CATEGORY MATRIX | LEGIT MATRIX | SCORECARD -->` and
their `END` markers with inline SVG and tables.

- Never hand-edit inside those markers; the next run overwrites it.
- After changing the corpus or the JSON, re-run the script and diff `docs/index.html`.
- Chart labels are placed by a `PLACE` dict in the script (anchor + x/y offsets). The
  scorecard uses three-line callouts because two two-line labels cannot share the
  100%/100% corner.
- Copy that quotes a number must match the JSON. If a figure changes, regenerate and
  re-read the prose around it.

## Assets

| File | Source | Regenerate |
| --- | --- | --- |
| `assets/mark.svg`, `favicon.svg` | hand-authored vault-and-keyhole mark | edit the SVG |
| `assets/mark-192.png` | the mark, rasterised for `apple-touch-icon` | Chrome screenshot of the SVG at 192×192 |
| `assets/og.png` (1200×630) | `scripts/og_card.html` | the one-liner in that file's header comment |
| `img/demo-run.png` (1086×537) | last frame of `img/demo.cast` | `agg --font-size 22 --emoji-font-family "Apple Symbols" --select 100% docs/img/demo.cast out.png`, then trim blank rows |
| `img/demo.gif`, `img/demo.cast` | `scripts/demo.sh` under asciinema | re-run the script; it is the recording's origin |

## Verification

The page is checked with system Chrome through Playwright, served statically:

```
python3 -m http.server 8912 --directory docs
```

Four things must hold before any change to `docs/` is pushed:

1. **No horizontal overflow** at 1440 / 1280 / 834 / 390, and every `<img>` has intrinsic
   dimensions while every `<svg>` has a `role="img"` label.
2. **axe: 0 violations** with `wcag2a, wcag2aa, wcag21aa` tags.
3. **Focus is never under the sticky masthead** — `--focus-clearance` (80px desktop,
   116px under 860px) is applied as `scroll-margin-block` on interactive elements and as
   `scroll-margin-top` on `.clause`.
4. **Copy behaves** — the install button writes the real command to the clipboard and the
   `aria-live` region announces it.

Harness scripts live outside the repo (`/tmp/avsite`): `verify.js`, `a11y.js`,
`focusclear.js`, `copy.js`, `hint.js`, `sections.js`, `fold.js`. Run each with
`NODE_PATH="<path-to-node_modules>" node <script>.js`.

## Do / don't

- Do add a section as another `§` clause with the same margin column and hairline.
- Do state a limitation next to the number it qualifies — §05's Docker row executed 92 of
  103, and the table says so.
- Don't add a gradient, a blur, a rounded card, an emoji outside the product's own strings,
  or a second accent colour.
- Don't write a figure by hand that the generator can produce, and don't render a mock UI
  whose text differs from what `internal/approval/` actually prints.

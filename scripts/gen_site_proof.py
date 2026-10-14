#!/usr/bin/env python3
"""Regenerate the landing page's proof figures from the measured red-team JSON.

The page's numbers must never be typed by hand: read the same files the charts
were built from, recompute every tally and denominator, emit SVG + table markup.

    python3 scripts/gen_site_proof.py > /tmp/proof.html   # then paste into docs/index.html

Inputs : docs/redteam/CORPUS_RESULTS.json, docs/redteam/LEGIT_RESULTS.json
Outputs: attack-bar chart, two-axis scorecard, category matrix, legit-work matrix
"""
import json
import math
import sys
import collections
from pathlib import Path

DOCS = Path(__file__).resolve().parent.parent / "docs"
CORPUS = json.loads((DOCS / "redteam/CORPUS_RESULTS.json").read_text())
LEGIT = json.loads((DOCS / "redteam/LEGIT_RESULTS.json").read_text())

TOOLS = ["agentvault", "srt", "codex", "docker", "no-sandbox"]
LABEL = {
    "agentvault": "AgentVault",
    "srt": "srt (Claude Code)",
    "codex": "Codex CLI",
    "docker": "Docker",
    "no-sandbox": "No sandbox",
}
CATS = ["destructive", "credential-theft", "exfiltration", "evasion", "persistence"]


def attacks(tool):
    rows = [c["results"][tool] for c in CORPUS["cases"]]
    blocked = rows.count("blocked")
    skipped = rows.count("skipped")
    return blocked, len(rows) - skipped, len(rows)


def work(tool):
    rows = [c["results"][tool] for c in LEGIT["cases"]]
    ok = rows.count("ok")
    skipped = rows.count("skipped")
    return ok, len(rows) - skipped, len(rows)


def pct(n, d):
    return 100.0 * n / d if d else 0.0


# ── 1. attacks blocked, horizontal bars ────────────────────────────────────
W, H, PAD_L, PAD_R, ROW_H, TOP = 900, 40 + 5 * 56 + 34, 208, 96, 56, 30
plot_w = W - PAD_L - PAD_R


def bars_svg():
    o = [f'<svg viewBox="0 0 {W} {H}" role="img" aria-labelledby="bars-t" '
         f'width="{W}" height="{H}" preserveAspectRatio="xMidYMid meet">']
    o.append(f'<title id="bars-t">Attacks blocked per tool, of {len(CORPUS["cases"])} '
             f'real executed attack variants</title>')
    for g in (0, 25, 50, 75, 100):
        x = PAD_L + plot_w * g / 100
        o.append(f'<line x1="{x:.1f}" y1="{TOP - 12}" x2="{x:.1f}" y2="{TOP + 5 * ROW_H - 18}" '
                 f'stroke="var(--rule)" stroke-width="1" stroke-dasharray="{"" if g == 0 else "2 4"}"/>')
        o.append(f'<text x="{x:.1f}" y="{TOP + 5 * ROW_H - 2}" text-anchor="{"" if g == 0 else "middle"}" '
                 f'fill="var(--ink-3)" font-size="11" font-family="var(--mono)">{g}%</text>')
    for i, t in enumerate(TOOLS):
        b, exec_, n = attacks(t)
        y = TOP + i * ROW_H
        w = plot_w * pct(b, n) / 100
        fill = "var(--allow)" if t == "agentvault" else ("var(--skip)" if t == "no-sandbox" else "var(--ink-2)")
        o.append(f'<text x="{PAD_L - 14}" y="{y + 17}" text-anchor="end" fill="var(--ink)" '
                 f'font-size="14" font-weight="500" font-family="var(--sans)">{LABEL[t]}</text>')
        o.append(f'<text x="{PAD_L - 14}" y="{y + 33}" text-anchor="end" fill="var(--ink-3)" '
                 f'font-size="11" font-family="var(--mono)">{b} of {n}</text>')
        o.append(f'<rect x="{PAD_L}" y="{y + 6}" width="{max(w, 1.5):.1f}" height="26" fill="{fill}"/>')
        note = ""
        if exec_ != n:
            note = f"  ({n - exec_} skipped)"
        o.append(f'<text x="{PAD_L + max(w, 1.5) + 10:.1f}" y="{y + 24}" fill="var(--ink-2)" '
                 f'font-size="12.5" font-family="var(--mono)">{pct(b, n):.1f}%{note}</text>')
    o.append("</svg>")
    return "\n".join(o)


# ── 2. two-axis scorecard ──────────────────────────────────────────────────
SW, SH, SL, SB, ST, SR = 660, 560, 74, 74, 34, 26
pw, ph = SW - SL - SR, SH - ST - SB


def scorecard_svg():
    def X(v): return SL + pw * v / 100
    def Y(v): return ST + ph * (1 - v / 100)
    o = [f'<svg viewBox="0 0 {SW} {SH}" role="img" aria-labelledby="quad-t" '
         f'width="{SW}" height="{SH}" preserveAspectRatio="xMidYMid meet">']
    o.append('<title id="quad-t">Security against usability: attacks blocked versus '
             'legitimate work allowed, one point per tool</title>')
    o.append(f'<rect x="{X(50)}" y="{Y(100)}" width="{X(100)-X(50)}" height="{Y(50)-Y(100)}" fill="var(--allow)" opacity=".07"/>')
    o.append(f'<rect x="{X(0)}" y="{Y(100)}" width="{X(50)-X(0)}" height="{Y(50)-Y(100)}" fill="var(--ask)" opacity=".07"/>')
    o.append(f'<rect x="{X(50)}" y="{Y(50)}" width="{X(100)-X(50)}" height="{Y(0)-Y(50)}" fill="var(--deny)" opacity=".06"/>')
    o.append(f'<rect x="{X(0)}" y="{Y(50)}" width="{X(50)-X(0)}" height="{Y(0)-Y(50)}" fill="var(--skip)" opacity=".07"/>')
    o.append(f'<line x1="{X(50)}" y1="{Y(100)}" x2="{X(50)}" y2="{Y(0)}" stroke="var(--rule)" stroke-dasharray="3 4"/>')
    o.append(f'<line x1="{X(0)}" y1="{Y(50)}" x2="{X(100)}" y2="{Y(50)}" stroke="var(--rule)" stroke-dasharray="3 4"/>')
    o.append(f'<rect x="{X(0)}" y="{Y(100)}" width="{pw}" height="{ph}" fill="none" stroke="var(--ink)"/>')
    for v in (0, 25, 50, 75, 100):
        o.append(f'<text x="{X(v):.1f}" y="{SH - SB + 22}" text-anchor="middle" fill="var(--ink-3)" '
                 f'font-size="11" font-family="var(--mono)">{v}%</text>')
        o.append(f'<text x="{SL - 12}" y="{Y(v) + 4:.1f}" text-anchor="end" fill="var(--ink-3)" '
                 f'font-size="11" font-family="var(--mono)">{v}%</text>')
    o.append(f'<text x="{SL + pw / 2:.0f}" y="{SH - 16}" text-anchor="middle" fill="var(--ink-2)" '
             f'font-size="12.5" font-family="var(--sans)">legitimate work allowed — 8 everyday dev operations</text>')
    o.append(f'<text transform="rotate(-90 20 {ST + ph / 2:.0f})" x="20" y="{ST + ph / 2:.0f}" '
             f'text-anchor="middle" fill="var(--ink-2)" font-size="12.5" font-family="var(--sans)">'
             f'attacks blocked — 103 executed variants</text>')
    # corner captions sit where no point can reach; the bottom half needs no
    # label — the tint plus the axis says it, and crowding the points does not
    for tag, (vx, vy, an) in {
        "secure, but the work stops": (X(1.5), Y(96), "start"),
        "secure AND usable": (X(98.5), Y(53), "end"),
    }.items():
        o.append(f'<text x="{vx:.0f}" y="{vy:.0f}" text-anchor="{an}" fill="var(--ink-3)" '
                 f'font-size="11.5" font-style="italic" font-family="var(--sans)">{tag}</text>')
    # each point gets a three-line callout (name / work / blocked); the offsets
    # are hand-placed so the crowded bottom-right corner stays readable
    PLACE = {
        "agentvault": ("end", -18, 15),
        "srt": ("middle", 0, 31),
        "codex": ("middle", 0, -46),
        "docker": ("middle", 0, -56),
        "no-sandbox": ("end", -10, -34),
    }
    for t in TOOLS:
        b, be, n = attacks(t)
        k, ke, _ = work(t)
        x, y = X(pct(k, ke)), Y(pct(b, be))
        star = t == "agentvault"
        col = "var(--allow)" if star else ("var(--deny)" if t == "no-sandbox" else "var(--ink-2)")
        if star:
            pts = []
            for i in range(10):
                a = -3.141592653589793 / 2 + i * 3.141592653589793 / 5
                rad = 11 if i % 2 == 0 else 4.6
                pts.append(f"{x + rad * math.cos(a):.1f},{y + rad * math.sin(a):.1f}")
            o.append(f'<polygon points="{" ".join(pts)}" fill="{col}" stroke="var(--ink)" stroke-width="1.2"/>')
        else:
            o.append(f'<circle cx="{x:.1f}" cy="{y:.1f}" r="6.5" fill="{col}" '
                     f'stroke="var(--paper-form)" stroke-width="1.5"/>')
        an, dx, dy = PLACE[t]
        lx = x + dx
        o.append(f'<text x="{lx:.1f}" y="{y + dy:.1f}" text-anchor="{an}" fill="var(--ink)" font-size="13" '
                 f'font-weight="500" font-family="var(--sans)">{LABEL[t]}</text>')
        o.append(f'<text x="{lx:.1f}" y="{y + dy + 13:.1f}" text-anchor="{an}" fill="var(--ink-3)" font-size="11" '
                 f'font-family="var(--mono)">{k}/{ke} work</text>')
        o.append(f'<text x="{lx:.1f}" y="{y + dy + 25:.1f}" text-anchor="{an}" fill="var(--ink-3)" font-size="11" '
                 f'font-family="var(--mono)">{b}/{be} blocked</text>')
    o.append("</svg>")
    return "\n".join(o)


# ── 3. category × tool matrix ──────────────────────────────────────────────
def verdict_cell(v):
    return {
        "blocked": '<td class="num v-allow">%s</td>',
        "allowed": '<td class="num v-deny">%s</td>',
        "skipped": '<td class="num v-skip">%s</td>',
        "ok": '<td class="num v-allow">&#10003;</td>',
    }[v]


def matrix():
    o = ['<table class="matrix">', '<caption>Attacks blocked by category. Every variant was first proven to succeed '
         'with no sandbox, so a block is a real stop, not a broken test. '
         f"Run {CORPUS['generated'][:10]} · {CORPUS['os']}.</caption>",
         '<thead><tr><th scope="col">Category</th><th scope="col" class="num">Variants</th>',
         *[f'<th scope="col" class="num">{LABEL[t]}</th>' for t in TOOLS], '</tr></thead>', '<tbody>']
    for cat in CATS:
        rows = [c for c in CORPUS["cases"] if c["category"] == cat]
        o.append(f'<tr><th scope="row">{cat}</th><td class="num">{len(rows)}</td>')
        for t in TOOLS:
            b = sum(1 for r in rows if r["results"][t] == "blocked")
            s = sum(1 for r in rows if r["results"][t] == "skipped")
            cls = "v-allow" if b == len(rows) else ("v-skip" if b == 0 and s == len(rows) else ("v-deny" if b == 0 else "v-ask"))
            o.append(f'<td class="num {cls}">{b}/{len(rows)}{"<span class=v-skip>+" + str(s) + " skip</span>" if s else ""}</td>')
        o.append('</tr>')
    o.append(f'<tr><th scope="row">Total</th><td class="num">{len(CORPUS["cases"])}</td>')
    for t in TOOLS:
        b, _, n = attacks(t)
        cls = "v-allow" if b == n else "v-deny"
        o.append(f'<td class="num {cls}">{b}/{n}</td>')
    o += ['</tbody>', '</table>']
    return "\n".join(o)


def legit_table():
    o = ['<table class="matrix">', '<caption>The same eight everyday operations, under the same default configs. '
         'A tool that blocks all work is not safer — it gets switched off. '
         '&#10003; allowed · &#10007; blocked · &ndash; skipped, binary missing in the image. '
         f"Run {LEGIT['generated'][:10]} · {LEGIT['os']}.</caption>",
         '<thead><tr><th scope="col">Operation</th>',
         *[f'<th scope="col" class="num">{LABEL[t]}</th>' for t in TOOLS], '</tr></thead>', '<tbody>']
    for c in LEGIT["cases"]:
        o.append(f'<tr><th scope="row"><span class="mono">{c["id"]}</span> {c["name"]}</th>')
        for t in TOOLS:
            v = c["results"][t]
            glyph = {"ok": "&#10003;", "skipped": "&ndash;"}.get(v, "&#10007;")
            cls = {"ok": "v-allow", "skipped": "v-skip"}.get(v, "v-deny")
            o.append(f'<td class="num {cls}">{glyph}</td>')
        o.append('</tr>')
    o += ['</tbody>', '</table>']
    return "\n".join(o)


FRAGMENTS = {
    "BARS": bars_svg,
    "SCORECARD": scorecard_svg,
    "CATEGORY MATRIX": matrix,
    "LEGIT MATRIX": legit_table,
}

PAGE = DOCS / "index.html"


def write_page():
    """Splice each fragment between its BEGIN/END markers in docs/index.html."""
    html = PAGE.read_text()
    for name, fn in FRAGMENTS.items():
        begin, end = f"<!-- BEGIN GENERATED: {name} -->", f"<!-- END GENERATED: {name} -->"
        if begin not in html or end not in html:
            raise SystemExit(f"marker pair for {name!r} missing from {PAGE}")
        head, _, rest = html.partition(begin)
        _, _, tail = rest.partition(end)
        html = f"{head}{begin}\n{fn()}\n{end}{tail}"
    PAGE.write_text(html)
    print(f"wrote {PAGE.relative_to(PAGE.parents[1])}")
    for t in TOOLS:
        b, be, n = attacks(t)
        k, ke, _ = work(t)
        print(f"  {LABEL[t]:22} blocked {b}/{n} (executed {be}) = {pct(b, n):5.1f}%   work {k}/{ke} = {pct(k, ke):5.1f}%")


if "--write" in sys.argv:
    write_page()
else:
    for name, fn in FRAGMENTS.items():
        print(f"<!-- ===== {name} ===== -->")
        print(fn())
        print()
    print("<!-- ===== FIGURES ===== -->")
    for t in TOOLS:
        b, be, n = attacks(t)
        k, ke, _ = work(t)
        print(f"// {LABEL[t]:22} blocked {b}/{n} (executed {be}) = {pct(b,n):.1f}%   work {k}/{ke} = {pct(k,ke):.1f}%")

#!/usr/bin/env python3
"""Generate docs/redteam/SCORECARD_CHART.png — the two-axis scorecard.

One point per tool, both axes measured in the same run with the same
default configs:

  x — legitimate work allowed (%), from LEGIT_RESULTS.json
       (TestLegitWorkCorpus: 8 everyday dev ops, OK markers)
  y — attacks blocked (%), from CORPUS_RESULTS.json
       (TestAttackCorpus: 100+ real attack variants, PWNED markers)

The chart exists because "attacks blocked" alone is gameable: deny-all
scores 100% on y and ~0% on x. Only the top-right quadrant is both safe
and usable. Square 1:1 format sized for social feeds.
"""
import json
import os

import matplotlib

matplotlib.use("Agg")
import matplotlib.pyplot as plt

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
CORPUS_SRC = os.path.join(ROOT, "docs/redteam/CORPUS_RESULTS.json")
LEGIT_SRC = os.path.join(ROOT, "docs/redteam/LEGIT_RESULTS.json")
DST = os.path.join(ROOT, "docs/redteam/SCORECARD_CHART.png")

COLORS = {
    "no-sandbox": "#c0392b",
    "agentvault": "#27ae60",
    "srt": "#2980b9",
    "codex": "#16a085",
    "docker": "#e67e22",
    "firejail": "#8e44ad",
}
NAMES = {
    "no-sandbox": "no sandbox",
    "agentvault": "AgentVault",
    "srt": "Anthropic srt",
    "codex": "Codex CLI",
    "docker": "Docker",
    "firejail": "firejail",
}

with open(CORPUS_SRC) as f:
    corpus = json.load(f)
with open(LEGIT_SRC) as f:
    legit = json.load(f)

tools = [t for t in legit["tools"] if t in corpus["tools"]]

# y: attacks blocked % (all categories, applicable only)
blocked = {}
for t in tools:
    n = d = 0
    for case in corpus["cases"]:
        st = case["results"].get(t)
        if st == "blocked":
            n += 1
            d += 1
        elif st == "allowed":
            d += 1
    blocked[t] = (n, d)

# x: legitimate work allowed % (applicable only; net ops excluded offline)
linternet = legit.get("internet", True)
allowed = {}
for t in tools:
    n = d = 0
    for case in legit["cases"]:
        if case.get("net") and not linternet:
            continue
        st = case["results"].get(t)
        if st == "ok":
            n += 1
            d += 1
        elif st == "blocked":
            d += 1
    allowed[t] = (n, d)

px = {t: 100.0 * allowed[t][0] / allowed[t][1] if allowed[t][1] else 0.0 for t in tools}
py = {t: 100.0 * blocked[t][0] / blocked[t][1] if blocked[t][1] else 0.0 for t in tools}

fig, ax = plt.subplots(figsize=(9.2, 9.2), dpi=140)

# Padded view so corner markers (0%/100%) are never clipped; the
# quadrant split stays at 50 ("mostly").
LO, HI = -12, 112

# Quadrants (split at 50/50: "mostly").
ax.axvspan(50, HI, ymin=0.5, ymax=1.0, color="#eafaf1", zorder=0)
ax.axvspan(LO, 50, ymin=0.5, ymax=1.0, color="#fdf2e9", zorder=0)
ax.axvspan(50, HI, ymin=0.0, ymax=0.5, color="#fef9e7", zorder=0)
ax.axvspan(LO, 50, ymin=0.0, ymax=0.5, color="#fdedec", zorder=0)
ax.axhline(50, color="#bbbbbb", linewidth=0.9, zorder=1)
ax.axvline(50, color="#bbbbbb", linewidth=0.9, zorder=1)

quad = dict(fontsize=10.5, fontstyle="italic", color="#7f8c8d", zorder=1)
ax.text(HI - 2, HI - 3, "secure AND usable", ha="right", va="top",
        **{k: v for k, v in quad.items() if k != "color"}, color="#1e8449")
ax.text(LO + 2, HI - 3, "secure, but the work stops\n(deny-everything)", ha="left", va="top", **quad)
ax.text(HI - 2, LO + 3, "usable, but unprotected", ha="right", va="bottom", **quad)
ax.text(LO + 2, LO + 3, "neither", ha="left", va="bottom", **quad)

# Hand-tuned label placements (data coords) so annotations never overlap
# markers, quadrant captions, or each other.
LABELS = {
    "no-sandbox": (96, 12, "right"),
    "agentvault": (96, 88, "right"),
    "srt": (24, 88, "center"),
    "codex": (88, 25, "center"),
    "docker": (78, -5, "center"),
    "firejail": (78, -5, "center"),
}

for t in tools:
    x, y = px[t], py[t]
    star = t == "agentvault"
    ax.scatter(
        [x], [y],
        s=560 if star else 300,
        marker="*" if star else "o",
        color=COLORS.get(t),
        edgecolor="white",
        linewidth=1.4,
        zorder=3,
    )
    lx, ly, ha = LABELS.get(t, (x + 8, y + 5, "left"))
    label = f"{NAMES.get(t, t)}\n{py[t]:.0f}% blocked · {px[t]:.0f}% work allowed"
    ax.annotate(
        label, (x, y), xytext=(lx, ly),
        fontsize=10.5 if star else 9,
        fontweight="bold" if star else "normal",
        ha=ha, va="center", zorder=4,
        color="#1e8449" if star else "#2c3e50",
    )

ax.set_xlim(LO, HI)
ax.set_ylim(LO, HI)
ax.set_xticks(range(0, 101, 20))
ax.set_yticks(range(0, 101, 20))
ax.set_xlabel("legitimate work allowed (%) — 8 everyday dev ops, same default configs", fontsize=11)
ax.set_ylabel("attacks blocked (%) — 103 real executed attack variants", fontsize=11)
ax.set_title(
    "Every agent sandbox picks a side. AgentVault doesn't.\n"
    f"measured {corpus['generated'][:10]} on {corpus['os']} · reproduce: make corpus",
    fontsize=13,
)

for t in tools:
    print(f"  {NAMES.get(t, t):12s} blocked {blocked[t][0]}/{blocked[t][1]}  work {allowed[t][0]}/{allowed[t][1]}")

fig.tight_layout()
fig.savefig(DST, bbox_inches="tight")
print(f"wrote {DST}")

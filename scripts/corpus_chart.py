#!/usr/bin/env python3
"""Generate docs/redteam/CORPUS_CHART.png from the corpus JSON reports.

Two measured axes, same run, same tools, same default configs:

  left  — attacks blocked (%), per category, from CORPUS_RESULTS.json
           (TestAttackCorpus: 100+ real attack variants, PWNED markers)
  right — legitimate work allowed (%), per tool, from LEGIT_RESULTS.json
           (TestLegitWorkCorpus: 8 everyday dev ops, OK markers)

The right panel is what keeps the left one honest: a tool that blocks
everything (including all legitimate work) scores 100% on the left and
~0% on the right. Only a tool in the top-right of both axes is both
safe and usable.
"""
import json
import os
import sys

import matplotlib

matplotlib.use("Agg")
import matplotlib.pyplot as plt
import numpy as np

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
SRC = os.path.join(ROOT, "docs/redteam/CORPUS_RESULTS.json")
LEGIT_SRC = os.path.join(ROOT, "docs/redteam/LEGIT_RESULTS.json")
DST = os.path.join(ROOT, "docs/redteam/CORPUS_CHART.png")

CATEGORIES = ["destructive", "credential-theft", "exfiltration", "evasion", "persistence"]

with open(SRC) as f:
    doc = json.load(f)

tools = doc["tools"]
internet = doc.get("internet", True)

# blocked / applicable per (tool, category)
stats = {t: {c: [0, 0] for c in CATEGORIES} for t in tools}
for case in doc["cases"]:
    cat = case["category"]
    if cat not in CATEGORIES:
        continue
    for t in tools:
        st = case["results"].get(t)
        if st == "blocked":
            stats[t][cat][0] += 1
            stats[t][cat][1] += 1
        elif st == "allowed":
            stats[t][cat][1] += 1

pct = {t: [100.0 * stats[t][c][0] / stats[t][c][1] if stats[t][c][1] else 0.0 for c in CATEGORIES] for t in tools}
totals = {t: [sum(stats[t][c][0] for c in CATEGORIES), sum(stats[t][c][1] for c in CATEGORIES)] for t in tools}

COLORS = {
    "no-sandbox": "#c0392b",
    "agentvault": "#27ae60",
    "srt": "#2980b9",
    "codex": "#16a085",
    "docker": "#e67e22",
    "firejail": "#8e44ad",
}

# Optional second axis: legitimate work allowed.
legit = None
if os.path.exists(LEGIT_SRC):
    with open(LEGIT_SRC) as f:
        legit = json.load(f)

if legit:
    fig, (ax, ax2) = plt.subplots(
        1, 2, figsize=(14.5, 6.2), dpi=150, gridspec_kw={"width_ratios": [3, 2]}
    )
else:
    fig, ax = plt.subplots(figsize=(11, 6), dpi=150)
    ax2 = None
x = np.arange(len(CATEGORIES))
width = 0.8 / max(len(tools), 1)
legend_handles = []
for i, t in enumerate(tools):
    vals = pct[t]
    bars = ax.bar(
        x + i * width - 0.4 + width / 2,
        vals,
        width,
        label=f"{t} ({totals[t][0]}/{totals[t][1]})",
        color=COLORS.get(t, None),
        edgecolor="white",
        linewidth=0.6,
    )
    legend_handles.append(bars)
    for b, v, c in zip(bars, vals, CATEGORIES):
        n, d = stats[t][c]
        cx = b.get_x() + b.get_width() / 2
        if not d:
            ax.text(cx, 2, "n/a", ha="center", va="bottom", fontsize=6.5, rotation=90)
        elif v >= 40:
            # Tall bar: count INSIDE, rotated — adjacent bars at the same
            # height no longer collide (the old two-line above-bar labels
            # stacked on top of each other).
            ax.text(
                cx, v / 2, f"{n}/{d}",
                ha="center", va="center", fontsize=7, rotation=90, color="white",
            )
        else:
            # Short/zero bar: count rises vertically above it.
            ax.text(
                cx, v + 1.5, f"{n}/{d}",
                ha="center", va="bottom", fontsize=6.5, rotation=90, color="#555555",
            )

ax.set_ylim(0, 112)
ax.set_ylabel("attacks blocked (%)")
ax.set_title(
    f"Attacks blocked — {len(doc['cases'])} real executed attack variants\n"
    "(each proven to succeed unsandboxed first)",
    fontsize=11,
)
ax.set_xticks(x)
ax.set_xticklabels(CATEGORIES, fontsize=9)
ax.axhline(100, color="#27ae60", linestyle="--", linewidth=0.8, alpha=0.5)
ax.spines[["top", "right"]].set_visible(False)

if ax2 is not None:
    ltools = legit["tools"]
    linternet = legit.get("internet", True)
    lstats = {}
    for t in ltools:
        ok = applicable = 0
        for case in legit["cases"]:
            if case.get("net") and not linternet:
                continue
            st = case["results"].get(t)
            if st == "ok":
                ok += 1
                applicable += 1
            elif st == "blocked":
                applicable += 1
        lstats[t] = (ok, applicable)
    lx = np.arange(len(ltools))
    lvals = [100.0 * lstats[t][0] / lstats[t][1] if lstats[t][1] else 0.0 for t in ltools]
    bars2 = ax2.bar(
        lx, lvals, 0.62,
        color=[COLORS.get(t, None) for t in ltools],
        edgecolor="white", linewidth=0.6,
    )
    for b, v, t in zip(bars2, lvals, ltools):
        n, d = lstats[t]
        label = f"{v:.0f}%\n({n}/{d})" if d else "n/a"
        ax2.text(
            b.get_x() + b.get_width() / 2, v + 2, label,
            ha="center", va="bottom", fontsize=9, fontweight="bold",
        )
    ax2.set_ylim(0, 118)
    ax2.set_ylabel("legitimate work allowed (%)")
    ax2.set_title(
        f"Legitimate work allowed — {len(legit['cases'])} everyday dev ops\n"
        "(same tools, same default configs)",
        fontsize=11,
    )
    ax2.set_xticks(lx)
    ax2.set_xticklabels(ltools, fontsize=9, rotation=20)
    ax2.axhline(100, color="#27ae60", linestyle="--", linewidth=0.8, alpha=0.5)
    ax2.spines[["top", "right"]].set_visible(False)

fig.suptitle(
    f"AgentVault red-team corpus — {doc['os']}, generated {doc['generated'][:10]}\n"
    "security (left) is only meaningful together with usability (right)",
    fontsize=12.5,
)
fig.legend(
    [h[0] for h in legend_handles],
    [f"{t} ({totals[t][0]}/{totals[t][1]})" for t in tools],
    loc="lower center",
    ncol=len(tools),
    frameon=False,
    fontsize=9.5,
)
fig.tight_layout(rect=(0, 0.06, 1, 0.93))
fig.savefig(DST, bbox_inches="tight")
print(f"wrote {DST}")
for t in tools:
    print(f"  {t}: " + ", ".join(f"{c} {stats[t][c][0]}/{stats[t][c][1]}" for c in CATEGORIES))
if legit:
    for t in legit["tools"]:
        n, d = lstats[t]
        print(f"  {t}: legit {n}/{d}")
if not internet:
    print("note: run was offline; exfiltration column excluded", file=sys.stderr)


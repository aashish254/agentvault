#!/usr/bin/env python3
"""Generate docs/redteam/CORPUS_CHART.png from docs/redteam/CORPUS_RESULTS.json.

Grouped bar chart: attack category x tool, showing blocked-attack
percentage as measured by TestAttackCorpus (make corpus).
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

COLORS = {
    "no-sandbox": "#c0392b",
    "agentvault": "#27ae60",
    "srt": "#2980b9",
    "codex": "#16a085",
    "docker": "#e67e22",
    "firejail": "#8e44ad",
}

fig, ax = plt.subplots(figsize=(11, 6), dpi=150)
x = np.arange(len(CATEGORIES))
width = 0.8 / max(len(tools), 1)
for i, t in enumerate(tools):
    vals = pct[t]
    bars = ax.bar(
        x + i * width - 0.4 + width / 2,
        vals,
        width,
        label=t,
        color=COLORS.get(t, None),
        edgecolor="white",
        linewidth=0.6,
    )
    for b, v, c in zip(bars, vals, CATEGORIES):
        n, d = stats[t][c]
        label = f"{v:.0f}%\n({n}/{d})" if d else "n/a"
        ax.text(
            b.get_x() + b.get_width() / 2,
            b.get_height() + 1.2,
            label,
            ha="center",
            va="bottom",
            fontsize=7.5,
        )

ax.set_ylim(0, 118)
ax.set_ylabel("attacks blocked (%)")
ax.set_title(
    f"AgentVault attack corpus — {len(doc['cases'])} real executed attacks, measured per tool\n"
    f"({doc['os']}, generated {doc['generated'][:10]})",
    fontsize=12,
)
ax.set_xticks(x)
ax.set_xticklabels(CATEGORIES)
ax.axhline(100, color="#27ae60", linestyle="--", linewidth=0.8, alpha=0.5)
ax.legend(
    loc="upper center",
    bbox_to_anchor=(0.5, -0.09),
    ncol=len(tools),
    frameon=False,
    fontsize=10,
)
ax.spines[["top", "right"]].set_visible(False)
fig.tight_layout()
fig.savefig(DST, bbox_inches="tight")
print(f"wrote {DST}")
for t in tools:
    print(f"  {t}: " + ", ".join(f"{c} {stats[t][c][0]}/{stats[t][c][1]}" for c in CATEGORIES))
if not internet:
    print("note: run was offline; exfiltration column excluded", file=sys.stderr)

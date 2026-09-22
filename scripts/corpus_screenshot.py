#!/usr/bin/env python3
"""Render a terminal-style screenshot of a TestAttackCorpus run.

Usage: python3 scripts/corpus_screenshot.py <go-test -v log> <out.png>

Picks a window of TRY/PWNED markers from the no-sandbox section plus the
final summary block, and renders them like a dark terminal.
"""
import os
import re
import sys

import matplotlib

matplotlib.use("Agg")
import matplotlib.pyplot as plt

def main():
    log_path, out_path = sys.argv[1], sys.argv[2]
    lines = open(log_path, errors="replace").read().expandtabs(4).splitlines()

    # strip the go-test indentation prefix
    lines = [re.sub(r"^\s{4,}(corpus_test\.go:\d+:\s*)?", "", l) for l in lines]

    # window 1: first TRY/PWNED burst (no-sandbox proving the attacks are real)
    markers = [i for i, l in enumerate(lines) if re.match(r"(TRY|PWNED)-? ?[A-Z]-\d", l)]
    w1 = lines[markers[0] : markers[0] + 14] if markers else []

    # window 2: summary block
    si = next((i for i, l in enumerate(lines) if "corpus summary" in l), None)
    w2 = []
    if si is not None:
        for l in lines[si : si + 12]:
            if re.match(r"(--- PASS|PASS|ok\s)", l.strip()):
                break
            w2.append(l)

    # window 3: final verdict lines (deduped)
    seen = set()
    w3 = []
    for l in lines:
        key = l.strip()
        if re.match(r"(--- PASS|PASS|ok\s)", key) and key not in seen:
            seen.add(key)
            w3.append(key)

    body = (
        ["$ make corpus", ""]
        + w1
        + ["   ...  103 attacks x 5 tools  ...", ""]
        + w2
        + [""]
        + w3
    )

    fig = plt.figure(figsize=(9.6, 0.27 * len(body) + 0.6), dpi=160)
    fig.patch.set_facecolor("#1e1e2e")
    ax = fig.add_axes([0, 0, 1, 1])
    ax.axis("off")

    y = 1 - 0.5 / (len(body) + 1)
    for line in body:
        color = "#cdd6f4"
        if line.startswith("PWNED"):
            color = "#f38ba8"  # attack succeeded (unsandboxed)
        elif line.startswith("TRY"):
            color = "#89b4fa"
        elif "agentvault" in line or "srt" in line or line.startswith(("PASS", "ok", "--- PASS")):
            color = "#a6e3a1"
        elif "docker" in line or "no-sandbox" in line:
            color = "#f38ba8"
        elif line.startswith("$"):
            color = "#f9e2af"
        ax.text(
            0.035, y, line if line else " ",
            family="monospace", fontsize=11, color=color,
            va="center", transform=ax.transAxes,
        )
        y -= 1.0 / (len(body) + 1)

    fig.savefig(out_path, facecolor=fig.get_facecolor())
    print(f"wrote {out_path}")

if __name__ == "__main__":
    main()

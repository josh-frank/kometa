#!/usr/bin/env python3
# kometa-cat.py
# Visualise homoglyph carriers in text.
# Highlights Cyrillic (red), Greek (green), Latin carriers (blue).
# Imports ALPHA directly from kometa.py — single source of truth.

import sys, os
sys.path.insert(0, os.path.dirname(__file__))
from kometa import ALPHA

COLORS = dict(lat="\x1b[34m", cyr="\x1b[31m", ell="\x1b[32m", reset="\x1b[0m")

LOOKUP = {ch: script for script, chars in ALPHA.items() for ch in chars}

def _summary(text: str) -> str:
    counts = {s: 0 for s in ALPHA}
    for ch in text:
        if ch in LOOKUP: counts[LOOKUP[ch]] += 1
    total = sum(counts.values())
    if not total: return "no carriers found"
    return (f"{COLORS['cyr']}cyr:{counts['cyr']}{COLORS['reset']}  "
            f"{COLORS['ell']}ell:{counts['ell']}{COLORS['reset']}  "
            f"{COLORS['lat']}lat:{counts['lat']}{COLORS['reset']}  "
            f"total:{total}")

def colorize(text: str) -> str:
    out = []
    for ch in text:
        script = LOOKUP.get(ch)
        out.append(f"{COLORS[script]}{ch}{COLORS['reset']}" if script else ch)
    return "".join(out)

if __name__ == "__main__":
    if len(sys.argv) > 1:
        text = open(sys.argv[1], encoding="utf-8").read()
    else:
        text = sys.stdin.read()
    sys.stdout.write(colorize(text) + "\n")
    sys.stderr.write(_summary(text) + "\n")

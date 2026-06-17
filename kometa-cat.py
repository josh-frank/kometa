#!/usr/bin/env python3
# kometa-cat.py
# Visualise homoglyph carriers in text.
# Highlights Cyrillic (red), Greek (green), Latin carriers (blue).
# Imports ALPHA directly from kometa.py — single source of truth.

import sys, os
sys.path.insert(0, os.path.dirname(__file__))
from kometa import DICT

COLORS = dict(lat="\x1b[34m", cyr="\x1b[31m", reset="\x1b[0m")

LOOKUP = {}
for _i, (_l, _c) in enumerate(zip(DICT["lat"], DICT["cyr"])):
    LOOKUP[_l] = "lat"
    LOOKUP[_c] = "cyr"

def _summary(text: str) -> str:
    counts = {"lat": 0, "cyr": 0}
    for ch in text:
        if ch in LOOKUP: counts[LOOKUP[ch]] += 1
    total = sum(counts.values())
    if not total: return "no carriers found"
    return (f"{COLORS['cyr']}cyr:{counts['cyr']}{COLORS['reset']}  "
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

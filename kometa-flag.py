#!/usr/bin/env python3
# kometa-flag.py
# Scan text for mixed-script words — potential homoglyph substitution.
# Highlights flagged words in red. Summary to stderr.
#
# Usage:
#   python3 kometa-flag.py <file>
#   cat file | python3 kometa-flag.py

import sys, os, re

# Cyrillic: U+0400–U+04FF
# Greek:    U+0370–U+03FF

ALPHA_CYR = "КОМЕТАХРНо"
ALPHA_ELL = "ΚΟΜΕΤΑΧΡΗο"

KNOWN_HOMOGLYPHS = re.compile(f"[{re.escape(ALPHA_CYR + ALPHA_ELL)}]")
HOMOGLYPH_PATTERN = re.compile(r'[\u0400-\u04FF\u0370-\u03FF]')

# ── DETECTION ────────────────────────────────

LATIN    = re.compile(r'[A-Za-z]')
NONLATIN = re.compile(r'[\u0400-\u04FF\u0370-\u03FF]')  # Cyrillic + Greek blocks

def is_mixed(word):
    return bool(LATIN.search(word) and NONLATIN.search(word))

def has_homoglyphs(text):
    return bool(HOMOGLYPH_PATTERN.search(text))

def mixed_script_words(text):
    return [w for w in text.split()
            if LATIN.search(w) and NONLATIN.search(w)]

# ── OUTPUT ────────────────────────────────────

RED   = "\x1b[31m"
RESET = "\x1b[0m"

def flag(text):
    flagged = 0
    out = []
    for word in re.split(r'(\s+)', text):   # preserve whitespace
        if is_mixed(word):
            out.append(f"{RED}{word}{RESET}")
            flagged += 1
        else:
            out.append(word)
    return "".join(out), flagged

# ── CLI ───────────────────────────────────────

if __name__ == "__main__":
    text = open(sys.argv[1], encoding="utf-8").read() if len(sys.argv) > 1 else sys.stdin.read()
    result, flagged = flag(text)
    sys.stdout.write(result)
    sys.stderr.write(f"{'⚠️  ' + str(flagged) + ' mixed-script word(s) flagged' if flagged else '✓ no mixed-script words found'}\n")
    if flagged:
        sys.exit(1)
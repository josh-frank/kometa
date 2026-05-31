#!/usr/bin/env node
// kometa-cat.js
// Visualize homoglyph carriers in text.
// Highlights Cyrillic (red), Greek (green), Latin carriers (blue).

"use strict";
const fs = require("fs");

// Character sets from kometa.js
const ALPHA = {
  lat: "KOMETAXPHo",
  cyr: "КОМЕТАХРНо",
  ell: "ΚΟΜΕТΑΧΡΗο",
};

const BETA = {
  lat: "IJij",
  cyr: "ІЈіј",
};

// Build lookup: character → script type
const charToScript = new Map();
const addToMap = (script, chars) => {
  for (const ch of chars) charToScript.set(ch, script);
};

Object.entries(ALPHA).forEach(([script, chars]) => addToMap(script, chars));
Object.entries(BETA).forEach(([script, chars]) => addToMap(script, chars));

// ANSI color codes
const COLORS = {
  lat: "\x1b[34m", // Blue - Latin carrier (inactive)
  cyr: "\x1b[31m", // Red - Cyrillic (bit 0)
  ell: "\x1b[32m", // Green - Greek (bit 1)
  reset: "\x1b[0m",
};

// Colorize entire text
const colorize = text => {
  return [...text]
    .map(ch => {
      const script = charToScript.get(ch);
      return script ? COLORS[script] + ch + COLORS.reset : ch;
    })
    .join("");
};

// ── Main ─────────────────────────────────────
const [, , file] = process.argv;

if (file) {
  const content = fs.readFileSync(file, "utf8");
  process.stdout.write(colorize(content));
} else {
  let data = "";
  process.stdin.on("data", chunk => {
    data += chunk;
  });
  process.stdin.on("end", () => {
    process.stdout.write(colorize(data));
  });
}

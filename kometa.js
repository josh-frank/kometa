#!/usr/bin/env node
// ─────────────────────────────────────────────
// kometa.js
// Homoglyph steganography with password-derived keys.
// Zero dependencies — Node built-ins only.
//
// Usage:
//   node kometa.js encode <cover> <message> <password> <output>
//   node kometa.js decode <input>  <password> <output>
// ─────────────────────────────────────────────

"use strict";
const fs     = require("fs");
const crypto = require("crypto");

// ── CONSTANTS & CONFIG ────────────────────────

const SEED_BYTES       = 8;      // bytes reserved for carrier selection seed
const BLOCK_SIZE       = 64;     // pad keylen to this multiple (obscures message length)
const SALT_COVER_BYTES = 4096;   // how much of the cover to hash for the scrypt salt

const SCRYPT = {
  N: 1 << 17,  // memory/time cost (~0.5 s); raise to 1<<20 for harsher environments
  r: 8,
  p: 1,
  // Node caps scrypt memory by default — set maxmem explicitly so N=2^17+ works.
  // Formula: 128 * N * r bytes. Double it for headroom.
  get maxmem() { return 128 * this.N * this.r * 2; },
};

const ALPHA = {
  lat: "KOMETAXPHo",
  cyr: "КОМЕТАХРНо",
  ell: "ΚΟΜΕΤΑΧΡΗο",
};

// ── KEY DERIVATION ────────────────────────────

// Normalise cover: replace all homoglyph carriers with Latin equivalents.
// Ensures the salt is identical whether hashing the original cover or
// the encoded output (which has Cyrillic/Greek chars swapped in).
const _normaliseCover = text => {
  const map = new Map();
  for (let i = 0; i < ALPHA.lat.length; i++) {
    map.set(ALPHA.lat[i], i);
    map.set(ALPHA.cyr[i], i);
    map.set(ALPHA.ell[i], i);
  }
  return [...text].map(ch => {
    const idx = map.get(ch);
    return idx !== undefined ? ALPHA.lat[idx] : ch;
  }).join("");
};

// Derive { seed: Uint8Array(8), keystream: Uint8Array } from password + cover.
// Both sides independently arrive at identical keys — no transmission needed.
const deriveKeys = (password, coverText, messageBytes) => {
  const keylen = Math.ceil((SEED_BYTES + messageBytes) / BLOCK_SIZE) * BLOCK_SIZE;
  const salt   = crypto.createHash("sha256")
    .update(_normaliseCover(coverText).slice(0, SALT_COVER_BYTES), "utf8")
    .digest();
  const key = crypto.scryptSync(password, salt, keylen, SCRYPT);
  return {
    seed:      new Uint8Array(key.buffer, 0, SEED_BYTES),
    keystream: new Uint8Array(key.buffer, SEED_BYTES),
  };
};

// ── PRIMITIVES ────────────────────────────────

// XOR bytes against a keystream. Wrong password → noise, no error.
const _xor = (bytes, keystream) =>
  bytes.map((b, i) => b ^ (keystream[i] ?? 0));

// Bytes → bit array with 16-bit big-endian length header.
const _toBits = bytes => {
  if (bytes.length > 65535) throw new Error("Message too long (max 65,535 bytes)");
  const framed = [bytes.length >> 8, bytes.length & 0xff, ...bytes];
  const bits   = [];
  for (const byte of framed)
    for (let b = 7; b >= 0; b--) bits.push((byte >> b) & 1);
  return bits;
};

// Bit array → Buffer, reading 16-bit length header first.
const _fromBits = bits => {
  const byte = offset => {
    let v = 0;
    for (let b = 0; b < 8; b++) v = (v << 1) | (bits[offset + b] ?? 0);
    return v;
  };
  const len = (byte(0) << 8) | byte(8);
  const out = Buffer.alloc(len);
  for (let i = 0; i < len; i++) out[i] = byte(16 + i * 8);
  return out;
};

// xoshiro128** PRNG seeded from a Uint8Array.
const _makeRng = seed => {
  const v = new DataView(seed.buffer, seed.byteOffset, SEED_BYTES);
  let s0 = v.getUint32(0, true) | 1, s1 = v.getUint32(4, true) | 1;
  let s2 = 0x9e3779b9,              s3 = 0x6c62272e;
  const rotl = (x, k) => ((x << k) | (x >>> (32 - k))) >>> 0;
  return () => {
    const r = Math.imul(rotl(Math.imul(s1, 5), 7), 9) >>> 0;
    const t = (s1 << 9) >>> 0;
    s2 = (s2 ^ s0) >>> 0; s3 = (s3 ^ s1) >>> 0;
    s1 = (s1 ^ s2) >>> 0; s0 = (s0 ^ s3) >>> 0;
    s2 = (s2 ^ t)  >>> 0; s3 = rotl(s3, 11);
    return r;
  };
};

// Fisher-Yates shuffle — same seed → same order on both sides.
const _shuffle = (arr, rng) => {
  const a = arr.slice();
  for (let i = a.length - 1; i > 0; i--) {
    const j = rng() % (i + 1);
    [a[i], a[j]] = [a[j], a[i]];
  }
  return a;
};

// ── STEGANOGRAPHY ─────────────────────────────

// Build a char → { script, index } lookup for all three scripts.
const _lookup = (() => {
  const map = new Map();
  for (const [script, chars] of Object.entries(ALPHA))
    for (let i = 0; i < chars.length; i++)
      map.set(chars[i], { script, index: i });
  return map;
})();

// Embed a bit array into cover text using a shuffled carrier selection.
const _embed = (cover, bits, seed) => {
  const positions = [];
  for (let i = 0; i < cover.length; i++)
    if (_lookup.has(cover[i])) positions.push(i);

  if (positions.length < bits.length)
    throw new Error(
      `Cover too small: need ${bits.length} carrier positions, got ${positions.length}`
    );

  const active = new Map(
    _shuffle(positions, _makeRng(seed)).slice(0, bits.length).map((p, i) => [p, bits[i]])
  );

  return [...cover].map((ch, i) => {
    const info = _lookup.get(ch);
    if (!info) return ch;
    if (!active.has(i)) return ALPHA.lat[info.index];         // inactive → Latin
    return active.get(i) === 0
      ? ALPHA.cyr[info.index]                                  // bit 0 → Cyrillic
      : ALPHA.ell[info.index];                                 // bit 1 → Greek
  }).join("");
};

// Extract a bit array from an encoded cover using the same shuffle.
const _extract = (encoded, seed) => {
  const positions = [];
  const observed  = new Map();
  for (let i = 0; i < encoded.length; i++) {
    const info = _lookup.get(encoded[i]);
    if (!info) continue;
    positions.push(i);
    if (info.script !== "lat") observed.set(i, info.script === "cyr" ? 0 : 1);
  }

  const shuffled = _shuffle(positions, _makeRng(seed));
  const bit      = i => observed.get(shuffled[i]) ?? 0;
  const byte     = offset => {
    let v = 0;
    for (let b = 0; b < 8; b++) v = (v << 1) | bit(offset + b);
    return v;
  };

  const payloadBytes = (byte(0) << 8) | byte(8);
  const bits = [];
  for (let i = 0; i < 16 + payloadBytes * 8; i++) bits.push(bit(i));
  return bits;
};

// ── ENCODE / DECODE ───────────────────────────

// Read a file if it exists, otherwise treat the argument as a literal string.
const readOrLiteral = arg =>
  fs.existsSync(arg) ? fs.readFileSync(arg) : Buffer.from(arg, "utf8");

const encode = (coverFile, messageArg, password, outputFile) => {
  const cover   = fs.readFileSync(coverFile, "utf8").trimEnd();
  const message = readOrLiteral(messageArg);

  process.stderr.write("⏳ Deriving keys…\n");
  const { seed, keystream } = deriveKeys(password, cover, message.length);

  const encrypted = _xor(new Uint8Array(message), keystream);
  const output    = _embed(cover, _toBits([...encrypted]), seed);

  fs.writeFileSync(outputFile, output, "utf8");
  process.stderr.write(`✓ Encoded → ${outputFile}\n`);
};

const decode = (inputFile, password, outputFile) => {
  const encoded = fs.readFileSync(inputFile, "utf8").trimEnd();

  process.stderr.write("⏳ Deriving keys…\n");
  // Derive with generous keylen; actual message length is read from the bit header.
  const { seed, keystream } = deriveKeys(password, encoded, BLOCK_SIZE * 8);

  const bits      = _extract(encoded, seed);
  const encrypted = new Uint8Array(_fromBits(bits));
  const decrypted = _xor(encrypted, keystream);

  fs.writeFileSync(outputFile, Buffer.from(decrypted));
  process.stderr.write(`✓ Decoded → ${outputFile}\n`);
};

// ── CLI ───────────────────────────────────────

const [,, cmd, ...args] = process.argv;

if (cmd === "encode" && args.length === 4) {
  const [cover, message, password, output] = args;
  encode(cover, message, password, output);
} else if (cmd === "decode" && args.length === 3) {
  const [input, password, output] = args;
  decode(input, password, output);
} else {
  process.stderr.write(
    "usage:\n" +
    "  node kometa.js encode <cover> <message> <password> <output>\n" +
    "  node kometa.js decode <input>  <password> <output>\n"
  );
  process.exit(1);
}

// ─────────────────────────────────────────────
// kometa-encode.js
// Homoglyph steganography — MVP encode/decode
// ─────────────────────────────────────────────

const fs = require("fs");
const path = require("path");

const dictionary = {
  alpha: {
    lat: "KOMETAXPHo", // Latin   (B and p removed)
    cyr: "КОМЕТАХРНо", // Cyrillic
    ell: "ΚΟΜΕΤΑΧΡΗο", // Greek
  },
  beta: {
    lat: "IJij",
    cyr: "ІЈіј",
  },
};

// ─────────────────────────────────────────────
// Pad layout
//
// Bytes 0–7  : carrier selection seed (xoshiro128** input)
// Bytes 8–N  : OTP key material for message encryption
//
// otpGenerate() always produces a block-aligned pad (multiple of 64
// bytes) so pad size does not leak message length to an observer of
// the pad file.
// ─────────────────────────────────────────────

const SEED_BYTES = 8;
const BLOCK_SIZE = 64;

// ─────────────────────────────────────────────
// Lookup table helpers
// ─────────────────────────────────────────────

const buildLookupTableFrom = dict => {
  const lookup = new Map();
  for (const [setName, chars] of Object.entries(dict)) {
    for (let i = 0; i < chars.length; i++) {
      lookup.set(chars[i], {setName, index: i});
    }
  }
  return lookup;
};

// ─────────────────────────────────────────────
// Bit packing helpers
// ─────────────────────────────────────────────

// Convert a string to a flat bit array.
// Prepends a 16-bit big-endian length header (max 65,535 chars).
const messageToBits = message => {
  if (message.length > 65535)
    throw new Error("Message too long (max 65,535 chars)");
  const len = message.length;
  const bytes = [
    len >> 8,
    len & 0xff,
    ...message.split("").map(c => c.charCodeAt(0)),
  ];
  const bits = [];
  for (const byte of bytes)
    for (let b = 7; b >= 0; b--) bits.push((byte >> b) & 1);
  return bits;
};

// Convert a flat bit array back to a string.
// Reads the 16-bit length header first.
const bitsToMessage = bits => {
  const readByte = offset => {
    let val = 0;
    for (let b = 0; b < 8; b++) val = (val << 1) | (bits[offset + b] ?? 0);
    return val;
  };
  const length = (readByte(0) << 8) | readByte(8);
  let message = "";
  for (let i = 0; i < length; i++)
    message += String.fromCharCode(readByte(16 + i * 8));
  return message;
};

// ─────────────────────────────────────────────
// OTP helpers
// ─────────────────────────────────────────────

// Generate a cryptographically random OTP pad, base64-encoded.
// Pad is always a multiple of BLOCK_SIZE bytes — pad size does not
// leak message length. First SEED_BYTES are the carrier selection
// seed; remaining bytes are OTP key material.
const otpGenerate = (messageBytes = 32) => {
  const needed = messageBytes + SEED_BYTES;
  const total = Math.ceil(needed / BLOCK_SIZE) * BLOCK_SIZE;
  const arr = new Uint8Array(total);
  crypto.getRandomValues(arr);
  return btoa(String.fromCharCode(...arr));
};

// XOR message bytes against the OTP region of a base64-encoded pad.
// OTP region starts at SEED_BYTES (bytes 0–7 are the selection seed).
// Returns a new Uint8Array of the same length as messageBytes.
const otpApply = (messageBytes, padBase64) => {
  const padBytes = Uint8Array.from(atob(padBase64), c => c.charCodeAt(0));
  const otpSlice = padBytes.slice(SEED_BYTES);
  if (otpSlice.length < messageBytes.length)
    throw new Error(
      `OTP pad too short: need ${messageBytes.length} bytes of key material, ` +
        `got ${otpSlice.length} (pad total ${padBytes.length})`,
    );
  return messageBytes.map((byte, i) => byte ^ otpSlice[i]);
};

// ─────────────────────────────────────────────
// Keyed carrier selection
//
// Active carrier positions are chosen by a Fisher-Yates shuffle of
// all carrier positions in the document, seeded from the first
// SEED_BYTES of the pad. Encoder and decoder reconstruct the same
// shuffle independently — no extra signalling required.
//
// Benefits vs. sequential fill:
//   • Bits are distributed across the full document — no density
//     cliff or front-loading visible to a casual observer.
//   • Without the pad an adversary reads bits from the wrong
//     positions in the wrong order: output is noise even with the
//     OTP key. Position knowledge and pad are both required.
// ─────────────────────────────────────────────

// xoshiro128** — fast, seedable, deterministic PRNG.
const _rotl = (x, k) => ((x << k) | (x >>> (32 - k))) >>> 0;

const makeRng = (seedBytes) /* Uint8Array, len >= SEED_BYTES */ => {
  const view = new DataView(seedBytes.buffer, seedBytes.byteOffset, SEED_BYTES);
  let s0 = view.getUint32(0, true) | 1; // ensure non-zero state
  let s1 = view.getUint32(4, true) | 1;
  let s2 = 0x9e3779b9;
  let s3 = 0x6c62272e;
  return () => {
    const result = Math.imul(_rotl(Math.imul(s1, 5), 7), 9) >>> 0;
    const t = (s1 << 9) >>> 0;
    s2 = (s2 ^ s0) >>> 0;
    s3 = (s3 ^ s1) >>> 0;
    s1 = (s1 ^ s2) >>> 0;
    s0 = (s0 ^ s3) >>> 0;
    s2 = (s2 ^ t) >>> 0;
    s3 = _rotl(s3, 11);
    return result;
  };
};

// Fisher-Yates shuffle driven by a makeRng() PRNG.
const fisherYates = (arr, rng) => {
  const a = arr.slice();
  for (let i = a.length - 1; i > 0; i--) {
    const j = rng() % (i + 1);
    [a[i], a[j]] = [a[j], a[i]];
  }
  return a;
};

// Extract the selection seed from a pad (non-destructive read).
const selectionSeed = padBase64 =>
  Uint8Array.from(atob(padBase64), c => c.charCodeAt(0)).slice(0, SEED_BYTES);

// Best-effort pad destruction: overwrite with zeros, then delete.
// NOTE: best-effort only — does not guarantee low-level disk erasure.
// For stronger guarantees, use Rust + zeroize or shred(1).
const destroyPad = filePath => {
  const len = fs.statSync(filePath).size;
  fs.writeFileSync(filePath, "\0".repeat(len), "utf8");
  fs.unlinkSync(filePath);
};

// ─────────────────────────────────────────────
// Encoding scheme
//
// Carrier characters (KOMETAXPHo / homoglyphs) are collected from
// the cover text and their positions shuffled via a pad-seeded PRNG.
// The first N positions in shuffled order are "active" and carry
// payload bits; all others are written as Latin (neutral/inactive).
//
//   Active carrier → Cyrillic = bit 0, Greek = bit 1
//   Inactive carrier → Latin  (no information)
//
// OTP layer: message bytes are XORed with pad key material before
// embedding. Without the pad, neither bit values nor active positions
// are recoverable.
// ─────────────────────────────────────────────

// Encode message into cover text using OTP encryption + keyed carrier
// selection. All arguments are file paths.
// Writes encoded output to outputFile, or <coverFile>.out if omitted.
const encode = (coverFile, messageFile, padFile, outputFile = null) => {
  const plaintext = fs.readFileSync(coverFile, "utf8").trimEnd();
  const message = fs.readFileSync(messageFile, "utf8").trimEnd();
  const pad = fs.readFileSync(padFile, "utf8").trimEnd();

  const messageBytes = Uint8Array.from(
    message.split("").map(c => c.charCodeAt(0)),
  );
  const encryptedBytes = otpApply(messageBytes, pad);
  const encryptedStr = Array.from(encryptedBytes)
    .map(b => String.fromCharCode(b))
    .join("");
  const bits = messageToBits(encryptedStr);

  const alphaLookup = buildLookupTableFrom(dictionary.alpha);

  // Collect all carrier positions in document order
  const carrierPositions = [];
  for (let i = 0; i < plaintext.length; i++)
    if (alphaLookup.has(plaintext[i])) carrierPositions.push(i);

  if (carrierPositions.length < bits.length)
    throw new Error(
      `Insufficient carrier capacity: needed ${bits.length} bits, ` +
        `only ${carrierPositions.length} positions available in cover text`,
    );

  // Shuffle all carrier positions, then take the first bits.length as active
  const rng = makeRng(selectionSeed(pad));
  const shuffled = fisherYates(carrierPositions, rng);
  const activeMap = new Map();
  for (let i = 0; i < bits.length; i++) activeMap.set(shuffled[i], bits[i]);

  // Write output: active → Cyr/Greek, inactive → Latin
  const chars = [...plaintext];
  for (let i = 0; i < chars.length; i++) {
    const info = alphaLookup.get(chars[i]);
    if (!info) continue;
    if (!activeMap.has(i)) {
      chars[i] = dictionary.alpha.lat[info.index]; // inactive — stays Latin
      continue;
    }
    chars[i] =
      activeMap.get(i) === 0
        ? dictionary.alpha.cyr[info.index]
        : dictionary.alpha.ell[info.index];
  }

  const outPath = outputFile ?? coverFile + ".out";
  fs.writeFileSync(outPath, chars.join(""), "utf8");
  console.log(`✓ Encoded → ${outPath}`);
  return outPath;
};

// Decode a steganographic file back to the hidden message.
// Writes plaintext output to outputFile, or <encodedFile>.decoded if omitted.
// Pad is consumed (destroyed) after successful decode.
const decode = (encodedFile, padFile, outputFile = null) => {
  const encoded = fs.readFileSync(encodedFile, "utf8").trimEnd();
  const pad = fs.readFileSync(padFile, "utf8").trimEnd();

  const alphaLookup = buildLookupTableFrom(dictionary.alpha);

  // Collect all carrier positions and their observed script
  const carrierPositions = [];
  const observedBits = new Map(); // position → bit (Latin positions absent = inactive)
  for (let i = 0; i < encoded.length; i++) {
    const info = alphaLookup.get(encoded[i]);
    if (!info) continue;
    carrierPositions.push(i);
    if (info.setName !== "lat")
      observedBits.set(i, info.setName === "cyr" ? 0 : 1);
  }

  // Reconstruct identical shuffle from same pad seed
  const rng = makeRng(selectionSeed(pad));
  const shuffled = fisherYates(carrierPositions, rng);

  // Helper: read bit i from the shuffled active sequence
  const readBit = i => observedBits.get(shuffled[i]) ?? 0;
  const readByte = offset => {
    let val = 0;
    for (let b = 0; b < 8; b++) val = (val << 1) | readBit(offset + b);
    return val;
  };

  // Decode 16-bit length header, then read full payload
  const payloadBytes = (readByte(0) << 8) | readByte(8);
  const totalBits = 16 + payloadBytes * 8;
  const bits = [];
  for (let i = 0; i < totalBits; i++) bits.push(readBit(i));

  const encryptedStr = bitsToMessage(bits);
  const encryptedBytes = Uint8Array.from(
    encryptedStr.split("").map(c => c.charCodeAt(0)),
  );
  const decryptedBytes = otpApply(encryptedBytes, pad);
  const message = Array.from(decryptedBytes)
    .map(b => String.fromCharCode(b))
    .join("");

  const outPath = outputFile ?? encodedFile + ".decoded";
  fs.writeFileSync(outPath, message, "utf8");

  // Consume the pad — best-effort destruction
  destroyPad(padFile);
  console.log(`✓ Decoded → ${outPath}`);
  console.log(`✓ Pad destroyed: ${padFile}`);

  return message;
};

module.exports = {
  buildLookupTableFrom,
  messageToBits,
  bitsToMessage,
  otpGenerate,
  otpApply,
  makeRng,
  fisherYates,
  selectionSeed,
  destroyPad,
  encode,
  decode,
};

// ─────────────────────────────────────────────
// kometa-encode.js
// Homoglyph steganography — encode/decode
// ─────────────────────────────────────────────

const fs     = require("fs");
const crypto = require("crypto");

const dictionary = {
  alpha: {
    lat: "KOMETAXPHo", // Latin
    cyr: "КОМЕТАХРНо", // Cyrillic
    ell: "ΚΟΜΕΤΑΧΡΗο", // Greek
  },
  beta: {
    lat: "IJij",
    cyr: "ІЈіј",
  },
};

// ─────────────────────────────────────────────
// Key derivation
//
// Two modes share the same internal key layout:
//
//   Bytes 0–7  : carrier selection seed  (xoshiro128** input)
//   Bytes 8–N  : keystream for XOR encryption
//
// OTP mode   — keys come directly from a pad file (original behaviour).
// Password mode — keys are derived via scrypt + cover-derived salt.
//
// SCRYPT PARAMETERS (password mode)
//   N = 2^17  — memory/time cost (~0.5 s on modern hardware; raise to
//               2^20 for maximum resistance at the cost of ~4 s)
//   r = 8     — block size (standard)
//   p = 1     — parallelism (standard)
//   keylen    — 8 (seed) + messageBytes, rounded to next multiple of
//               BLOCK_SIZE so output length does not leak payload size
//
// COVER SALT
//   SHA-256 of the first SALT_COVER_BYTES of the cover text.
//   Deterministic for both parties — no transmission required.
//   Naturally unique per cover file; reuse risk is negligible for
//   single-use exfil scenarios.
// ─────────────────────────────────────────────

const SEED_BYTES       = 8;
const BLOCK_SIZE       = 64;
const SALT_COVER_BYTES = 4096; // how much of the cover to hash for the salt

// Normalise cover text before hashing: replace all homoglyph carriers
// with their Latin equivalent so the salt is identical whether computed
// from the original cover or the encoded output.
const _normaliseCover = text => {
  // Build a flat char → latin-index map inline (dictionary not yet defined here)
  const lat = "KOMETAXPHo", cyr = "КОМЕТАХРНо", ell = "ΚΟΜΕΤΑΧΡΗο";
  const map = new Map();
  for (let i = 0; i < lat.length; i++) {
    map.set(lat[i], i); map.set(cyr[i], i); map.set(ell[i], i);
  }
  return [...text].map(ch => {
    const idx = map.get(ch);
    return idx !== undefined ? lat[idx] : ch;
  }).join("");
};

const SCRYPT = {
  N: 1 << 17,  // cost factor  — raise to 1 << 20 for harsher environments
  r: 8,        // block size
  p: 1,        // parallelism
};

// Derive { seed: Uint8Array(8), keystream: Uint8Array(keylen-8) }
// from a password and the cover text.  Zero external dependencies.
const deriveKeys = (password, coverText, messageBytes) => {
  const needed  = SEED_BYTES + messageBytes;
  const keylen  = Math.ceil(needed / BLOCK_SIZE) * BLOCK_SIZE;

  // Cover-derived salt: SHA-256 of the first SALT_COVER_BYTES of the
  // *normalised* cover (all homoglyphs → Latin) so the salt is identical
  // whether computed from the original cover or the encoded output.
  const coverSlice = _normaliseCover(coverText).slice(0, SALT_COVER_BYTES);
  const salt       = crypto.createHash("sha256").update(coverSlice, "utf8").digest();

  const key = crypto.scryptSync(password, salt, keylen, {
    N: SCRYPT.N, r: SCRYPT.r, p: SCRYPT.p,
  });

  return {
    seed:      new Uint8Array(key.buffer, 0, SEED_BYTES),
    keystream: new Uint8Array(key.buffer, SEED_BYTES),
  };
};

// ─────────────────────────────────────────────
// Lookup table helpers
// ─────────────────────────────────────────────

const buildLookupTableFrom = dict => {
  const lookup = new Map();
  for (const [setName, chars] of Object.entries(dict))
    for (let i = 0; i < chars.length; i++)
      lookup.set(chars[i], { setName, index: i });
  return lookup;
};

// ─────────────────────────────────────────────
// Bit packing helpers
// ─────────────────────────────────────────────

// Bytes → flat bit array with 16-bit big-endian length header.
const messageToBits = message => {
  if (message.length > 65535)
    throw new Error("Message too long (max 65,535 bytes)");
  const len   = message.length;
  const bytes = [len >> 8, len & 0xff, ...message];
  const bits  = [];
  for (const byte of bytes)
    for (let b = 7; b >= 0; b--) bits.push((byte >> b) & 1);
  return bits;
};

// Flat bit array → Buffer.  Reads 16-bit length header first.
const bitsToMessage = bits => {
  const readByte = offset => {
    let val = 0;
    for (let b = 0; b < 8; b++) val = (val << 1) | (bits[offset + b] ?? 0);
    return val;
  };
  const length = (readByte(0) << 8) | readByte(8);
  const out    = Buffer.alloc(length);
  for (let i = 0; i < length; i++) out[i] = readByte(16 + i * 8);
  return out;
};

// ─────────────────────────────────────────────
// OTP helpers (pad mode — unchanged)
// ─────────────────────────────────────────────

// Generate a cryptographically random OTP pad, base64-encoded.
const otpGenerate = (messageBytes = 32) => {
  const needed = messageBytes + SEED_BYTES;
  const total  = Math.ceil(needed / BLOCK_SIZE) * BLOCK_SIZE;
  const arr    = new Uint8Array(total);
  globalThis.crypto.getRandomValues(arr);
  return btoa(String.fromCharCode(...arr));
};

// XOR message bytes against a keystream Uint8Array.
// Works for both pad mode (slice of decoded pad) and password mode
// (keystream from deriveKeys).
const xorKeystream = (messageBytes, keystream) => {
  if (keystream.length < messageBytes.length)
    throw new Error(
      `Keystream too short: need ${messageBytes.length} bytes, got ${keystream.length}`
    );
  return messageBytes.map((byte, i) => byte ^ keystream[i]);
};

// XOR against a base64-encoded pad (OTP mode, backward-compatible).
const otpApply = (messageBytes, padBase64) => {
  const padBytes = Uint8Array.from(atob(padBase64), c => c.charCodeAt(0));
  return xorKeystream(messageBytes, padBytes.slice(SEED_BYTES));
};

// Extract the selection seed from a base64-encoded pad.
const selectionSeed = padBase64 =>
  Uint8Array.from(atob(padBase64), c => c.charCodeAt(0)).slice(0, SEED_BYTES);

// Best-effort pad destruction: overwrite with zeros, then delete.
const destroyPad = filePath => {
  const len = fs.statSync(filePath).size;
  fs.writeFileSync(filePath, "\0".repeat(len), "utf8");
  fs.unlinkSync(filePath);
};

// ─────────────────────────────────────────────
// xoshiro128** PRNG + Fisher-Yates
// ─────────────────────────────────────────────

const _rotl = (x, k) => ((x << k) | (x >>> (32 - k))) >>> 0;

const makeRng = seedBytes /* Uint8Array, len >= SEED_BYTES */ => {
  const view = new DataView(seedBytes.buffer, seedBytes.byteOffset, SEED_BYTES);
  let s0 = view.getUint32(0, true) | 1;
  let s1 = view.getUint32(4, true) | 1;
  let s2 = 0x9e3779b9;
  let s3 = 0x6c62272e;
  return () => {
    const result = Math.imul(_rotl(Math.imul(s1, 5), 7), 9) >>> 0;
    const t = (s1 << 9) >>> 0;
    s2 = (s2 ^ s0) >>> 0; s3 = (s3 ^ s1) >>> 0;
    s1 = (s1 ^ s2) >>> 0; s0 = (s0 ^ s3) >>> 0;
    s2 = (s2 ^ t)  >>> 0; s3 = _rotl(s3, 11);
    return result;
  };
};

const fisherYates = (arr, rng) => {
  const a = arr.slice();
  for (let i = a.length - 1; i > 0; i--) {
    const j = rng() % (i + 1);
    [a[i], a[j]] = [a[j], a[i]];
  }
  return a;
};

// ─────────────────────────────────────────────
// Core steganography — shared by both modes
//
//   Active carrier → Cyrillic = bit 0, Greek = bit 1
//   Inactive carrier → Latin  (no information)
// ─────────────────────────────────────────────

const _embedBits = (plaintext, bits, seed) => {
  const alphaLookup = buildLookupTableFrom(dictionary.alpha);

  const carrierPositions = [];
  for (let i = 0; i < plaintext.length; i++)
    if (alphaLookup.has(plaintext[i])) carrierPositions.push(i);

  if (carrierPositions.length < bits.length)
    throw new Error(
      `Insufficient carrier capacity: needed ${bits.length} bits, ` +
      `only ${carrierPositions.length} positions available`
    );

  const shuffled  = fisherYates(carrierPositions, makeRng(seed));
  const activeMap = new Map();
  for (let i = 0; i < bits.length; i++) activeMap.set(shuffled[i], bits[i]);

  const chars = [...plaintext];
  for (let i = 0; i < chars.length; i++) {
    const info = alphaLookup.get(chars[i]);
    if (!info) continue;
    if (!activeMap.has(i)) {
      chars[i] = dictionary.alpha.lat[info.index];
      continue;
    }
    chars[i] = activeMap.get(i) === 0
      ? dictionary.alpha.cyr[info.index]
      : dictionary.alpha.ell[info.index];
  }
  return chars.join("");
};

const _extractBits = (encoded, seed) => {
  const alphaLookup = buildLookupTableFrom(dictionary.alpha);

  const carrierPositions = [];
  const observedBits     = new Map();
  for (let i = 0; i < encoded.length; i++) {
    const info = alphaLookup.get(encoded[i]);
    if (!info) continue;
    carrierPositions.push(i);
    if (info.setName !== "lat")
      observedBits.set(i, info.setName === "cyr" ? 0 : 1);
  }

  const shuffled = fisherYates(carrierPositions, makeRng(seed));
  const readBit  = i => observedBits.get(shuffled[i]) ?? 0;
  const readByte = offset => {
    let val = 0;
    for (let b = 0; b < 8; b++) val = (val << 1) | readBit(offset + b);
    return val;
  };

  const payloadBytes = (readByte(0) << 8) | readByte(8);
  const totalBits    = 16 + payloadBytes * 8;
  const bits         = [];
  for (let i = 0; i < totalBits; i++) bits.push(readBit(i));
  return bits;
};

// ─────────────────────────────────────────────
// Public encode / decode — OTP mode (pad file)
// ─────────────────────────────────────────────

const encode = (coverFile, messageFile, padFile, outputFile = null) => {
  const plaintext    = fs.readFileSync(coverFile,   "utf8").trimEnd();
  const messageBytes = fs.readFileSync(messageFile);           // Buffer
  const pad          = fs.readFileSync(padFile, "utf8").trimEnd();

  const encrypted = otpApply(new Uint8Array(messageBytes), pad);
  const bits      = messageToBits([...encrypted]);
  const seed      = selectionSeed(pad);
  const output    = _embedBits(plaintext, bits, seed);

  const outPath = outputFile ?? coverFile + ".out";
  fs.writeFileSync(outPath, output, "utf8");
  console.log(`✓ Encoded → ${outPath}`);
  return outPath;
};

const decode = (encodedFile, padFile, outputFile = null) => {
  const encoded = fs.readFileSync(encodedFile, "utf8").trimEnd();
  const pad     = fs.readFileSync(padFile, "utf8").trimEnd();

  const seed      = selectionSeed(pad);
  const bits      = _extractBits(encoded, seed);
  const encrypted = new Uint8Array(bitsToMessage(bits));
  const decrypted = otpApply(encrypted, pad);

  const outPath = outputFile ?? encodedFile + ".decoded";
  fs.writeFileSync(outPath, Buffer.from(decrypted));
  destroyPad(padFile);
  console.log(`✓ Decoded → ${outPath}`);
  console.log(`✓ Pad destroyed: ${padFile}`);
  return outPath;
};

// ─────────────────────────────────────────────
// Public encode / decode — password mode
// ─────────────────────────────────────────────

const encodeWithPassword = (coverFile, messageFile, password, outputFile = null) => {
  const plaintext    = fs.readFileSync(coverFile,   "utf8").trimEnd();
  const messageBytes = fs.readFileSync(messageFile);           // Buffer

  console.log("⏳ Deriving keys (this takes a moment)…");
  const { seed, keystream } = deriveKeys(password, plaintext, messageBytes.length);

  const encrypted = xorKeystream(new Uint8Array(messageBytes), keystream);
  const bits      = messageToBits([...encrypted]);
  const output    = _embedBits(plaintext, bits, seed);

  const outPath = outputFile ?? coverFile + ".out";
  fs.writeFileSync(outPath, output, "utf8");
  console.log(`✓ Encoded → ${outPath}`);
  return outPath;
};

const decodeWithPassword = (encodedFile, password, outputFile = null) => {
  const encoded = fs.readFileSync(encodedFile, "utf8").trimEnd();

  console.log("⏳ Deriving keys (this takes a moment)…");
  // We don't know message length yet — derive with a generous keylen,
  // extract bits to find actual length, then decrypt.
  const { seed, keystream } = deriveKeys(password, encoded, BLOCK_SIZE * 8);

  const bits      = _extractBits(encoded, seed);
  const encrypted = new Uint8Array(bitsToMessage(bits));

  // Truncate encrypted to available keystream — wrong password will produce
  // noise output rather than throwing, which is the correct silent-fail behaviour.
  const usable    = Math.min(encrypted.length, keystream.length);
  const decrypted = xorKeystream(encrypted.slice(0, usable), keystream);

  const outPath = outputFile ?? encodedFile + ".decoded";
  fs.writeFileSync(outPath, Buffer.from(decrypted));
  console.log(`✓ Decoded → ${outPath}`);
  return outPath;
};

module.exports = {
  // Key derivation
  deriveKeys,
  SCRYPT,
  // Primitives
  buildLookupTableFrom,
  messageToBits,
  bitsToMessage,
  xorKeystream,
  otpGenerate,
  otpApply,
  makeRng,
  fisherYates,
  selectionSeed,
  destroyPad,
  // OTP mode
  encode,
  decode,
  // Password mode
  encodeWithPassword,
  decodeWithPassword,
};

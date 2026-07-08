// -----------------------------------------------
// kometa.ts
// Homoglyph steganography with password-derived keys.
// Zero npm dependencies -- Web Crypto API + plain TS only.
//
// Port notes vs. the original kometa.py:
//   - scrypt -> PBKDF2-SHA256 via crypto.subtle. Browsers don't ship scrypt
//     natively, and hand-rolling it would mean rolling our own crypto for
//     the one piece where that's genuinely dangerous. PBKDF2 is CPU-hard,
//     not memory-hard like scrypt, so it's weaker against GPU/ASIC brute
//     force at equal wall-clock cost. We compensate with a high iteration
//     count (PBKDF2_ITERATIONS below). This means encoded output is NOT
//     cross-compatible with kometa.py -- the key material differs.
//   - xoshiro128**, bit-packing, and carrier placement are ported as plain
//     TS: this is bespoke logic nobody else has audited but us, so
//     readability wins over hiding it behind a library.
//   - Sensitive byte buffers (keys, keystreams, password bytes) are
//     zeroed with .fill(0) as soon as they're no longer needed.
// -----------------------------------------------

// ---- CONSTANTS & CONFIG -----------------------

const SEED_BYTES = 8;
const BLOCK_SIZE = 64;
const SALT_COVER_CHARS = 4096; // character count (post-normalise), not bytes

// PBKDF2-SHA256 substituted for scrypt (see header note). OWASP's current
// floor for PBKDF2-SHA256 is 600,000 iterations; bump this over time.
const PBKDF2_ITERATIONS = 600_000;

// ---- DISTRIBUTION CONFIG -----------------------

const DEAD_ZONE_START = 0.10; // fraction of carriers excluded at head
const DEAD_ZONE_END = 0.10;   // fraction of carriers excluded at tail
const DENSITY_BUCKETS = 20;   // granularity of carrier density profile

// Homoglyph pairs -- positional: LAT[n] is the visual twin of CYR[n].
// Mnemonic: KOMETA = same in Latin & Cyrillic.
const LAT = "acepoijxyKOMETAPHIJX";
const CYR = "\u0430\u0441\u0435\u0440\u043e\u0456\u0458\u0445\u0443\u041a\u041e\u041c\u0415\u0422\u0410\u0420\u041d\u0406\u0408\u0425";

// ---- LOOKUP TABLES (built once at module load) ----

type Script = "lat" | "cyr";

const NORM = new Map<string, number>();
for (let i = 0; i < CYR.length; i++) NORM.set(CYR[i], i);
for (let i = 0; i < LAT.length; i++) NORM.set(LAT[i], i);

const LOOKUP = new Map<string, { script: Script; idx: number }>();
for (let i = 0; i < LAT.length; i++) {
  LOOKUP.set(LAT[i], { script: "lat", idx: i });
  LOOKUP.set(CYR[i], { script: "cyr", idx: i });
}

function normalise(text: string): string {
  const out: string[] = [];
  for (const ch of text) {
    const idx = NORM.get(ch);
    out.push(idx !== undefined ? LAT[idx] : ch);
  }
  return out.join("");
}

// ---- BYTE UTILITIES ----------------------------

function concatBytes(...parts: Uint8Array[]): Uint8Array {
  const total = parts.reduce((n, p) => n + p.length, 0);
  const out = new Uint8Array(total);
  let offset = 0;
  for (const p of parts) {
    out.set(p, offset);
    offset += p.length;
  }
  return out;
}

function xorBytes(data: Uint8Array, keystream: Uint8Array): Uint8Array {
  const out = new Uint8Array(data.length);
  for (let i = 0; i < data.length; i++) out[i] = data[i] ^ keystream[i];
  return out;
}

// ---- KEY DERIVATION (crypto.subtle) ------------

// crypto.subtle's TS types require ArrayBufferView<ArrayBuffer> in very
// recent lib.dom versions, which plain Uint8Array<ArrayBufferLike> doesn't
// satisfy. This cast is a typing-only nit (SharedArrayBuffer exclusion) --
// no behavioral effect, since these buffers are never shared.
function bs(u: Uint8Array): BufferSource {
  return u as unknown as BufferSource;
}

async function sha256(data: Uint8Array): Promise<Uint8Array> {
  return new Uint8Array(await crypto.subtle.digest("SHA-256", bs(data)));
}

async function pbkdf2(
  password: Uint8Array,
  salt: Uint8Array,
  dklenBytes: number,
  iterations: number
): Promise<Uint8Array> {
  const keyMaterial = await crypto.subtle.importKey(
    "raw",
    bs(password),
    "PBKDF2",
    false,
    ["deriveBits"]
  );
  const bits = await crypto.subtle.deriveBits(
    { name: "PBKDF2", salt: bs(salt), iterations, hash: "SHA-256" },
    keyMaterial,
    dklenBytes * 8
  );
  return new Uint8Array(bits);
}

async function hmacSha256(keyBytes: Uint8Array, data: Uint8Array): Promise<Uint8Array> {
  const key = await crypto.subtle.importKey(
    "raw",
    bs(keyBytes),
    { name: "HMAC", hash: "SHA-256" },
    false,
    ["sign"]
  );
  return new Uint8Array(await crypto.subtle.sign("HMAC", key, bs(data)));
}

/** One PBKDF2 call -- returns 64 bytes of base key material. */
async function deriveBootstrap(password: string, cover: string): Promise<Uint8Array> {
  const enc = new TextEncoder();
  const saltSource = enc.encode(normalise(cover).slice(0, SALT_COVER_CHARS));
  const salt = await sha256(saltSource);
  const passBytes = enc.encode(password);
  const baseKey = await pbkdf2(passBytes, salt, 64, PBKDF2_ITERATIONS);
  passBytes.fill(0);
  return baseKey;
}

function bootstrapSeed(baseKey: Uint8Array): Uint8Array {
  return baseKey.slice(0, SEED_BYTES);
}

/**
 * Expand base key with nonce via HKDF-SHA256 (HMAC extract + expand).
 * Returns { seed[8], keystream[messageLen] }.
 *
 * Note: the expand-step counter is packed as a single byte, matching
 * kometa.py's `i.to_bytes(1, "big")`. Python throws OverflowError past
 * i=255; this port wraps instead (Uint8Array truncates to the low byte).
 * That's a real behavioral difference for very large messages -- flagging
 * it rather than silently hoping nobody hits it.
 */
async function deriveKeys(
  baseKey: Uint8Array,
  messageLen: number,
  nonce: Uint8Array
): Promise<{ seed: Uint8Array; keystream: Uint8Array }> {
  const keylen = Math.ceil((SEED_BYTES + messageLen) / BLOCK_SIZE) * BLOCK_SIZE;
  const prk = await hmacSha256(nonce, baseKey);

  let out: Uint8Array = new Uint8Array(0);
  let prev: Uint8Array = new Uint8Array(0);
  const iterations = Math.floor(keylen / 32) + 1;
  for (let i = 1; i <= iterations; i++) {
    const input = concatBytes(prev, new Uint8Array([i]));
    prev = await hmacSha256(prk, input);
    out = concatBytes(out, prev);
  }
  prk.fill(0);

  const key = out.slice(0, keylen);
  return { seed: key.slice(0, SEED_BYTES), keystream: key.slice(SEED_BYTES) };
}

// ---- BIT PACKING -------------------------------

function toBits(data: Uint8Array): number[] {
  if (data.length > 65535) throw new Error("Message too long (max 65,535 bytes)");
  const framed = concatBytes(
    new Uint8Array([data.length >> 8, data.length & 0xff]),
    data
  );
  const bits: number[] = [];
  for (const b of framed) {
    for (let i = 7; i >= 0; i--) bits.push((b >> i) & 1);
  }
  return bits;
}

function fromBits(bits: number[]): Uint8Array {
  const readByte = (offset: number): number => {
    let v = 0;
    for (let b = 0; b < 8; b++) {
      v = (v << 1) | (bits[offset + b] ?? 0);
    }
    return v;
  };
  const length = (readByte(0) << 8) | readByte(8);
  const out = new Uint8Array(length);
  for (let i = 0; i < length; i++) out[i] = readByte(16 + i * 8);
  return out;
}

// ---- xoshiro128** -------------------------------

function rotl(x: number, k: number): number {
  return ((x << k) | (x >>> (32 - k))) >>> 0;
}

function makeRng(seed: Uint8Array): () => number {
  const view = new DataView(seed.buffer as ArrayBuffer, seed.byteOffset, seed.byteLength);
  let s0 = (view.getUint32(0, true) | 1) >>> 0;
  let s1 = (view.getUint32(4, true) | 1) >>> 0;
  let s2 = 0x9e3779b9;
  let s3 = 0x6c62272e;

  return function rng(): number {
    // Operands here stay well under 2^53, so plain `*` keeps exact
    // integer precision -- no Math.imul needed at these magnitudes.
    const r = (rotl((s1 * 5) >>> 0, 7) * 9) >>> 0;
    const t = (s1 << 9) >>> 0;
    s2 ^= s0; s3 ^= s1; s1 ^= s2; s0 ^= s3; s2 ^= t;
    s2 >>>= 0; s3 = rotl(s3, 11);
    s0 >>>= 0; s1 >>>= 0;
    return r;
  };
}

function shuffle<T>(arr: T[], rng: () => number): T[] {
  const a = arr.slice();
  for (let i = a.length - 1; i > 0; i--) {
    const j = rng() % (i + 1);
    [a[i], a[j]] = [a[j], a[i]];
  }
  return a;
}

// ---- CARRIER POSITION SELECTION ----------------

function deadZoneBounds(n: number): { lo: number; hi: number } {
  const lo = Math.floor(n * DEAD_ZONE_START);
  const hi = n - Math.floor(n * DEAD_ZONE_END);
  return { lo, hi };
}

/** Select 64 fixed carrier positions for the nonce (drawn before header/body). */
function noncePositions(positions: number[], seed: Uint8Array): number[] {
  const { lo, hi } = deadZoneBounds(positions.length);
  const eligible = positions.slice(lo, hi);
  if (eligible.length < 64) {
    throw new Error(`Cover too small: need at least 64 carriers for nonce, got ${eligible.length}`);
  }
  return shuffle(eligible, makeRng(seed)).slice(0, 64);
}

/**
 * Select 16 fixed carrier positions for the length header. Drawn from the
 * dead-zone-excluded pool independent of message length, so decode can
 * always recover them without knowing n_bits first.
 */
function headerPositions(positions: number[], seed: Uint8Array, bs: Uint8Array): number[] {
  const { lo, hi } = deadZoneBounds(positions.length);
  const nonceSet = new Set(noncePositions(positions, bs));
  const eligible = positions.slice(lo, hi).filter((p) => !nonceSet.has(p));
  if (eligible.length < 16) {
    throw new Error(`Cover too small: need at least 16 eligible carriers, got ${eligible.length}`);
  }
  return shuffle(eligible, makeRng(seed)).slice(0, 16);
}

/** Select n_bits carrier positions for the message body via density-matched buckets. */
function bodyPositions(
  positions: number[],
  headerPos: number[],
  nBits: number,
  seed: Uint8Array,
  bs: Uint8Array,
  nBuckets: number = DENSITY_BUCKETS
): number[] {
  const { lo, hi } = deadZoneBounds(positions.length);
  const nonceSet = new Set(noncePositions(positions, bs));
  const headerSet = new Set(headerPos);
  const eligible = positions.slice(lo, hi).filter((p) => !nonceSet.has(p) && !headerSet.has(p));

  if (eligible.length < nBits) {
    throw new Error(
      `Cover too small after dead-zone trim: need ${nBits} body carriers, have ${eligible.length} eligible`
    );
  }

  const actualBuckets = Math.min(nBuckets, eligible.length);
  const bucketSize = eligible.length / actualBuckets;
  const buckets: number[][] = [];
  for (let i = 0; i < actualBuckets; i++) {
    buckets.push(eligible.slice(Math.floor(i * bucketSize), Math.floor((i + 1) * bucketSize)));
  }

  const raw = buckets.map((b) => (b.length / eligible.length) * nBits);
  const alloc = raw.map((r) => Math.floor(r));
  const remainder = nBits - alloc.reduce((a, b) => a + b, 0);

  const fracOrder = raw
    .map((r, i) => ({ i, frac: r - alloc[i] }))
    .sort((a, b) => b.frac - a.frac)
    .map((x) => x.i);
  for (const i of fracOrder.slice(0, remainder)) alloc[i] += 1;

  const rng = makeRng(seed);
  const selected: number[] = [];
  for (let i = 0; i < buckets.length; i++) {
    selected.push(...shuffle(buckets[i], rng).slice(0, alloc[i]));
  }
  return selected;
}

// ---- STEGANOGRAPHY EMBED / EXTRACT -------------

function embed(
  cover: string,
  bits: number[],
  bs: Uint8Array,
  seed: Uint8Array,
  nonce: Uint8Array
): string {
  const headerBits = bits.slice(0, 16);
  const bodyBits = bits.slice(16);

  const chars = Array.from(cover);
  const positions: number[] = [];
  chars.forEach((ch, i) => { if (LOOKUP.has(ch)) positions.push(i); });

  const noncePos = noncePositions(positions, bs);
  const hdrPos = headerPositions(positions, seed, bs);
  const bodyPos = bodyPositions(positions, hdrPos, bodyBits.length, seed, bs);

  const nonceBits: number[] = [];
  for (let i = 0; i < 64; i++) {
    nonceBits.push((nonce[Math.floor(i / 8)] >> (7 - (i % 8))) & 1);
  }

  const active = new Map<number, number>();
  noncePos.forEach((p, i) => active.set(p, nonceBits[i]));
  hdrPos.forEach((p, i) => active.set(p, headerBits[i]));
  bodyPos.forEach((p, i) => active.set(p, bodyBits[i]));

  const out = chars.map((ch, i) => {
    const entry = LOOKUP.get(ch);
    if (!entry) return ch;
    const bit = active.get(i) ?? 0; // inactive positions -> bit 0
    return bit ? CYR[entry.idx] : LAT[entry.idx];
  });
  return out.join("");
}

function extractNonce(encoded: string, bs: Uint8Array): Uint8Array {
  const chars = Array.from(encoded);
  const positions: number[] = [];
  const observed = new Set<number>();
  chars.forEach((ch, i) => {
    const entry = LOOKUP.get(ch);
    if (entry) {
      positions.push(i);
      if (entry.script === "cyr") observed.add(i);
    }
  });

  const noncePos = noncePositions(positions, bs);
  const bits = noncePos.map((p) => (observed.has(p) ? 1 : 0));
  const bytes = new Uint8Array(8);
  for (let i = 0; i < 8; i++) {
    let v = 0;
    for (let b = 0; b < 8; b++) v = (v << 1) | bits[i * 8 + b];
    bytes[i] = v;
  }
  return bytes;
}

function extract(encoded: string, seed: Uint8Array, bs: Uint8Array): number[] {
  const chars = Array.from(encoded);
  const positions: number[] = [];
  const observed = new Map<number, number>();
  chars.forEach((ch, i) => {
    const entry = LOOKUP.get(ch);
    if (entry) {
      positions.push(i);
      if (entry.script === "cyr") observed.set(i, 1);
    }
  });

  const readBit = (p: number) => observed.get(p) ?? 0;
  const readByte = (ps: number[], offset: number) => {
    let v = 0;
    for (let b = 0; b < 8; b++) v = (v << 1) | readBit(ps[offset + b]);
    return v;
  };

  const hdrPos = headerPositions(positions, seed, bs);
  const payloadBytes = (readByte(hdrPos, 0) << 8) | readByte(hdrPos, 8);
  let nBodyBits = payloadBytes * 8;

  const { lo, hi } = deadZoneBounds(positions.length);
  const nonceSet = new Set(noncePositions(positions, bs));
  const hdrSet = new Set(hdrPos);
  const maxBodyBits = positions.slice(lo, hi).filter((p) => !nonceSet.has(p) && !hdrSet.has(p)).length;
  nBodyBits = Math.min(nBodyBits, Math.max(0, maxBodyBits));

  const bodyPos = bodyPositions(positions, hdrPos, nBodyBits, seed, bs);
  const headerBits = hdrPos.map(readBit);
  const bodyBits = bodyPos.map(readBit);
  return headerBits.concat(bodyBits);
}

// ---- PUBLIC API ---------------------------------

/** Encode `message` into `cover` text using `password`. Returns the carrier text. */
export async function encode(cover: string, message: Uint8Array, password: string): Promise<string> {
  const trimmedCover = cover.replace(/\s+$/, "");
  const nonce = crypto.getRandomValues(new Uint8Array(8));

  const baseKey = await deriveBootstrap(password, trimmedCover);
  const bs = bootstrapSeed(baseKey);
  const { seed, keystream } = await deriveKeys(baseKey, message.length, nonce);

  const encrypted = xorBytes(message, keystream);
  const bits = toBits(encrypted);
  const output = embed(trimmedCover, bits, bs, seed, nonce);

  baseKey.fill(0);
  keystream.fill(0);
  seed.fill(0);

  return output;
}

/** Decode a carrier string produced by `encode`, given the same `password`. */
export async function decodeText(encoded: string, password: string): Promise<Uint8Array> {
  const trimmed = encoded.replace(/\s+$/, "");

  const baseKey = await deriveBootstrap(password, trimmed);
  const bs = bootstrapSeed(baseKey);
  const nonce = extractNonce(trimmed, bs);

  const first = await deriveKeys(baseKey, BLOCK_SIZE, nonce); // seed only, dummy length
  const bits = extract(trimmed, first.seed, bs);
  const encrypted = fromBits(bits);

  const second = await deriveKeys(baseKey, encrypted.length, nonce); // real keystream
  const result = xorBytes(encrypted, second.keystream);

  baseKey.fill(0);
  first.seed.fill(0);
  first.keystream.fill(0);
  second.seed.fill(0);
  second.keystream.fill(0);

  return result;
}

// Convenience wrappers for string messages (UTF-8 in/out).
export async function encodeText(cover: string, message: string, password: string): Promise<string> {
  return encode(cover, new TextEncoder().encode(message), password);
}

export async function decodeToString(encoded: string, password: string): Promise<string> {
  return new TextDecoder().decode(await decodeText(encoded, password));
}
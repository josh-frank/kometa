#!/usr/bin/env python3
# ─────────────────────────────────────────────
# kometa.py
# Homoglyph steganography with password-derived keys.
# Zero dependencies — standard library only.
#
# Usage:
#   python3 kometa.py encode <cover> <message> <password> <output>
#   python3 kometa.py decode <input>  <password> <output>
# ─────────────────────────────────────────────

import sys, os, hashlib, struct

# ── CONSTANTS & CONFIG ────────────────────────

SEED_BYTES       = 8
BLOCK_SIZE       = 64
SALT_COVER_BYTES = 4096

SCRYPT = dict(n=1<<17, r=8, p=1, dklen=None)  # dklen set per-call

ALPHA = dict(
    lat = "KOMETAXPHo",
    cyr = "КОМЕТАХРНо",
    ell = "ΚΟΜΕΤΑΧΡΗο",
)

BETA = dict(
    lat = "IJij",
    cyr = "ІЈіј",
)

# ── KEY DERIVATION ────────────────────────────

def _normalise(text: str) -> str:
    """Replace all homoglyph carriers with Latin equivalents."""
    table = {}
    for i, (l, c, e) in enumerate(zip(ALPHA["lat"], ALPHA["cyr"], ALPHA["ell"])):
        table[l] = i; table[c] = i; table[e] = i
    return "".join(ALPHA["lat"][table[ch]] if ch in table else ch for ch in text)

def derive_keys(password: str, cover: str, message_len: int) -> tuple[bytes, bytes]:
    """Return (seed[8], keystream[n]) derived from password + cover."""
    keylen  = ((SEED_BYTES + message_len + BLOCK_SIZE - 1) // BLOCK_SIZE) * BLOCK_SIZE
    salt    = hashlib.sha256(_normalise(cover)[:SALT_COVER_BYTES].encode()).digest()
    maxmem  = 128 * SCRYPT["n"] * SCRYPT["r"] * 2  # 2× headroom; overrides platform default
    key     = hashlib.scrypt(password.encode(), salt=salt, dklen=keylen,
                             n=SCRYPT["n"], r=SCRYPT["r"], p=SCRYPT["p"], maxmem=maxmem)
    return key[:SEED_BYTES], key[SEED_BYTES:]

# ── PRIMITIVES ────────────────────────────────

def _xor(data: bytes, keystream: bytes) -> bytes:
    return bytes(a ^ b for a, b in zip(data, keystream))

def _to_bits(data: bytes) -> list[int]:
    if len(data) > 65535: raise ValueError("Message too long (max 65,535 bytes)")
    framed = bytes([len(data) >> 8, len(data) & 0xff]) + data
    return [(b >> i) & 1 for b in framed for i in range(7, -1, -1)]

def _from_bits(bits: list[int]) -> bytes:
    def read_byte(offset):
        v = 0
        for b in range(8): v = (v << 1) | (bits[offset + b] if offset + b < len(bits) else 0)
        return v
    length = (read_byte(0) << 8) | read_byte(8)
    return bytes(read_byte(16 + i * 8) for i in range(length))

# xoshiro128** — must match JS implementation exactly
def _make_rng(seed: bytes):
    s0, s1 = struct.unpack_from("<II", seed, 0)
    s0 |= 1; s1 |= 1
    s2, s3 = 0x9e3779b9, 0x6c62272e
    def rotl(x, k): return ((x << k) | (x >> (32 - k))) & 0xFFFFFFFF
    def rng():
        nonlocal s0, s1, s2, s3
        r = (rotl(s1 * 5 & 0xFFFFFFFF, 7) * 9) & 0xFFFFFFFF
        t = (s1 << 9) & 0xFFFFFFFF
        s2 ^= s0; s3 ^= s1; s1 ^= s2; s0 ^= s3; s2 ^= t
        s3 = rotl(s3, 11)
        return r
    return rng

def _shuffle(arr: list, rng) -> list:
    a = arr[:]
    for i in range(len(a) - 1, 0, -1):
        j = rng() % (i + 1)
        a[i], a[j] = a[j], a[i]
    return a

# ── STEGANOGRAPHY ─────────────────────────────

# Build char → (script, index) lookup for all three scripts
_LOOKUP = {ch: (s, i)
           for s, chars in ALPHA.items()
           for i, ch in enumerate(chars)}

def _embed(cover: str, bits: list[int], seed: bytes) -> str:
    positions = [i for i, ch in enumerate(cover) if ch in _LOOKUP]
    if len(positions) < len(bits):
        raise ValueError(f"Cover too small: need {len(bits)} carriers, got {len(positions)}")
    active = {p: bits[i] for i, p in enumerate(_shuffle(positions, _make_rng(seed))[:len(bits)])}
    out = []
    for i, ch in enumerate(cover):
        if ch not in _LOOKUP:
            out.append(ch)
        elif i not in active:
            out.append(ALPHA["lat"][_LOOKUP[ch][1]])   # inactive → Latin
        elif active[i] == 0:
            out.append(ALPHA["cyr"][_LOOKUP[ch][1]])   # bit 0 → Cyrillic
        else:
            out.append(ALPHA["ell"][_LOOKUP[ch][1]])   # bit 1 → Greek
    return "".join(out)

def _extract(encoded: str, seed: bytes) -> list[int]:
    positions, observed = [], {}
    for i, ch in enumerate(encoded):
        if ch not in _LOOKUP: continue
        script, _ = _LOOKUP[ch]
        positions.append(i)
        if script != "lat": observed[i] = 0 if script == "cyr" else 1
    shuffled = _shuffle(positions, _make_rng(seed))
    def bit(i): return observed.get(shuffled[i], 0) if i < len(shuffled) else 0
    def byte(offset): return sum(bit(offset + b) << (7 - b) for b in range(8))
    payload_bytes = (byte(0) << 8) | byte(8)
    return [bit(i) for i in range(16 + payload_bytes * 8)]

# ── ENCODE / DECODE ───────────────────────────

def _read_or_literal(arg: str) -> bytes:
    if os.path.exists(arg):
        with open(arg, "rb") as f: return f.read()
    return arg.encode()

def encode(cover_file: str, message_arg: str, password: str, output_file: str):
    cover   = open(cover_file, encoding="utf-8").read().rstrip()
    message = _read_or_literal(message_arg)
    sys.stderr.write("⏳ Deriving keys…\n")
    seed, keystream = derive_keys(password, cover, len(message))
    encrypted = _xor(message, keystream)
    output    = _embed(cover, _to_bits(encrypted), seed)
    open(output_file, "w", encoding="utf-8").write(output)
    sys.stderr.write(f"✓ Encoded → {output_file}\n")

def decode(input_file: str, password: str, output_file: str):
    encoded = open(input_file, encoding="utf-8").read().rstrip()
    sys.stderr.write("⏳ Deriving keys…\n")
    seed, keystream = derive_keys(password, encoded, BLOCK_SIZE * 8)
    bits      = _extract(encoded, seed)
    encrypted = _from_bits(bits)
    decrypted = _xor(encrypted, keystream)
    open(output_file, "wb").write(decrypted)
    sys.stderr.write(f"✓ Decoded → {output_file}\n")

# ── CLI ───────────────────────────────────────

if __name__ == "__main__":
    args = sys.argv[1:]
    if len(args) == 5 and args[0] == "encode":
        encode(args[1], args[2], args[3], args[4])
    elif len(args) == 4 and args[0] == "decode":
        decode(args[1], args[2], args[3])
    else:
        sys.stderr.write(
            "usage:\n"
            "  python3 kometa.py encode <cover> <message> <password> <output>\n"
            "  python3 kometa.py decode <input>  <password> <output>\n"
        )
        sys.exit(1)

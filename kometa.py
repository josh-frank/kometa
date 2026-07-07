#!/usr/bin/env python3
# ─────────────────────────────────────────────
# kometa.py
# Homoglyph steganography with password-derived keys.
# Zero dependencies — standard library only.
#
# Usage:
#   python3 kometa.py encode <cover> <message> <output>
#   python3 kometa.py decode <input> <output>
# ─────────────────────────────────────────────

import sys, os, hashlib, hmac, struct, getpass

# ── CONSTANTS & CONFIG ────────────────────────

SEED_BYTES       = 8
BLOCK_SIZE       = 64
SALT_COVER_BYTES = 4096

# Adjust memalloc to 1<<15 to improve performance.
# Tradeoff is brute-force cost: compromise expensive but possible.
SCRYPT = dict(n=1<<17, r=8, p=1, dklen=None)  # dklen set per-call

# ── DISTRIBUTION CONFIG ───────────────────────

DEAD_ZONE_START  = 0.10   # fraction of carriers to exclude at head
DEAD_ZONE_END    = 0.10   # fraction of carriers to exclude at tail
DENSITY_BUCKETS  = 20     # granularity of carrier density profile

# Homoglyph pairs — positional: lat[n] is the visual twin of cyr[n].
# Ordered by frequency/importance; mnemonic: KOMETA = same in Latin & Cyrillic.
DICT = dict(
    lat = "acepoijxyKOMETAPHIJX",
    cyr = "асероіјхуКОМЕТАРНІЈХ",
)

# ── KEY DERIVATION ────────────────────────────

# Build char → index lookup for normalisation (covers both scripts)
_NORM = {ch: i for i, ch in enumerate(DICT["cyr"])}
_NORM.update({ch: i for i, ch in enumerate(DICT["lat"])})

def _normalise(text: str) -> str:
    """Replace all homoglyph carriers with their Latin equivalents."""
    return "".join(DICT["lat"][_NORM[ch]] if ch in _NORM else ch for ch in text)

def _derive_bootstrap(password: str, cover: str) -> bytes:
    """One scrypt call — returns 64 bytes of base key material."""
    salt   = hashlib.sha256(_normalise(cover)[:SALT_COVER_BYTES].encode()).digest()
    maxmem = 128 * SCRYPT["n"] * SCRYPT["r"] * 2
    return hashlib.scrypt(password.encode(), salt=salt, dklen=64,
                          n=SCRYPT["n"], r=SCRYPT["r"], p=SCRYPT["p"], maxmem=maxmem)

def _bootstrap_seed(base_key: bytes) -> bytes:
    """Seed for nonce pool — first 8 bytes of base key, no nonce involved."""
    return base_key[:SEED_BYTES]

def derive_keys(base_key: bytes, message_len: int, nonce: bytes) -> tuple[bytes, bytes]:
    """Expand base key with nonce via HKDF-SHA256. Returns (seed[8], keystream[n])."""
    keylen = ((SEED_BYTES + message_len + BLOCK_SIZE - 1) // BLOCK_SIZE) * BLOCK_SIZE
    # HKDF-expand: cheap HMAC-based expansion, no second scrypt
    prk  = hmac.digest(nonce, base_key, "sha256")  # extract step (nonce as salt)
    out  = b""
    prev = b""
    for i in range(1, (keylen // 32) + 2):
        prev = hmac.digest(prk, prev + i.to_bytes(1, "big"), "sha256")
        out += prev
    key = out[:keylen]
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

# xoshiro128**
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

# Build char → index lookup for all carriers (both scripts, flat)
_LOOKUP = {}
for _i, (_l, _c) in enumerate(zip(DICT["lat"], DICT["cyr"])):
    _LOOKUP[_l] = ("lat", _i)
    _LOOKUP[_c] = ("cyr", _i)

def _nonce_positions(positions: list[int], seed: bytes) -> list[int]:
    """Select 64 fixed carrier positions for the nonce (drawn before header/body)."""
    n  = len(positions)
    lo = int(n * DEAD_ZONE_START)
    hi = n - int(n * DEAD_ZONE_END)
    eligible = positions[lo:hi]
    if len(eligible) < 64:
        raise ValueError(f"Cover too small: need at least 64 carriers for nonce, got {len(eligible)}")
    return _shuffle(eligible, _make_rng(seed))[:64]

def _header_positions(positions: list[int], seed: bytes, bootstrap_seed: bytes) -> list[int]:
    """
    Select 16 fixed carrier positions for the length header.
    Drawn from the dead-zone-excluded pool via a seeded shuffle —
    independent of message length, so decode can always recover them
    without knowing n_bits first. Header positions are excluded from
    body selection.
    """
    n  = len(positions)
    lo = int(n * DEAD_ZONE_START)
    hi = n - int(n * DEAD_ZONE_END)
    nonce_set = set(_nonce_positions(positions, bootstrap_seed))
    eligible = [p for p in positions[lo:hi] if p not in nonce_set]
    if len(eligible) < 16:
        raise ValueError(f"Cover too small: need at least 16 eligible carriers, got {len(eligible)}")
    return _shuffle(eligible, _make_rng(seed))[:16]

def _body_positions(positions: list[int], header_pos: list[int], n_bits: int, seed: bytes,
                    bootstrap_seed: bytes, n_buckets: int = DENSITY_BUCKETS) -> list[int]:
    """
    Select n_bits carrier positions for the message body using
    density-matched bucket allocation. Header and nonce positions are excluded.
    """
    n  = len(positions)
    lo = int(n * DEAD_ZONE_START)
    hi = n - int(n * DEAD_ZONE_END)
    nonce_set  = set(_nonce_positions(positions, bootstrap_seed))
    header_set = set(header_pos)
    eligible   = [p for p in positions[lo:hi] if p not in nonce_set and p not in header_set]

    if len(eligible) < n_bits:
        raise ValueError(
            f"Cover too small after dead-zone trim: "
            f"need {n_bits} body carriers, have {len(eligible)} eligible "
            f"(total {n}, margins {DEAD_ZONE_START:.0%}/{DEAD_ZONE_END:.0%})"
        )

    # ── density-matched bucket allocation ────
    actual_buckets = min(n_buckets, len(eligible))
    bucket_size    = len(eligible) / actual_buckets
    buckets        = [
        eligible[int(i * bucket_size) : int((i + 1) * bucket_size)]
        for i in range(actual_buckets)
    ]

    raw   = [len(b) / len(eligible) * n_bits for b in buckets]
    alloc = [int(r) for r in raw]
    remainder = n_bits - sum(alloc)
    fracs = sorted(range(actual_buckets), key=lambda i: -(raw[i] - alloc[i]))
    for i in fracs[:remainder]:
        alloc[i] += 1

    rng      = _make_rng(seed)
    selected = []
    for bucket, k in zip(buckets, alloc):
        chosen = _shuffle(bucket, rng)[:k]
        selected.extend(chosen)

    return selected

def _embed(cover: str, bits: list[int], bootstrap_seed: bytes, seed: bytes, nonce: bytes) -> str:
    # bits layout: first 16 = length header, rest = body
    # lat = bit 0 (inactive), cyr = bit 1 (active)
    header_bits = bits[:16]
    body_bits   = bits[16:]

    positions = [i for i, ch in enumerate(cover) if ch in _LOOKUP]
    nonce_pos = _nonce_positions(positions, bootstrap_seed)
    hdr_pos   = _header_positions(positions, seed, bootstrap_seed)
    body_pos  = _body_positions(positions, hdr_pos, len(body_bits), seed, bootstrap_seed)

    nonce_bits = [(nonce[i // 8] >> (7 - i % 8)) & 1 for i in range(64)]

    active = {}
    for p, b in zip(nonce_pos, nonce_bits): active[p] = b
    for p, b in zip(hdr_pos, header_bits):  active[p] = b
    for p, b in zip(body_pos, body_bits):   active[p] = b

    out = []
    for i, ch in enumerate(cover):
        if ch not in _LOOKUP:
            out.append(ch)
        else:
            idx = _LOOKUP[ch][1]
            bit = active.get(i, 0)                  # inactive positions → bit 0
            out.append(DICT["cyr"][idx] if bit else DICT["lat"][idx])
    return "".join(out)

def _extract_nonce(encoded: str, bootstrap_seed: bytes) -> bytes:
    """Read the 64-bit nonce from its fixed carrier pool using the bootstrap seed."""
    positions = [i for i, ch in enumerate(encoded) if ch in _LOOKUP]
    nonce_pos = _nonce_positions(positions, bootstrap_seed)
    observed  = {i for i, ch in enumerate(encoded) if ch in _LOOKUP and _LOOKUP[ch][0] == "cyr"}
    bits = [(1 if p in observed else 0) for p in nonce_pos]
    return bytes(sum(bits[i*8+b] << (7-b) for b in range(8)) for i in range(8))

def _extract(encoded: str, seed: bytes, bootstrap_seed: bytes) -> list[int]:
    positions, observed = [], {}
    for i, ch in enumerate(encoded):
        if ch not in _LOOKUP: continue
        positions.append(i)
        if _LOOKUP[ch][0] == "cyr": observed[i] = 1

    def read_bit(p): return observed.get(p, 0)
    def read_byte(ps, offset):
        return sum(read_bit(ps[offset + b]) << (7 - b) for b in range(8))

    hdr_pos       = _header_positions(positions, seed, bootstrap_seed)
    payload_bytes = (read_byte(hdr_pos, 0) << 8) | read_byte(hdr_pos, 8)
    n_body_bits   = payload_bytes * 8

    n  = len(positions)
    lo = int(n * DEAD_ZONE_START)
    hi = n - int(n * DEAD_ZONE_END)
    nonce_set     = set(_nonce_positions(positions, bootstrap_seed))
    hdr_set       = set(hdr_pos)
    max_body_bits = len([p for p in positions[lo:hi] if p not in nonce_set and p not in hdr_set])
    n_body_bits   = min(n_body_bits, max(0, max_body_bits))

    body_pos    = _body_positions(positions, hdr_pos, n_body_bits, seed, bootstrap_seed)
    header_bits = [read_bit(p) for p in hdr_pos]
    body_bits   = [read_bit(p) for p in body_pos]
    return header_bits + body_bits

# ── ENCODE / DECODE ───────────────────────────

def _read_or_literal(arg: str) -> bytes:
    if os.path.exists(arg):
        with open(arg, "rb") as f: return f.read()
    return arg.encode()

def encode(cover_file: str, message_arg: str, password: str, output_file: str):
    cover   = open(cover_file, encoding="utf-8").read().rstrip()
    message = _read_or_literal(message_arg)
    nonce   = os.urandom(8)
    sys.stderr.write("⏳ Deriving keys…\n")
    base_key         = _derive_bootstrap(password, cover)
    bs               = _bootstrap_seed(base_key)
    seed, keystream  = derive_keys(base_key, len(message), nonce)
    encrypted = _xor(message, keystream)
    output    = _embed(cover, _to_bits(encrypted), bs, seed, nonce)
    open(output_file, "w", encoding="utf-8").write(output)
    sys.stderr.write(f"✓ Encoded → {output_file}\n")

def decode_text(encoded: str, password: str) -> bytes:
    """Pure in-memory decode — no disk I/O. Returns decrypted payload as bytes."""
    encoded  = encoded.rstrip()
    base_key = _derive_bootstrap(password, encoded)
    bs       = _bootstrap_seed(base_key)
    nonce    = _extract_nonce(encoded, bs)
    seed, _  = derive_keys(base_key, BLOCK_SIZE, nonce)
    bits      = _extract(encoded, seed, bs)
    encrypted = _from_bits(bits)
    _, keystream = derive_keys(base_key, len(encrypted), nonce)
    return _xor(encrypted, keystream)

def decode(input_file: str, password: str, output_file: str):
    """CLI wrapper — reads file, decodes in memory, writes result."""
    sys.stderr.write("⏳ Deriving keys…\n")
    encoded   = open(input_file, encoding="utf-8").read()
    decrypted = decode_text(encoded, password)
    open(output_file, "wb").write(decrypted)
    sys.stderr.write(f"✓ Decoded → {output_file}\n")

# ── CLI ───────────────────────────────────────

def _get_password() -> str:
    """Read password from KOMETA_PASSWORD env var (testing) or a secure prompt (interactive)."""
    env = os.environ.get("KOMETA_PASSWORD")
    if env is not None:
        return env
    return getpass.getpass("Password: ")

if __name__ == "__main__":
    args = sys.argv[1:]
    if len(args) == 4 and args[0] == "encode":
        encode(args[1], args[2], _get_password(), args[3])
    elif len(args) == 3 and args[0] == "decode":
        decode(args[1], _get_password(), args[2])
    else:
        sys.stderr.write(
            "usage:\n"
            "  python3 kometa.py encode <cover> <message> <output>\n"
            "  python3 kometa.py decode <input>  <output>\n"
            "\n"
            "Password prompted securely: never passed in argv\n"
        )
        sys.exit(1)
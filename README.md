# `kometa` — Homoglyph Steganography Suite

A covert text steganography system that hides encrypted messages inside ordinary plaintext using Unicode homoglyphs. No anomalous network signature, no zero-width characters, visually indistinguishable from the original to human readers.

---

## Concept

Certain characters across Latin and Cyrillic scripts are visually identical at the glyph level but occupy different Unicode code points:

```
Latin    K  O  M  E  T  A  P  H  I  J  X  a  c  e  p  o  i  j  x  y
Cyrillic К  О  М  Е  Т  А  Р  Н  І  Ј  Х  а  с  е  р  о  і  ј  х  у
```

Ordered by frequency and importance. The name *kometa* is itself mnemonic — К О М Е Т А are identical in Russian and Latin, making the character set easy to reconstruct from memory.

A document containing these characters can have any of them silently substituted. The result is indistinguishable from the original to a human reader — and to most automated text processing.

**Encoding scheme:**
- **Latin** — carrier position inactive; carries no information
- **Cyrillic** — active carrier encoding bit **1**

Which positions are active and their read order is determined by a password-seeded shuffle (Fisher-Yates via xoshiro128** PRNG). Inactive positions are normalised to Latin.

---

## Architecture

### Character Set

```python
DICT = dict(
    lat = "KOMETAPHIJXacepoijxy",
    cyr = "КОМЕТАРНІЈХасероіјху",
)
```

All 20 pairs are positional: `lat[n]` is the visual twin of `cyr[n]`. This is the single source of truth for all carrier logic across the suite.

### Payload Layout

The embedded bitstream has two parts with distinct selection logic:

```
[ header: 16 bits ]                [ body: N bits ]
  └─ 2-byte big-endian length of     └─ XOR-encrypted message bytes
     the encrypted message
```

**Header and body use separate carrier pools** so that decode can recover the length without knowing it in advance.

### Security Model

1. **Key derivation** — `scrypt(password, sha256(normalise(cover[:4096])))`
   - Parameters: N=2¹⁷, r=8, p=1
   - Produces seed (8 bytes) + keystream (padded to 64-byte blocks)
   - Salt derived from *normalised* cover text — homoglyph substitutions in the cover do not change the salt, so re-encoding the same cover always produces the same keys

2. **Encryption** — message bytes XOR-ed with keystream
   - Keystream length matched exactly to message length on both encode and decode
   - Wrong password → random noise output, no error thrown

3. **Steganography** — active carrier positions determined by seeded shuffle
   - Bit values encoded via script selection: Latin = 0, Cyrillic = 1
   - Carrier distribution designed to resist casual visual inspection (see *Distribution* below)

**Detection vectors to be aware of:**
- A purpose-built scanner checking Unicode blocks will detect substitutions
- Copy-paste through Unicode-normalising platforms (some CMSes, some email clients) may destroy the payload
- Targeted forensic examination with a hex editor will find this
- Designed to survive bulk automated surveillance, not determined targeted investigation

---

## Carrier Selection & Distribution

### Dead Zones

The first and last **10%** of carrier positions (by carrier index, not character index) are never used. This means encoded characters never appear near the very beginning or end of the document — the regions most likely to receive close attention on a quick scroll.

```python
DEAD_ZONE_START = 0.10
DEAD_ZONE_END   = 0.10
```

### Density-Matched Placement

Rather than distributing active carriers uniformly across the eligible zone, kometa mirrors the document's own carrier density. The eligible carrier pool is divided into **20 buckets**; bits are allocated to each bucket in proportion to its size. The result: paragraphs naturally rich in carrier characters receive more encoded bits, sparse paragraphs receive fewer. Carrier density after encoding tracks carrier density before encoding.

```python
DENSITY_BUCKETS = 20
```

### Header / Body Split

The 16-bit length header uses its own independently-shuffled carrier pool, selected purely from the dead-zone-excluded positions using the seed alone. Body carriers are then drawn from the remaining eligible positions using density-matched bucket allocation. This split means:

- Decode always recovers the header without needing to know the message length first
- A wrong password produces a garbage length, which is capped to the physical maximum rather than crashing

---

## Payload Capacity

Carriers appear in typical English prose at roughly 1 per 25–30 characters across the full `DICT` set. Each carrier holds 1 bit. After dead zones (20% of carriers removed) and the 16-bit header:

| Document length | Carriers (est.) | Eligible (80%) | Usable payload |
|---|---|---|---|
| 1,000 chars | ~35 | ~28 | ~1 byte |
| 5,000 chars | ~175 | ~140 | ~15 bytes |
| 20,000 chars | ~700 | ~560 | ~68 bytes |
| 50,000 chars | ~1,750 | ~1,400 | ~173 bytes |

Carrier-dense covers (technical text, proper-noun-heavy journalism, legal documents) will significantly exceed these estimates. Use `kometa-grade` to measure a specific cover before committing to it.

---

## Installation & Usage

### Prerequisites

- Python 3.6+ (standard library only — zero external dependencies)

### Basic Usage

**Encode a message into a cover text:**
```bash
python3 kometa.py encode <cover> <message> <password> <output>
```

`<message>` can be a file path or a literal string. If a file exists at that path, its contents are used; otherwise the argument itself is encoded as UTF-8.

**Decode an encoded file:**
```bash
python3 kometa.py decode <input> <password> <output>
```

### Examples

```bash
# Encode from a message file
python3 kometa.py encode cover.txt message.txt correct-horse-battery-staple encoded.txt

# Encode a literal string directly
python3 kometa.py encode cover.txt "stop spying on me" correct-horse-battery-staple encoded.txt

# Decode
python3 kometa.py decode encoded.txt correct-horse-battery-staple decoded.txt

# Works with any cover format — prose, CSV, source code
python3 kometa.py encode data.csv "stop spying on me" password output.csv
```

The output file is the same character length as the cover. Whitespace is preserved exactly.

---

## Utilities

### `kometa-cat`

Visualises homoglyph carriers in a document. Highlights substituted characters by script so you can inspect the distribution of encoded bits.

```bash
python3 kometa-cat.py <file>
cat file.txt | python3 kometa-cat.py
```

**Color legend:**
- 🔴 Red — Cyrillic (active, bit 1)
- 🔵 Blue — Latin carrier (inactive, bit 0)
- White — non-carrier character

Summary counts (cyr / lat / total) are written to stderr.

### `kometa-flag`

Scans text for mixed-script words — words containing both Latin and Cyrillic carrier characters. Mixed-script words are the main spellchecker detection vector.

```bash
python3 kometa-flag.py <file>
cat file.txt | python3 kometa-flag.py
```

Flagged words are highlighted red. Exit code 1 if any mixed-script words are found. Useful for vetting a cover before use, or auditing an encoded output.

### `kometa-grade`

Assesses covertext quality:

- **Carrier analysis** — count, density, per-1000-chars ratio
- **Capacity calculation** — dead zones, header reservation, body bits
- **Bucket distribution** — 20 buckets, even/uneven/very-uneven verdict
- **Pre-existing scripts** — detects if cover already contains Cyrillic
- **Word-boundary risk** — 3-tier frequency lookup (top 2000 Google Trillion Word Corpus)
- **Verdict tiers** — USABLE / MARGINAL / UNUSABLE with clear reasoning
- **Exit codes** — 0 for USABLE, 1 for MARGINAL/UNUSABLE (scriptable)
- **Default + verbose modes** — compact by default, detailed with `--verbose`
- **Message-len checking** — optional `--message-len N` to validate specific payload sizes

```bash
python3 kometa-grade.py <file> --verbose --message-len 48
cat file.txt | python3 kometa-grade.py
```

---

## Implementation Details

### Key Derivation

```python
salt      = sha256(normalise(cover[:4096]))
keystream = scrypt(password, salt, N=2**17, r=8, p=1, dklen=keylen)
seed      = keystream[:8]
```

The cover is normalised before hashing (all homoglyphs → Latin equivalents), so the salt is stable regardless of whether the cover has been previously encoded.

Decode runs scrypt **twice**: once with a minimal keystream to extract the payload and learn its length, then again at the correct length to produce the matching keystream for decryption. This avoids the need to store the message length out-of-band.

### PRNG

xoshiro128** seeded from the first 8 bytes of the key material. The same algorithm is used for all shuffles — header position selection, body position selection within each bucket, and Fisher-Yates ordering within each bucket.

### Framing

```
bits = to_bits(xor(message, keystream))
     = 16 header bits (big-endian byte count) + N body bits
```

`_from_bits` reads the 2-byte length prefix then extracts exactly that many payload bytes. Maximum message size is 65,535 bytes.

---

## Testing

```bash
python3 kometa-test.py
```

The test suite covers:

1. Encode produces a valid output file
2. Cover integrity — same character length, whitespace preserved
3. Correct password recovers the original message
4. Wrong password produces noise (non-printable bytes, not the original message)
5. Determinism — same inputs always produce identical output
6. Password sensitivity — different password produces different encoding
7. Round-trip with a different password
8. Literal string argument round-trip

---

## Character Dictionary

All pairs satisfy strict two-way visual symmetry across Latin and Cyrillic.

| Latin | Cyrillic |
|---|---|
| K | К |
| O | О |
| M | М |
| E | Е |
| T | Т |
| A | А |
| P | Р |
| H | Н |
| I | І |
| J | Ј |
| X | Х |
| a | а |
| c | с |
| e | е |
| p | р |
| o | о |
| i | і |
| j | ј |
| x | х |
| y | у |

---

## References

- Unicode Technical Report #36 — Unicode Security Considerations
- Unicode Technical Standard #39 — Unicode Security Mechanisms
- IDN Homograph Attack (Wikipedia)
- Unicode confusables dataset: `https://www.unicode.org/Public/security/revision-03/confusablesSummary.txt`

---

## Status

**Implemented:**
- Unified carrier set (20 Latin/Cyrillic pairs) — `DICT` is the single source of truth
- Password-derived key generation via scrypt
- XOR encryption with exact-length keystream
- Dead-zone placement (head/tail exclusion)
- Density-matched carrier distribution across 20 buckets
- Header/body carrier pool separation (length-independent decode bootstrap)
- Wrong-password graceful noise output (no crash)
- CLI: encode / decode
- Utilities: `kometa-cat`, `kometa-flag`, `kometa-grade`
- Test suite

---

## License

TBD
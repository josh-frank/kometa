# `kometa` — Homoglyph Steganography Suite

A covert text steganography system that hides encrypted messages inside ordinary plaintext using Unicode homoglyphs. No anomalous network signature, no zero-width characters, visually indistinguishable from the original to human readers.

---

## Concept

Certain characters across Latin, Cyrillic, and Greek scripts are visually identical at the glyph level but occupy different Unicode code points:

```
Latin    K  O  M  E  T  A  X  P  H  o
Cyrillic К  О  М  Е  Т  А  Х  Р  Н  о
Greek    Κ  Ο  Μ  Ε  Τ  Α  Χ  Ρ  Η  ο
```

A document containing these characters can have any of them silently substituted. The result is indistinguishable from the original to a human reader — and to most automated text processing.

**Encoding scheme:**
- **Latin** — carrier position is inactive; carries no information
- **Cyrillic** — active carrier encoding bit **0**
- **Greek** — active carrier encoding bit **1**

Which positions are active and their read order is determined by a password-seeded shuffle (Fisher-Yates via xoshiro128** PRNG). Inactive positions are normalised to Latin.

---

## Architecture

### Character Sets

**Channel α (implemented):**

```python
ALPHA = dict(
    lat = "KOMETAXPHo",   # inactive — normalised on encode
    cyr = "КОМЕТАХРНо",  # active, bit 0
    ell = "ΚΟΜΕΤΑΧΡΗο",  # active, bit 1
)
```

**Channel β (defined, not yet wired into steganography layer):**

```python
BETA = dict(
    lat = "IJacepijxy",
    cyr = "ІЈасеріјху",
)
```

### Payload Layout

The embedded bitstream has two parts with distinct selection logic:

```
[ header: 16 bits ] [ body: N bits ]
  └─ 2-byte big-endian length of     └─ XOR-encrypted message bytes
     the encrypted message
```

**Header and body use separate carrier pools** so that decode can recover the length without knowing it in advance (see *Carrier Selection* below).

### Security Model

1. **Key derivation** — `scrypt(password, sha256(normalise(cover[:4096])))`
   - Parameters: N=2¹⁷, r=8, p=1
   - Produces seed (8 bytes) + keystream (padded to 64-byte blocks)
   - Salt derived from *normalised* cover text — homoglyph substitutions in the cover do not change the salt, so re-encoding the same cover always produces the same keys

2. **Encryption** — message bytes XOR-ed with keystream
   - Keystream length matched exactly to message length on both encode and decode
   - Wrong password → random noise output, no error thrown

3. **Steganography** — active carrier positions determined by seeded shuffle
   - Bit values encoded via script selection (Cyrillic=0, Greek=1)
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

Rather than distributing active carriers uniformly across the eligible zone, kometa mirrors the document's own carrier density. The eligible carrier pool is divided into **20 buckets**; bits are allocated to each bucket in proportion to its size. The result: paragraphs that are naturally rich in KOMETA/PHo characters receive more encoded bits, sparse paragraphs receive fewer. Squiggle density after encoding tracks squiggle density before encoding.

```python
DENSITY_BUCKETS = 20
```

### Header / Body Split

The 16-bit length header uses its own independently-shuffled carrier pool, selected purely from the dead-zone-excluded positions using the seed alone. Body carriers are then drawn from the remaining eligible positions using density-matched bucket allocation. This split means:

- Decode always recovers the header without needing to know the message length first
- A wrong password produces a garbage length, which is capped to the physical maximum rather than crashing

---

## Payload Capacity

Channel α carriers (K O M E T A X P H o) appear in typical English prose at roughly 1 per 100 characters. Each carrier holds 1 bit. After dead zones (20% of carriers removed) and the 16-bit header:

| Document length | α carriers | Eligible (80%) | Usable payload |
|---|---|---|---|
| 1,000 chars | ~100 | ~80 | ~8 bytes |
| 5,000 chars | ~500 | ~400 | ~48 bytes |
| 20,000 chars | ~2,000 | ~1,600 | ~198 bytes |
| 50,000 chars | ~5,000 | ~4,000 | ~498 bytes |

Carrier-dense covers (technical text, CSVs, proper-noun-heavy documents) will significantly exceed these estimates. Use `kometa-grade` (planned) to measure a specific cover before committing to it.

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

The output file is byte-for-byte the same length as the cover. Whitespace is preserved exactly.

---

## Utilities

### `kometa-cat`

Visualises homoglyph carriers in a document. Highlights substituted characters by script so you can inspect the distribution of encoded bits.

```bash
python3 kometa-cat.py <file>
cat file.txt | python3 kometa-cat.py
```

**Color legend:**
- 🔴 Red — Cyrillic (bit 0)
- 🟢 Green — Greek (bit 1)
- 🔵 Blue — Latin carrier (inactive)
- White — non-carrier character

Summary counts (cyr / ell / lat / total) are written to stderr.

### `kometa-flag`

Scans text for mixed-script words — words containing both Latin and non-Latin (Cyrillic or Greek) characters. Mixed-script words are the main spellchecker detection vector.

```bash
python3 kometa-flag.py <file>
cat file.txt | python3 kometa-flag.py
```

Flagged words are highlighted red. Exit code 1 if any mixed-script words are found. Useful for vetting a cover before use, or auditing an encoded output.

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

The α set satisfies strict three-way visual symmetry across Latin, Cyrillic, and Greek.

| Latin | Cyrillic | Greek | Channel |
|---|---|---|---|
| K | К | Κ | α |
| O | О | Ο | α |
| M | М | Μ | α |
| E | Е | Ε | α |
| T | Т | Τ | α |
| A | А | Α | α |
| X | Х | Χ | α |
| P | Р | Ρ | α |
| H | Н | Η | α |
| o | о | ο | α |
| I | І | — | β (defined) |
| J | Ј | — | β (defined) |
| a | а | — | β (defined) |
| c | с | — | β (defined) |
| e | е | — | β (defined) |
| p | р | — | β (defined) |
| i | і | — | β (defined) |
| j | ј | — | β (defined) |
| x | х | — | β (defined) |
| y | у | — | β (defined) |

β carriers are defined in `BETA` but not yet wired into the steganography layer. When implemented, β will significantly increase capacity for lowercase-heavy prose (common English words like "piece", "price", "cej" contain multiple β carriers).

---

## References

- Unicode Technical Report #36 — Unicode Security Considerations
- Unicode Technical Standard #39 — Unicode Security Mechanisms
- IDN Homograph Attack (Wikipedia)
- Unicode confusables dataset: `https://www.unicode.org/Public/security/revision-03/confusablesSummary.txt`

---

## Status

**Current version:** Password-based steganography, density-matched distribution, dead-zone placement

**Implemented:**
- Channel α (KOMETAXPHo / КОМЕТАХРНо / ΚΟΜΕΤΑΧΡΗο)
- Password-derived key generation via scrypt
- XOR encryption with exact-length keystream
- Dead-zone placement (head/tail exclusion)
- Density-matched carrier distribution across 20 buckets
- Header/body carrier pool separation (length-independent decode bootstrap)
- Wrong-password graceful noise output (no crash)
- CLI: encode / decode
- Utilities: kometa-cat, kometa-flag
- Comprehensive test suite (8 tests)

**Planned:**
- Channel β (IJacepijxy — high-frequency lowercase carriers)
- `kometa-grade` — cover quality assessment (carrier count, density profile, capacity after dead zones, spellcheck risk estimate)

---

## License

TBD

<!-- 
ALPHA = dict(
    lat = "KOMETAXPHo",
    cyr = "КОМЕТАХРНо",
    ell = "ΚΟΜΕΤΑΧΡΗο",
)

BETA = dict(
    lat = "IJacepijxy",
    cyr = "ІЈасеріјху",
)
 -->
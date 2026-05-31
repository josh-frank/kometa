# `kometa` — Homoglyph Steganography Suite

A covert text steganography system that hides encrypted messages inside ordinary plaintext using Unicode homoglyphs. No anomalous network signature, no zero-width characters, and visually indistinguishable from the original to human readers.

---

## Concept

Certain characters across Latin, Cyrillic, and Greek scripts are visually identical at the glyph level but occupy different Unicode code points:

```
Latin    K  O  M  E  T  A  X  P  H  o
Cyrillic К  О  М  Е  Т  А  Х  Р  Н  о
Greek    Κ  Ο  Μ  Ε  Τ  Α  Χ  Ρ  Η  ο
```

A document containing these characters can have any of them silently substituted. The result is indistinguishable from the original to a human reader.

**Encoding scheme:**
- **Latin** — carrier position is inactive; carries no information
- **Cyrillic** — active carrier position encoding bit **0**
- **Greek** — active carrier position encoding bit **1**

Not every carrier position is used. Which positions are active and their read order is determined by a password-seeded shuffle (Fisher-Yates via xoshiro128** PRNG). Inactive positions are reset to Latin.

---

## Architecture

### Character Sets

**Channel α (implemented):**
```javascript
const ALPHA = {
  lat: "KOMETAXPHo",   // inactive — carries no information
  cyr: "КОМЕТАХРНо",  // active, bit 0
  ell: "ΚΟΜΕΤΑΧΡΗο",  // active, bit 1
};
```

**Channel β (planned):**
```javascript
const BETA = {
  lat: "IJij",
  cyr: "ІЈіј",
};
```

### Security Model

1. **Key Derivation**: Password + cover text → scrypt → keystream + seed
   - Seed (8 bytes) → xoshiro128** PRNG → Fisher-Yates shuffle for carrier selection
   - Keystream → XOR with message bytes

2. **Steganography Layer**: 
   - Active carrier positions determined by seeded shuffle
   - Bit values encoded via script selection (Cyrillic=0, Greek=1)
   - Inactive positions reset to Latin

3. **Protection**:
   - Without the password, an adversary cannot determine which positions are active or their read order
   - Wrong password produces random noise, not errors
   - Visual indistinguishability from original text

**Detection vectors to be aware of:**
- A purpose-built scanner checking Unicode blocks can detect substitutions
- Copy-paste through Unicode-normalizing platforms may destroy the payload
- Targeted forensic examination with a hex editor will find this
- Protects against bulk automated surveillance, not determined targeted investigation

---

## Payload Capacity

Channel α carriers (K O M E T A X P H o) appear in typical English prose at roughly one per 100 characters. With 1 bit per active carrier and a 16-bit length header:

| Document length | α carriers available | Usable payload |
|---|---|---|
| 1,000 chars (~1 paragraph) | ~100 bits | ~10 bytes |
| 5,000 chars (~1 page) | ~500 bits | ~60 bytes |
| 20,000 chars (~1 essay) | ~2,000 bits | ~248 bytes |
| 50,000 chars (~short story) | ~5,000 bits | ~622 bytes |

---

## Installation & Usage

### Prerequisites
- Node.js (v14 or later recommended)

### Installation
```bash
# Clone or download the repository
# No npm dependencies — uses Node.js built-ins only
```

### Basic Usage

**Encode a message into a cover text:**
```bash
node kometa.js encode <cover.txt> <message.txt> <password> <output.txt>
```

**Decode an encoded file:**
```bash
node kometa.js decode <encoded.txt> <password> <output.txt>
```

### Examples

Encode a secret message into a cover document:
```bash
node kometa.js encode cover.txt "stop spying on me" correct-horse-battery-staple encoded.txt
```

Decode it back:
```bash
node kometa.js decode encoded.txt correct-horse-battery-staple decoded.txt
```

The encoded file (`encoded.txt`) will look identical to `cover.txt` when viewed normally, but contains your hidden message.

---

## Implementation Details

### Language & Dependencies
- **Pure Node.js** — zero external dependencies
- Uses built-in modules: `fs`, `crypto`, `child_process`

### Key Components

**Key Derivation (`deriveKeys`):**
- Uses `crypto.scryptSync` with configurable parameters
- Salt derived from normalized cover text (first 4096 bytes)
- Produces seed (8 bytes) + keystream (padded to 64-byte blocks)

**PRNG (`_makeRng`):**
- xoshiro128** algorithm seeded from key material
- Deterministic: same seed → same sequence on both sides

**Carrier Selection (`_embed`, `_extract`):**
- Collects all carrier positions in document
- Shuffles via Fisher-Yates using PRNG
- First N positions become active (N = bits needed)
- Bits encoded via script selection

**Encryption (`_xor`):**
- Simple XOR of message bytes with keystream
- Wrong password → random noise (no error thrown)

---

## Testing

Run the test suite to verify functionality:
```bash
node kometa-test.js
```

Tests cover:
1. Encoding produces valid output file
2. Cover integrity (length, whitespace preservation)
3. Decoding with correct password recovers message
4. Decoding with wrong password produces noise
5. Deterministic encoding (same input → same output)
6. Password sensitivity (different password → different encoding)
7. Cover survives round-trip

---

## Character Dictionary

The α set satisfies strict three-way visual symmetry across Latin, Cyrillic, and Greek. The β set (planned) uses Serbian Cyrillic equivalents for I and J.

| Latin | Cyrillic | Greek | Role |
|---|---|---|---|
| K | К | Κ | α carrier |
| O | О | Ο | α carrier |
| M | М | Μ | α carrier |
| E | Е | Ε | α carrier |
| T | Т | Τ | α carrier |
| A | А | Α | α carrier |
| X | Х | Χ | α carrier |
| P | Р | Ρ | α carrier |
| H | Н | Η | α carrier |
| o | о | ο | α carrier |
| I | І | - | β carrier (planned) |
| J | Ј | - | β carrier (planned) |
| i | і | - | β carrier (planned) |
| j | ј | - | β carrier (planned) |

---

## References

- Unicode Technical Report #36 — Unicode Security Considerations
- Unicode Technical Standard #39 — Unicode Security Mechanisms  
- IDN Homograph Attack (Wikipedia)
- Unicode confusables dataset: `http://www.unicode.org/Public/security/revision-03/confusablesSummary.txt`

---
## Status

**Current version:** Password-based steganography with scrypt key derivation

**Implemented:**
- Channel α (KOMETAXPHo carriers)
- Password-derived key generation
- XOR encryption
- Homoglyph embedding/extraction
- CLI interface (encode/decode)
- Comprehensive test suite

**Planned:**
- Channel β (IJij carriers)
- Interactive editor
- Analyze tool for detection testing

---
## License

TBD

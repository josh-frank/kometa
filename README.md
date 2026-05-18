# `kometa` — Homoglyph Steganography Suite

A covert multi-channel text steganography system using Unicode homoglyphs and one-time pad encryption. Hides encrypted payloads inside ordinary plaintext documents with no anomalous network signature, no zero-width characters, and neurological invisibility to human readers.

---

## Concept

Certain characters across Latin, Cyrillic, and Greek scripts are visually identical at the glyph level but occupy different Unicode code points:

```
Latin    K  O  M  E  T  A  X  P  H  o
Cyrillic К  О  М  Е  Т  А  Х  Р  Н  о
Greek    Κ  Ο  Μ  Ε  Τ  Α  Χ  Ρ  Η  ο
```

A document containing these characters can have any of them silently substituted. The result is indistinguishable from the original to a human reader. Which substitution is made — or whether any is made at all — encodes a payload bit stream. That bit stream is encrypted with a one-time pad before embedding, making the extracted ciphertext information-theoretically unbreakable without the pad.

---

## Architecture

### Two Independent Channels

The suite operates two orthogonal steganographic channels simultaneously in the same cover document:

**Channel α — Triad Channel**
```
Carriers:  K O M E T A X P H o
Scripts:   Latin / Cyrillic / Greek
Encoding:  ternary (log₂3 ≈ 1.58 bits per carrier position)
```

Each carrier character has three possible states — Latin, Cyrillic, or Greek. The choice encodes ~1.58 bits per position. In normal English prose these twelve characters appear frequently enough to provide meaningful payload capacity.

**Channel β — Binary Channel**
```
Carriers:  I J
Scripts:   Latin / Serbian Cyrillic  (І Ј)
Encoding:  binary (1 bit per carrier position)
```

Serbian Cyrillic provides visually identical equivalents for I, and J. Greek has no clean equivalents for these, so this channel is strictly binary. I is among the most frequent letters in English, giving this channel significant capacity despite being single-bit.

The two channels carry **independent payloads encrypted with independent OTP pads**. An adversary who finds and fully compromises channel α has no indication channel β exists.

### Encoding Pipeline

```
plaintext payload
      │
      ▼
  [compress]              ← reduce payload size before encryption
      │
      ▼
  [OTP encrypt]           ← XOR with cryptographically random pad
      │
      ├─────────────────────────────────┐
      ▼                                 ▼
 bitstream α                       bitstream β
 (1.58 bits/carrier)               (1 bit/carrier)
      │                                 │
      ▼                                 ▼
KOMETAXPBHop positions           I J positions
triad substitution               binary substitution
Latin / Cyrillic / Greek         Latin / Serbian Cyrillic
      │                                 │
      └──────────────┬──────────────────┘
                     ▼
              cover plaintext
         (visually identical to input)
                     │
                     ▼
              transmit freely
```

### Decoding Pipeline

Receiver walks the document character by character. At each carrier position:
- Channel α: Latin → `0x`, Cyrillic → `1x`, Greek → `x1` (or chosen encoding)
- Channel β: Latin → `0`, Serbian Cyrillic → `1`

Extracted bit streams are XORed with the respective pads to recover plaintext.

---

## Payload Capacity

Approximate capacity in typical English prose:

| Document length | Channel α | Channel β | Total |
|---|---|---|---|
| 1,000 chars (~1 paragraph) | ~13 bytes | ~1.6 bytes | ~15 bytes |
| 5,000 chars (~1 page) | ~65 bytes | ~8 bytes | ~73 bytes |
| 20,000 chars (~1 essay) | ~260 bytes | ~32 bytes | ~292 bytes |
| 50,000 chars (~short story) | ~650 bytes | ~80 bytes | ~730 bytes |

730 bytes is sufficient for a 4096-bit RSA public key, a meaningful encrypted message, or an OTP pad for a subsequent shorter message.

---

## Security Model

**What the OTP provides:** Information-theoretic security on the payload. Without the pad, the extracted bit stream is provably indistinguishable from random noise. This is not computational security — it is mathematically unbreakable regardless of adversary compute power.

**What the homoglyph layer provides:** Covert channel existence deniability against automated scanning. There are no zero-width characters. No anomalous byte sequences. No statistical artifacts visible to standard DLP or Unicode scanners.

**What the dual-channel architecture provides:** Independent compromise resistance. Discovering channel α reveals nothing about channel β. Each channel requires its own pad. A coerced reveal of one pad yields one message with no indication a second exists — a natural duress/deniability structure.

**Detection vectors to be aware of:**
- A purpose-built scanner checking every character's Unicode block can detect substitutions
- Copy-paste through Unicode-normalising platforms (some CMS, certain email clients) can silently destroy the payload
- A targeted forensic examiner with prior suspicion and a hex editor finds this quickly
- The scheme protects against bulk automated surveillance, not a determined targeted investigation

**The OTP non-negotiable:** Pad bytes must never be reused. Reuse allows an adversary to XOR two ciphertexts and cancel the key entirely, reducing the problem to frequency analysis of two known-language plaintexts. The pad management layer hard-enforces consumption tracking and refuses reuse — this is not a warning, it is a hard stop.

---

## Planned Components

### `kometa-encode` / `kometa-decode`
Core CLI tools. Embed a payload into a cover text file; extract and decrypt a payload from a `kometa` document. Accepts piped input. Explicit pad file and offset tracking.

### `kometa-edit`
Interactive editor modelled on `nano`. Split-pane view: rendered cover text on the left, annotated carrier map on the right showing which positions carry bits and current payload density. Real-time capacity warning as you type.

### `kometa-analyze`
Two modes:
- **Own-document mode:** Given a pad, fully decode the document and report payload, density map, and pad consumption.
- **Adversarial mode:** Without a pad, detect substitution presence, measure carrier density anomalies, report a suspicion score. Use this to red-team your own documents before transmission.

### `kometa-pad`
First-class pad management. Generates pads via CSPRNG, tracks consumption state, enforces non-reuse, supports secure destruction. Pad state is persisted with a random pad ID and checksum to detect substitution attacks on the state file.

### `kometa-test`
- Roundtrip fuzz tester: encode random payloads, decode, verify bit-perfect recovery
- Capacity benchmark across a corpus of cover texts
- Renderer compatibility matrix: does the substitution survive Gmail, Slack, Signal, Google Docs, iMessage?
- Detectability scoring: run your own documents through adversarial mode and report

---

## Implementation

### Language

**Rust** — the only mainstream language competitive across all three requirements simultaneously:

- **Memory safety** for the OTP layer (pad material must never leak into recoverable memory)
- **`zeroize` crate** for guaranteed pad zeroing the compiler cannot optimise away
- **`subtle` crate** for constant-time operations (no timing side-channels on secret data)
- **`getrandom`** for direct OS-level CSPRNG access
- **Native `char` type** is a Unicode scalar value — homoglyph substitution is a lookup over `char → char` with no encoding ambiguity possible
- **`wasm-pack`** compiles the core to WASM for browser use — same codebase, same security guarantees, in the browser

### Key Crates

| Purpose | Crate |
|---|---|
| CSPRNG | `getrandom` |
| Constant-time ops | `subtle` |
| Guaranteed zeroing | `zeroize` |
| CLI | `clap` |
| Unicode segmentation | `unicode-segmentation` |
| Serialization | `serde` + `bincode` |
| Terminal UI | `ratatui` + `crossterm` |
| Fuzzing | `cargo fuzz` |
| Property testing | `proptest` |

### WASM / Browser

The core encode/decode compiles to WASM via `wasm-pack`. The browser interface gets an `IndexedDB` adapter for pad storage behind the same interface as the filesystem adapter used by the CLI. The OTP layer never touches a server.

---

## The Dictionary

```javascript
// Channel α — triad (Latin / Cyrillic / Greek)
const alpha = {
  lat: "KOMETAXPBHop",
  cyr: "КОМЕТАХРВНор",
  ell: "ΚΟΜΕΤΑΧΡΒΗορ",
};

// Channel β — binary (Latin / Serbian Cyrillic)
const beta = {
  lat: "IJ",
  cyr: "ІЈ",
};
```

These twelve uppercase and two lowercase characters are the complete set satisfying strict three-way visual symmetry across Latin, Cyrillic, and Greek. Other scripts (Lisu, Coptic, Cherokee) contain partial matches but fail visual inspection at second glance. Serbian/Ukrainian Cyrillic extends the set for a binary-only channel. This asymmetry — the triad set and the binary set — is a feature, not a limitation: it produces two independent channels naturally.

---

## Potential uses for the β channel

A much more elegant use of the beta channel, instead of carrying an independent payload, is to make it part of the cryptographic infrastructure for channel α. A few ways this could work:

**Salt/IV embedding**
The I/J positions encode a random salt that was XORed into the alpha channel before embedding. Receiver extracts the salt from β first, then uses it to de-salt α before OTP decryption. This means even if someone has the α pad, they can't decode without also knowing the β encoding — adds a second factor naturally.

**Carrier selection mask**
β bits determine *which* α carrier positions are active vs. decoy. Some triad positions carry real payload trits, others are randomized noise. The β bitstream is the mask that tells the receiver which positions to read. An adversary seeing the α channel sees a valid-looking triad distribution with no obvious signal — because half the positions are intentional noise.

**Commitment / integrity check**
β encodes a short checksum or HMAC over the α payload. Decoding succeeds only if β verifies. Detects document tampering, normalization damage, or copy-paste corruption — which is actually your biggest operational risk.

The **carrier selection mask** idea feels most synergistic — it directly addresses the "uniform carrier density looks suspicious" problem, since decoy positions can be randomized to mimic natural script variation.

---

## Bugs

**1. The decode termination logic is wrong for encrypted payloads.**

```js
if (info.setName === "lat") break;  // ← this is the problem
```

This made sense when payload bits might naturally run out and you flip remaining carriers to Latin. But after OTP encryption, the length header bytes themselves are encrypted — so the first carrier the encoder touches is *always* either Cyr or Greek (never Latin), and you never hit an early-Latin until the payload is done. That part is fine.

The real problem: if the OTP produces a `0x00` byte anywhere in the encrypted length header, `bitsToMessage` will read `length = 0` and return an empty string even though more bits follow. The decoder won't break early (no Latin encountered yet), but it will reconstruct the wrong length and silently return garbage. The fix: validate the decoded length against the actual number of bits available.

**2. `messageToBits` uses `charCodeAt(0)` which only handles ASCII (0–127).**

If your message or — more importantly — the OTP-encrypted bytes produce values > 127, `charCodeAt` still returns the right value (0–255 for Latin-1), but `String.fromCharCode` in `bitsToMessage`'s reverse path is also fine for that range. So this actually works up to 255. However, if you ever move to proper Unicode messages, this breaks. Worth flagging now even if it's not a current bug.

**3. `otpGenerate` pad length = message bytes, but the length header adds 2 bytes.**

The smoke test calls `otpGenerate(secret.length)` — but the thing being OTP-encrypted is `messageBytes` (the raw message), not the length-prefixed bitstream. The length header is added *after* encryption in `messageToBits`. So the pad size is correct for the current code. But this is a subtle invariant that's easy to break if someone refactors — worth a comment.

---

## Prior Art & References

- Unicode Technical Report #36 — Unicode Security Considerations
- Unicode Technical Standard #39 — Unicode Security Mechanisms  
- IDN Homograph Attack (Wikipedia)
- Unicode confusables dataset: `http://www.unicode.org/Public/security/revision-03/confusablesSummary.txt`

---

## Status

Pre-implementation. Architecture and encoding scheme defined. Dictionary validated empirically — substitutions survive copy-paste through Claude.ai; further renderer compatibility testing required before operational use.

---

## License

TBD

<!-- Original dictionary
const dictionary = {
  alpha: {
    lat: "KOMETAXPBHop", // Latin
    cyr: "КОМЕТАХРВНор", // Cyrillic
    ell: "ΚΟΜΕΤΑΧΡΒΗορ", // Greek
  },
  beta: {
    lat: "IJij",
    cyr: "ІЈіј",
  },
};
 -->

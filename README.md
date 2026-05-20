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

A document containing these characters can have any of them silently substituted. The result is indistinguishable from the original to a human reader. The scheme uses this as follows:

- **Latin** — carrier position is inactive; carries no information
- **Cyrillic** — active carrier position encoding bit **0**
- **Greek** — active carrier position encoding bit **1**

Not every carrier position in the document is used. Which positions are active, and the order in which they are read, is determined by a Fisher-Yates shuffle seeded from the first 8 bytes of the OTP pad. The remaining pad bytes XOR the message before embedding, making the ciphertext information-theoretically unbreakable without the pad. Both the position seed and the OTP key material live in the same pad file — one secret, two layers of protection.

---

## Architecture

### Channel α — current implementation

```
Carriers:  K O M E T A X P H o
Scripts:   Latin / Cyrillic / Greek
Encoding:  binary (1 bit per active carrier position)
```

Each carrier character has three possible states — Latin, Cyrillic, or Greek — but the current encoding uses only two of them to carry payload bits:

```
Active carrier, bit 0  →  Cyrillic  (К О М Е Т А Х Р Н о)
Active carrier, bit 1  →  Greek     (Κ Ο Μ Ε Τ Α Χ Ρ Η ο)
Inactive carrier       →  Latin     (K O M E T A X P H o)
```

Not every carrier position in the document is active. Which positions carry bits — and their read order — is determined by a pad-seeded shuffle (see below). Inactive positions are reset to Latin and carry no information.

### Pad layout

The OTP pad serves a dual purpose. Its bytes are split into two regions:

```
Bytes 0–7   carrier selection seed   → feeds xoshiro128** PRNG
Bytes 8–N   OTP key material         → XORed with message bytes
```

The pad is always generated as a multiple of 64 bytes so its length does not leak the message length.

### Keyed carrier selection

All carrier positions in the cover document are collected in document order, then shuffled by a Fisher-Yates pass driven by the xoshiro128** PRNG seeded from pad bytes 0–7. The first `N` positions in the shuffled order are declared **active** (where `N = bits needed to encode the OTP-encrypted message`). All others are reset to Latin.

Encoder and decoder reconstruct the identical shuffle independently from the same pad — no additional signalling is required.

This has two consequences:

- **Uniform visual distribution.** Active bits are spread across the full document rather than front-loaded, so carrier density is even everywhere.
- **Position secrecy.** Without the pad, an adversary cannot determine which positions are active or in what order to read them. Even if they extract the correct bits from every carrier position, they read them in the wrong order: the output is noise independent of the OTP layer.

Both the position order and the OTP key are required to recover the message.

### Encoding pipeline

```
plaintext payload
      │
      ▼
  [OTP encrypt]                ← XOR message bytes with pad bytes 8–N
      │
      ▼
  [prepend 16-bit length]      ← length of encrypted payload in bytes
      │
      ▼
  [serialize to bitstream]     ← MSB-first, one bit per carrier slot
      │
      ▼
  [keyed carrier selection]    ← Fisher-Yates shuffle seeded from pad bytes 0–7
      │                           first N positions → active
      ▼                           remaining positions → Latin (inactive)
  embed into cover text
  active pos, bit 0 → Cyrillic
  active pos, bit 1 → Greek
  inactive pos      → Latin
      │
      ▼
   output file
(visually identical to input)
      │
      ▼
  transmit freely
```

### Decoding pipeline

```
encoded document + pad
      │
      ├─ extract pad bytes 0–7 → seed xoshiro128** → reconstruct Fisher-Yates shuffle
      │
      ├─ walk document, record all carrier positions and their observed script
      │    Cyrillic → bit 0
      │    Greek    → bit 1
      │    Latin    → inactive (no bit)
      │
      ├─ read bits in shuffled order to recover encrypted bitstream
      │
      ├─ decode 16-bit length header → know how many payload bytes to read
      │
      ├─ XOR encrypted bytes with pad bytes 8–N → plaintext
      │
      └─ destroy pad (overwrite + unlink)
```

### Channel β — planned

```
Carriers:  I J i j
Scripts:   Latin / Serbian Cyrillic  (І Ј і ј)
Encoding:  binary (1 bit per carrier position)
```

Serbian Cyrillic provides visually identical equivalents for I, J, i, j. Greek has no clean equivalents for these, so this channel is strictly binary. I is among the most frequent letters in English, giving this channel meaningful capacity. Channel β is architecturally independent of channel α — independent payload, independent pad, no coupling. **Not yet implemented.**

---

## Payload Capacity

Channel α carriers (K O M E T A X P H o) appear in typical English prose at roughly one per 100 characters. The current binary encoding uses 1 bit per active carrier. With a 16-bit length header, usable payload per document length is approximately:

| Document length | α carriers available | Usable payload |
|---|---|---|
| 1,000 chars (~1 paragraph) | ~100 bits | ~10 bytes |
| 5,000 chars (~1 page) | ~500 bits | ~60 bytes |
| 20,000 chars (~1 essay) | ~2,000 bits | ~248 bytes |
| 50,000 chars (~short story) | ~5,000 bits | ~622 bytes |

622 bytes is sufficient for a 4096-bit RSA public key, a meaningful encrypted message, or an OTP pad for a subsequent shorter message.

When channel β is implemented, its capacity adds roughly 8–10% on top of these figures (I and J are less frequent than the α set).

---

## Security Model

**What the OTP provides:** Information-theoretic security on the payload. Without the pad, the extracted bit stream is provably indistinguishable from random noise. This is not computational security — it is mathematically unbreakable regardless of adversary compute power.

**What the keyed carrier selection provides:** A second independent secret derived from the same pad. The carrier shuffle seed (pad bytes 0–7) determines which positions are active and in what order to read them. An adversary who extracts bits from all carrier positions without the pad reads them in the wrong order — the result is noise before the OTP layer is even considered. Recovering the message requires both the position order (seed) and the OTP key material: two secrets, one pad.

**What the homoglyph layer provides:** Covert channel existence deniability against automated scanning. There are no zero-width characters. No anomalous byte sequences. No statistical artifacts visible to standard DLP or Unicode scanners. Inactive carriers are reset to Latin, so the document contains no unexpected script mixing beyond what the payload positions require.

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
// Channel α — binary (Latin inactive / Cyrillic bit 0 / Greek bit 1)
const alpha = {
  lat: "KOMETAXPHo",   // inactive — carries no information
  cyr: "КОМЕТАХРНо",  // active, bit 0
  ell: "ΚΟΜΕΤΑΧΡΗο",  // active, bit 1
};

// Channel β — binary (Latin / Serbian Cyrillic) — planned
const beta = {
  lat: "IJij",
  cyr: "ІЈіј",
};
```

The α set satisfies strict three-way visual symmetry across Latin, Cyrillic, and Greek. Other scripts (Lisu, Coptic, Cherokee) contain partial matches but fail visual inspection at second glance. Serbian/Ukrainian Cyrillic extends the set with I and J equivalents for the planned binary β channel. The α and β sets are disjoint — they operate on different carrier characters with no overlap.

---

## Potential uses for the β channel

A much more elegant use of the beta channel, instead of carrying an independent payload, is to make it part of the cryptographic infrastructure for channel α. A few ways this could work:

**Salt/IV embedding**
The I/J positions encode a random salt that was XORed into the alpha channel before embedding. Receiver extracts the salt from β first, then uses it to de-salt α before OTP decryption. This means even if someone has the α pad, they can't decode without also knowing the β encoding — adds a second factor naturally.

**Carrier selection mask**
β bits determine *which* α carrier positions are active vs. decoy. Some carrier positions carry real payload bits, others are randomized noise (Cyr or Greek chosen at random). The β bitstream is the mask that tells the receiver which α positions to read. An adversary seeing the α channel sees script substitutions distributed across the document with no obvious signal — because some positions are intentional noise. Note that the current implementation achieves a weaker version of this via the pad-seeded Fisher-Yates shuffle: inactive positions are reset to Latin rather than randomized, which is simpler but slightly more detectable.

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

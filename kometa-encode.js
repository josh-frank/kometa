// ─────────────────────────────────────────────
// kometa-encode.js
// Homoglyph steganography — MVP encode/decode
// ─────────────────────────────────────────────

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

// ─────────────────────────────────────────────
// Lookup table helpers
// ─────────────────────────────────────────────

// Build lookup: char -> { setName, index }
// Works on a single channel dict e.g. dictionary.alpha
function buildLookupTableFrom(dict) {
  const lookup = new Map();
  for (const [setName, chars] of Object.entries(dict)) {
    for (let i = 0; i < chars.length; i++) {
      lookup.set(chars[i], {setName, index: i});
    }
  }
  return lookup;
}

// ─────────────────────────────────────────────
// Bit packing helpers
// ─────────────────────────────────────────────

// Convert a string message to a flat array of bits [0,1,1,0,...]
// Prepends an 8-bit length header (max message: 16 bits - 65,535 chars)
function messageToBits(message) {
  if (message.length > 65535)
    throw new Error("Message too long for MVP (max 65,535 chars)");
  const bytes = [
    message.length,
    ...message.split("").map(c => c.charCodeAt(0)),
  ];
  const bits = [];
  for (const byte of bytes) {
    for (let b = 7; b >= 0; b--) {
      bits.push((byte >> b) & 1);
    }
  }
  return bits;
}

// Convert a flat array of bits back to a string message
// Reads the 8-bit length header first
function bitsToMessage(bits) {
  const readByte = offset => {
    let val = 0;
    for (let b = 0; b < 8; b++) val = (val << 1) | (bits[offset + b] ?? 0);
    return val;
  };
  const length = readByte(0);
  let message = "";
  for (let i = 0; i < length; i++) {
    message += String.fromCharCode(readByte(8 + i * 8));
  }
  return message;
}

// ─────────────────────────────────────────────
// One time pad helpers
// ─────────────────────────────────────────────
function otpBase64(bytes = 32) {
  const arr = new Uint8Array(bytes);
  crypto.getRandomValues(arr);
  return btoa(String.fromCharCode(...arr));
}

function applyOTP(messageBytes, otpBase64) {
  const padBytes = Uint8Array.from(atob(otpBase64), c => c.charCodeAt(0));
  return messageBytes.map((byte, i) => byte ^ padBytes[i]);
}

// ─────────────────────────────────────────────
// Encoding scheme
//
// Each alpha carrier position has three states:
//   Latin    → 00  (no bit encoded — carrier is "off")
//   Cyrillic → 10  (bit = 0)
//   Greek    → 11  (bit = 1)
//
// Latin is the neutral/unflipped state. Only Cyr/Ell carry bits.
// This gives 1 bit per carrier with a natural "off" state for
// positions where we've run out of payload — no noise needed.
// ─────────────────────────────────────────────

// Encode a message string into a plaintext cover string.
// Returns the steganographic output string.
function encode(plaintext, message) {
  const alphaLookup = buildLookupTableFrom(dictionary.alpha);
  const bits = messageToBits(message);
  let bitIndex = 0;
  let result = "";

  for (let i = 0; i < plaintext.length; i++) {
    const char = plaintext[i];
    const info = alphaLookup.get(char);

    if (!info) {
      // Not a carrier — pass through unchanged
      result += char;
      continue;
    }

    if (bitIndex >= bits.length) {
      // All bits embedded — leave remaining carriers as Latin (neutral)
      result += dictionary.alpha.lat[info.index];
      continue;
    }

    // Embed next bit: 0 → Cyrillic, 1 → Greek
    const bit = bits[bitIndex++];
    result +=
      bit === 0
        ? dictionary.alpha.cyr[info.index]
        : dictionary.alpha.ell[info.index];
  }

  if (bitIndex < bits.length) {
    throw new Error(
      `Insufficient carrier capacity: needed ${bits.length} bits, ` +
        `only ${bitIndex} positions available in cover text`,
    );
  }

  return result;
}

// Decode a steganographic string back to the hidden message.
function decode(encoded) {
  const alphaLookup = buildLookupTableFrom(dictionary.alpha);
  const bits = [];

  for (let i = 0; i < encoded.length; i++) {
    const char = encoded[i];
    const info = alphaLookup.get(char);
    if (!info) continue;

    if (info.setName === "lat") {
      // Latin carrier = off, stop reading (all remaining will also be lat)
      break;
    } else if (info.setName === "cyr") {
      bits.push(0);
    } else if (info.setName === "ell") {
      bits.push(1);
    }
  }

  return bitsToMessage(bits);
}

// ─────────────────────────────────────────────
// Quick smoke test
// ─────────────────────────────────────────────

const cover =
  'Scientology is perhaps a religion, is probably a philosophy, is definitely a business, is potentially a political force, and is also a form of therapy, or as they call it now, pastoral counseling. Most people do not realize this, since the Scientologists draw attention only to the idea that they are a religion and a philosophy. Thus, they have been able to keep the public in the dark about what is happening -- and they have also been largely able to avoid public outcry. Scientologists have devised a series of methods that they believe can and will save this "enturbulated" world. Some of their practices -- those that have been widely criticized, such as disconnecting, suppressives, investigations -- are based on their belief that anyone who questions, criticizes or tries to stop Scientology from utilizing these methods is harming not only themselves but the world. Scientologists try to keep their methods of pastoral counseling a very strict secret. While this shields them from criticism, it also makes doctors doubtful as to its efficacy. "Suppose Newton had founded a Church of Newtonian physics and refused to show his formula to anyone who doubted the tenets of Newtonian physics?" wrote William Burroughs.[{2}](#c2) (In an earlier stage, when Burroughs was apparently more enchanted with Scientology, he wrote "There is nothing secret about Scientology, no talk of initiates, secret doctrines or hidden knowledge."[{3}](#c3)) But only someone who takes advanced Scientology courses or "grades" can find out what Scientology methods are.';
const secret = "stop spying on me";

const encoded = encode(cover, secret);
const decoded = decode(encoded);

console.log("Cover:  ", cover);
console.log("Encoded:", encoded);
console.log("Decoded:", decoded);
console.log("Match:  ", decoded === secret ? "✓" : "✗ MISMATCH");

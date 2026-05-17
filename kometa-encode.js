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

// Convert a string to a flat bit array.
// Prepends a 16-bit big-endian length header (max 65,535 chars).
function messageToBits(message) {
  if (message.length > 65535)
    throw new Error("Message too long (max 65,535 chars)");
  const len = message.length;
  const bytes = [
    len >> 8,
    len & 0xff,
    ...message.split("").map(c => c.charCodeAt(0)),
  ];
  const bits = [];
  for (const byte of bytes) {
    for (let b = 7; b >= 0; b--) bits.push((byte >> b) & 1);
  }
  return bits;
}

// Convert a flat bit array back to a string.
// Reads the 16-bit length header first.
function bitsToMessage(bits) {
  const readByte = offset => {
    let val = 0;
    for (let b = 0; b < 8; b++) val = (val << 1) | (bits[offset + b] ?? 0);
    return val;
  };
  const length = (readByte(0) << 8) | readByte(8);
  let message = "";
  for (let i = 0; i < length; i++) {
    message += String.fromCharCode(readByte(16 + i * 8));
  }
  return message;
}

// ─────────────────────────────────────────────
// OTP helpers
// ─────────────────────────────────────────────

// Generate a cryptographically random OTP pad, base64-encoded.
// bytes should equal the message length in bytes.
function otpGenerate(bytes = 32) {
  const arr = new Uint8Array(bytes);
  crypto.getRandomValues(arr);
  return btoa(String.fromCharCode(...arr));
}

// XOR an array of message bytes against a base64-encoded pad.
// Returns a new Uint8Array of the same length.
function otpApply(messageBytes, padBase64) {
  const padBytes = Uint8Array.from(atob(padBase64), c => c.charCodeAt(0));
  if (padBytes.length < messageBytes.length)
    throw new Error(
      `OTP pad too short: need ${messageBytes.length} bytes, got ${padBytes.length}`,
    );
  return messageBytes.map((byte, i) => byte ^ padBytes[i]);
}

// ─────────────────────────────────────────────
// Encoding scheme
//
// Each alpha carrier position has three states:
//   Latin    → carrier is "off" (no bit)
//   Cyrillic → bit = 0
//   Greek    → bit = 1
//
// Latin is the neutral/unflipped state. Only Cyr/Ell carry bits.
// This gives 1 bit per carrier with a natural "off" state for
// positions where we've run out of payload — no noise needed.
//
// OTP layer: message bytes are XORed with pad before embedding.
// Without the pad, extracted bits are indistinguishable from noise.
// ─────────────────────────────────────────────

// Encode a message into a cover text using OTP encryption.
// pad: base64 string from otpGenerate(message.length)
function encode(plaintext, message, pad) {
  // Encrypt: XOR message bytes with pad
  const messageBytes = Uint8Array.from(
    message.split("").map(c => c.charCodeAt(0)),
  );
  const encryptedBytes = otpApply(messageBytes, pad);

  // Pack encrypted bytes into bits (with length header)
  const encryptedStr = Array.from(encryptedBytes)
    .map(b => String.fromCharCode(b))
    .join("");
  const bits = messageToBits(encryptedStr);

  const alphaLookup = buildLookupTableFrom(dictionary.alpha);
  let bitIndex = 0;
  let result = "";

  for (let i = 0; i < plaintext.length; i++) {
    const char = plaintext[i];
    const info = alphaLookup.get(char);

    if (!info) {
      result += char;
      continue;
    }

    if (bitIndex >= bits.length) {
      // Payload fully embedded — neutralise remaining carriers to Latin
      result += dictionary.alpha.lat[info.index];
      continue;
    }

    const bit = bits[bitIndex++];
    result +=
      bit === 0
        ? dictionary.alpha.cyr[info.index]
        : dictionary.alpha.ell[info.index];
  }

  if (bitIndex < bits.length)
    throw new Error(
      `Insufficient carrier capacity: needed ${bits.length} bits, ` +
        `only ${bitIndex} positions available in cover text`,
    );

  return result;
}

// Decode a steganographic string back to the hidden message.
// pad: the same base64 pad used during encode
function decode(encoded, pad) {
  const alphaLookup = buildLookupTableFrom(dictionary.alpha);
  const bits = [];

  for (let i = 0; i < encoded.length; i++) {
    const char = encoded[i];
    const info = alphaLookup.get(char);
    if (!info) continue;

    if (info.setName === "lat") break; // payload ends at first Latin carrier
    bits.push(info.setName === "cyr" ? 0 : 1);
  }

  // Recover encrypted bytes from bits, then XOR with pad to decrypt
  const encryptedStr = bitsToMessage(bits);
  const encryptedBytes = Uint8Array.from(
    encryptedStr.split("").map(c => c.charCodeAt(0)),
  );
  const decryptedBytes = otpApply(encryptedBytes, pad);

  return Array.from(decryptedBytes)
    .map(b => String.fromCharCode(b))
    .join("");
}

// ─────────────────────────────────────────────
// Quick smoke test
// ─────────────────────────────────────────────

const cover =
  `Scientology is perhaps a religion, is probably a philosophy, is definitely a business, is potentially a political force, and is also a form of therapy, or as they call it now, pastoral counseling. Most people do not realize this, since the Scientologists draw attention only to the idea that they are a religion and a philosophy. Thus, they have been able to keep the public in the dark about what is happening -- and they have also been largely able to avoid public outcry. Scientologists have devised a series of methods that they believe can and will save this "enturbulated" world. Some of their practices -- those that have been widely criticized, such as disconnecting, suppressives, investigations -- are based on their belief that anyone who questions, criticizes or tries to stop Scientology from utilizing these methods is harming not only themselves but the world. Scientologists try to keep their methods of pastoral counseling a very strict secret. While this shields them from criticism, it also makes doctors doubtful as to its efficacy. "Suppose Newton had founded a Church of Newtonian physics and refused to show his formula to anyone who doubted the tenets of Newtonian physics?" wrote William Burroughs. (In an earlier stage, when Burroughs was apparently more enchanted with Scientology, he wrote "There is nothing secret about Scientology, no talk of initiates, secret doctrines or hidden knowledge." But only someone who takes advanced Scientology courses or "grades" can find out what Scientology methods are. If any Scientologist divulges these secrets after he takes the courses, he is subject to expulsion. But even though he doesn't know what the courses are until he takes them, he must agree that they are correct in advance and cannot question them. "It's like a physicist saying 'you can't see my formulae unless you first agree that they are correct sight unseen,' " said Burroughs. Some of these secret sessions are done with the E-meter, although other sessions consist of a series of exercises to "raise the preclear's ability." When working with the meter, the auditor may first show the preclear the auditing room and ask if there is anything about it that upsets him. The preclear may also be told to remove his watch and wedding ring to prevent interference by outside metals. Then the auditor and preclear face each other in chairs, with the E-meter on a table between them.`;
const secret = "stop spying on me";
const pad = otpGenerate(secret.length);

const encoded = encode(cover, secret, pad);
const decoded = decode(encoded, pad);

console.log("Cover:  ", cover);
console.log("Pad:    ", pad);
console.log("Encoded:", encoded);
console.log("Decoded:", decoded);
console.log("Match:  ", decoded === secret ? "✓" : "✗ MISMATCH");

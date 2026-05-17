// ─────────────────────────────────────────────
// kometa-encode.js
// Homoglyph steganography — MVP encode/decode
// ─────────────────────────────────────────────

const fs = require("fs");
const path = require("path");

const dictionary = {
  alpha: {
    lat: "KOMETAXPHo", // Latin   (B and p removed)
    cyr: "КОМЕТАХРНо", // Cyrillic
    ell: "ΚΟΜΕΤΑΧΡΗο", // Greek
  },
  beta: {
    lat: "IJij",
    cyr: "ІЈіј",
  },
};

// ─────────────────────────────────────────────
// Lookup table helpers
// ─────────────────────────────────────────────

const buildLookupTableFrom = dict => {
  const lookup = new Map();
  for (const [setName, chars] of Object.entries(dict)) {
    for (let i = 0; i < chars.length; i++) {
      lookup.set(chars[i], {setName, index: i});
    }
  }
  return lookup;
};

// ─────────────────────────────────────────────
// Bit packing helpers
// ─────────────────────────────────────────────

// Convert a string to a flat bit array.
// Prepends a 16-bit big-endian length header (max 65,535 chars).
const messageToBits = message => {
  if (message.length > 65535)
    throw new Error("Message too long (max 65,535 chars)");
  const len = message.length;
  const bytes = [
    len >> 8,
    len & 0xff,
    ...message.split("").map(c => c.charCodeAt(0)),
  ];
  const bits = [];
  for (const byte of bytes)
    for (let b = 7; b >= 0; b--) bits.push((byte >> b) & 1);
  return bits;
};

// Convert a flat bit array back to a string.
// Reads the 16-bit length header first.
const bitsToMessage = bits => {
  const readByte = offset => {
    let val = 0;
    for (let b = 0; b < 8; b++) val = (val << 1) | (bits[offset + b] ?? 0);
    return val;
  };
  const length = (readByte(0) << 8) | readByte(8);
  let message = "";
  for (let i = 0; i < length; i++)
    message += String.fromCharCode(readByte(16 + i * 8));
  return message;
};

// ─────────────────────────────────────────────
// OTP helpers
// ─────────────────────────────────────────────

// Generate a cryptographically random OTP pad, base64-encoded.
// bytes should equal the message length in bytes.
const otpGenerate = (bytes = 32) => {
  const arr = new Uint8Array(bytes);
  crypto.getRandomValues(arr);
  return btoa(String.fromCharCode(...arr));
};

// XOR message bytes against a base64-encoded pad.
// Returns a new Uint8Array of the same length.
const otpApply = (messageBytes, padBase64) => {
  const padBytes = Uint8Array.from(atob(padBase64), c => c.charCodeAt(0));
  if (padBytes.length < messageBytes.length)
    throw new Error(
      `OTP pad too short: need ${messageBytes.length} bytes, got ${padBytes.length}`,
    );
  return messageBytes.map((byte, i) => byte ^ padBytes[i]);
};

// ─────────────────────────────────────────────
// File I/O helpers
// ─────────────────────────────────────────────

const readText = filePath => {
  return fs.readFileSync(filePath, "utf8").trimEnd();
};

const writeText = (filePath, content) => {
  fs.writeFileSync(filePath, content, "utf8");
};

// Best-effort pad destruction: overwrite with zeros, then delete.
// NOTE: best-effort only — does not guarantee low-level disk erasure.
// For stronger guarantees, use Rust + zeroize or shred(1).
const destroyPad = filePath => {
  const len = fs.statSync(filePath).size;
  fs.writeFileSync(filePath, "\0".repeat(len), "utf8");
  fs.unlinkSync(filePath);
};

// ─────────────────────────────────────────────
// Encoding scheme
//
// Each alpha carrier position has three states:
//   Latin    → carrier is "off" (no bit)
//   Cyrillic → bit = 0
//   Greek    → bit = 1
//
// Latin is the neutral/unflipped state. Only Cyr/Ell carry bits.
// Remaining carriers after payload stay Latin — decoder stops at
// the first Latin carrier it encounters.
//
// OTP layer: message bytes are XORed with pad before embedding.
// Without the pad, extracted bits are indistinguishable from noise.
// ─────────────────────────────────────────────

// Encode message into cover text using OTP encryption.
// All arguments are file paths.
// Writes encoded output to <coverFile>.out
const encode = (coverFile, messageFile, padFile) => {
  const plaintext = readText(coverFile);
  const message = readText(messageFile);
  const pad = readText(padFile);

  const messageBytes = Uint8Array.from(
    message.split("").map(c => c.charCodeAt(0)),
  );
  const encryptedBytes = otpApply(messageBytes, pad);
  const encryptedStr = Array.from(encryptedBytes)
    .map(b => String.fromCharCode(b))
    .join("");
  const bits = messageToBits(encryptedStr);

  const alphaLookup = buildLookupTableFrom(dictionary.alpha);
  let bitIndex = 0;
  let result = "";

  for (const char of plaintext) {
    const info = alphaLookup.get(char);

    if (!info) {
      result += char;
      continue;
    }

    if (bitIndex >= bits.length) {
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

  const outPath = coverFile + ".out";
  writeText(outPath, result);
  console.log(`✓ Encoded → ${outPath}`);
  return outPath;
};

// Decode a steganographic file back to the hidden message.
// Writes plaintext output to <encodedFile>.decoded
// pad is consumed (destroyed) after successful decode.
const decode = (encodedFile, padFile) => {
  const encoded = readText(encodedFile);
  const pad = readText(padFile);

  const alphaLookup = buildLookupTableFrom(dictionary.alpha);
  const bits = [];

  for (const char of encoded) {
    const info = alphaLookup.get(char);
    if (!info) continue;
    if (info.setName === "lat") break;
    bits.push(info.setName === "cyr" ? 0 : 1);
  }

  const encryptedStr = bitsToMessage(bits);
  const encryptedBytes = Uint8Array.from(
    encryptedStr.split("").map(c => c.charCodeAt(0)),
  );
  const decryptedBytes = otpApply(encryptedBytes, pad);
  const message = Array.from(decryptedBytes)
    .map(b => String.fromCharCode(b))
    .join("");

  const outPath = encodedFile + ".decoded";
  writeText(outPath, message);

  // Consume the pad — best-effort destruction
  destroyPad(padFile);
  console.log(`✓ Decoded → ${outPath}`);
  console.log(`✓ Pad destroyed: ${padFile}`);

  return message;
};

module.exports = {
  buildLookupTableFrom,
  messageToBits,
  bitsToMessage,
  otpGenerate,
  otpApply,
  readText,
  writeText,
  destroyPad,
  encode,
  decode,
}
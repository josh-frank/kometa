// ─────────────────────────────────────────────
// kometa-workspace.js
// File-system workspace for kometa encode/decode sessions.
// Supports both OTP (pad file) and password modes.
// ─────────────────────────────────────────────

const fs = require("fs");
const {
  otpGenerate,
  destroyPad,
  encode:               _encode,
  decode:               _decode,
  encodeWithPassword:   _encodeWithPassword,
  decodeWithPassword:   _decodeWithPassword,
} = require("./kometa-encode.js");

// ─────────────────────────────────────────────
// Standalone workspace functions (OTP mode)
// ─────────────────────────────────────────────

const generatePad = (padFile, messageFile = null) => {
  const messageBytes = messageFile
    ? fs.statSync(messageFile).size
    : 1024;
  const pad = otpGenerate(messageBytes);
  fs.writeFileSync(padFile, pad, "utf8");
  console.log(`✓ Pad generated → ${padFile}`);
  return padFile;
};

const encode = (coverFile, messageFile, padFile, outputFile) =>
  _encode(coverFile, messageFile, padFile, outputFile ?? coverFile + ".out");

const decode = (encodedFile, padFile, outputFile) =>
  _decode(encodedFile, padFile, outputFile ?? encodedFile + ".decoded");

const destroy = filePath => {
  destroyPad(filePath);
  console.log(`✓ Destroyed: ${filePath}`);
};

// ─────────────────────────────────────────────
// Standalone workspace functions (password mode)
// ─────────────────────────────────────────────

const encodeWithPassword = (coverFile, messageFile, password, outputFile) =>
  _encodeWithPassword(coverFile, messageFile, password, outputFile ?? coverFile + ".out");

const decodeWithPassword = (encodedFile, password, outputFile) =>
  _decodeWithPassword(encodedFile, password, outputFile ?? encodedFile + ".decoded");

// ─────────────────────────────────────────────
// KometaSession
//
// Thin stateful wrapper for multi-step workflows.
// Supports both OTP and password modes via the same interface.
//
// OTP mode:
//   new KometaSession().generatePad("pad.txt", "secret.txt")
//                      .encode("cover.txt", "secret.txt", "out.txt")
//   new KometaSession().usePad("pad.txt")
//                      .decode("out.txt", "decoded.txt")
//
// Password mode:
//   new KometaSession().usePassword("correct-horse-battery-staple")
//                      .encode("cover.txt", "secret.txt", "out.txt")
//   new KometaSession().usePassword("correct-horse-battery-staple")
//                      .decode("out.txt", "decoded.txt")
// ─────────────────────────────────────────────

class KometaSession {
  constructor() {
    this._padFile  = null;
    this._password = null;
  }

  // ── OTP mode ──────────────────────────────

  generatePad(padFile, messageFile = null) {
    generatePad(padFile, messageFile);
    this._padFile = padFile;
    return this;
  }

  usePad(padFile) {
    if (!fs.existsSync(padFile))
      throw new Error(`Pad file not found: ${padFile}`);
    this._padFile  = padFile;
    this._password = null;
    return this;
  }

  // ── Password mode ─────────────────────────

  usePassword(password) {
    if (!password || password.length === 0)
      throw new Error("Password must not be empty");
    this._password = password;
    this._padFile  = null;
    return this;
  }

  // ── Shared encode / decode ────────────────

  encode(coverFile, messageFile, outputFile) {
    if (this._password)
      return encodeWithPassword(coverFile, messageFile, this._password, outputFile);
    this._requirePad();
    return encode(coverFile, messageFile, this._padFile, outputFile);
  }

  decode(encodedFile, outputFile) {
    if (this._password)
      return decodeWithPassword(encodedFile, this._password, outputFile);
    this._requirePad();
    const result  = decode(encodedFile, this._padFile, outputFile);
    this._padFile = null; // pad consumed
    return result;
  }

  _requirePad() {
    if (!this._padFile)
      throw new Error("No pad loaded. Call generatePad(), usePad(), or usePassword() first.");
  }
}

module.exports = {
  generatePad,
  encode,
  decode,
  destroy,
  encodeWithPassword,
  decodeWithPassword,
  KometaSession,
};

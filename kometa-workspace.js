// ─────────────────────────────────────────────
// kometa-workspace.js
// File-system workspace for kometa encode/decode sessions.
//
// Wraps kometa-encode.js primitives with:
//   - explicit, caller-controlled output paths
//   - pad generation sized to a given message file
//   - a thin session object for multi-step workflows
// ─────────────────────────────────────────────

const fs   = require("fs");
const {
  otpGenerate,
  destroyPad,
  encode: _encode,
  decode: _decode,
} = require("./kometa-encode.js");

// ─────────────────────────────────────────────
// Standalone workspace functions
//
// Each function is usable independently — no session object required.
// These are the building blocks the CLI calls directly.
// ─────────────────────────────────────────────

// Generate a pad sized for a given message file and write it to padFile.
// If messageFile is omitted, generates a 1 KB pad (enough for ~990 bytes
// of plaintext after the seed region).
const generatePad = (padFile, messageFile = null) => {
  const messageBytes = messageFile
    ? fs.statSync(messageFile).size
    : 1024;
  const pad = otpGenerate(messageBytes);
  fs.writeFileSync(padFile, pad, "utf8");
  console.log(`✓ Pad generated → ${padFile}`);
  return padFile;
};

// Encode cover + message → output, using pad at padFile.
// All paths are explicit — no suffix magic.
const encode = (coverFile, messageFile, padFile, outputFile) => {
  return _encode(coverFile, messageFile, padFile, outputFile ?? coverFile + ".out");
};

// Decode encodedFile → outputFile, using pad at padFile.
// Pad is destroyed after decode. All paths are explicit.
const decode = (encodedFile, padFile, outputFile) => {
  return _decode(encodedFile, padFile, outputFile ?? encodedFile + ".decoded");
};

// Best-effort file destruction: overwrite with zeros, then unlink.
// Re-exported here so the CLI only needs to import from one place.
// NOTE: best-effort only — does not guarantee low-level disk erasure.
// For stronger guarantees use shred(1) or srm(1).
const destroy = (filePath) => {
  destroyPad(filePath);
  console.log(`✓ Destroyed: ${filePath}`);
};

// ─────────────────────────────────────────────
// KometaSession
//
// Thin stateful wrapper for multi-step workflows.
// Holds pad material in memory for the lifetime of the session so
// the caller never needs to re-read or re-write the pad between steps.
//
// Typical usage:
//
//   const session = new KometaSession();
//   session.generatePad("pad.txt", "secret.txt");
//   session.encode("cover.txt", "secret.txt", "encoded.txt");
//   // ... transmit encoded.txt ...
//   session.decode("encoded.txt", "decoded.txt");   // pad destroyed on decode
// ─────────────────────────────────────────────

class KometaSession {
  constructor() {
    this._padFile = null;
  }

  // Generate a pad and remember its path for subsequent encode/decode calls.
  generatePad(padFile, messageFile = null) {
    generatePad(padFile, messageFile);
    this._padFile = padFile;
    return this;
  }

  // Load an existing pad file into the session.
  usePad(padFile) {
    if (!fs.existsSync(padFile))
      throw new Error(`Pad file not found: ${padFile}`);
    this._padFile = padFile;
    return this;
  }

  // Encode cover + message → output using the session pad.
  encode(coverFile, messageFile, outputFile) {
    this._requirePad();
    encode(coverFile, messageFile, this._padFile, outputFile);
    return this;
  }

  // Decode encodedFile → outputFile using the session pad.
  // Pad is destroyed after decode; session pad reference is cleared.
  decode(encodedFile, outputFile) {
    this._requirePad();
    decode(encodedFile, this._padFile, outputFile);
    this._padFile = null; // pad has been consumed
    return this;
  }

  _requirePad() {
    if (!this._padFile)
      throw new Error(
        "No pad loaded. Call generatePad() or usePad() first.",
      );
  }
}

module.exports = {
  generatePad,
  encode,
  decode,
  destroy,
  KometaSession,
};

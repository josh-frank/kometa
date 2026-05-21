#!/usr/bin/env node
// ─────────────────────────────────────────────
// kometa-cli.js
// CLI entry point — argument parsing only.
// All logic lives in kometa-workspace.js.
// ─────────────────────────────────────────────

const { program } = require("commander");
const { generatePad, encode, decode, destroy } = require("./kometa-workspace.js");

program
  .name("kometa")
  .description("Homoglyph steganography with one-time pad encryption")
  .version("0.1.0");

// ── generate ──────────────────────────────────
program
  .command("generate <pad>")
  .description("Generate a cryptographically random OTP pad")
  .option("-m, --message <file>", "size pad to this message file")
  .option("-b, --bytes <n>",      "size pad to exactly N bytes", parseInt)
  .action((pad, opts) => {
    if (opts.message && opts.bytes)
      fatal("--message and --bytes are mutually exclusive");

    const messageFile = opts.message ?? null;
    const bytes       = opts.bytes   ?? null;

    if (bytes !== null) {
      // --bytes: bypass generatePad's file-sizing logic
      const { otpGenerate } = require("./kometa-encode.js");
      const fs = require("fs");
      const padData = otpGenerate(bytes);
      fs.writeFileSync(pad, padData, "utf8");
      console.log(`✓ Pad generated → ${pad}`);
    } else {
      generatePad(pad, messageFile);
    }
  });

// ── encode ────────────────────────────────────
program
  .command("encode")
  .description("Encode a hidden message into a cover text")
  .requiredOption("-c, --cover <file>",   "cover text file")
  .requiredOption("-m, --message <file>", "message file to hide")
  .requiredOption("-p, --pad <file>",     "OTP pad file")
  .requiredOption("-o, --output <file>",  "output file for encoded cover")
  .action(opts => {
    encode(opts.cover, opts.message, opts.pad, opts.output);
  });

// ── decode ────────────────────────────────────
program
  .command("decode")
  .description("Decode a hidden message from an encoded cover text")
  .requiredOption("-i, --input <file>",  "encoded cover text file")
  .requiredOption("-p, --pad <file>",    "OTP pad file (destroyed after decode)")
  .requiredOption("-o, --output <file>", "output file for recovered message")
  .action(opts => {
    decode(opts.input, opts.pad, opts.output);
  });

// ── destroy ───────────────────────────────────
program
  .command("destroy <file>")
  .description(
    "Best-effort destruction: overwrite with zeros, then unlink.\n" +
    "  Does not guarantee low-level disk erasure — see shred(1) for stronger guarantees."
  )
  .action(file => {
    destroy(file);
  });

// ─────────────────────────────────────────────

const fatal = msg => {
  console.error(`error: ${msg}`);
  process.exit(1);
};

program.parse();

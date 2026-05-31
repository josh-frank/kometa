#!/usr/bin/env node
// ─────────────────────────────────────────────
// kometa-cli.js
// CLI entry point — argument parsing only.
// All logic lives in kometa-workspace.js.
// ─────────────────────────────────────────────

const { program } = require("commander");
const {
  generatePad,
  encode,
  decode,
  destroy,
  encodeWithPassword,
  decodeWithPassword,
} = require("./kometa-workspace.js");

program
  .name("kometa")
  .description("Homoglyph steganography — OTP or password mode")
  .version("0.2.0");

// ── generate (OTP mode only) ──────────────────

program
  .command("generate <pad>")
  .description("Generate a cryptographically random OTP pad")
  .option("-m, --message <file>", "size pad to this message file")
  .option("-b, --bytes <n>",      "size pad to exactly N bytes", parseInt)
  .action((pad, opts) => {
    if (opts.message && opts.bytes) fatal("--message and --bytes are mutually exclusive");
    if (opts.bytes !== undefined) {
      const { otpGenerate } = require("./kometa-encode.js");
      require("fs").writeFileSync(pad, otpGenerate(opts.bytes), "utf8");
      console.log(`✓ Pad generated → ${pad}`);
    } else {
      generatePad(pad, opts.message ?? null);
    }
  });

// ── encode ────────────────────────────────────
//
// OTP mode:      kometa encode -c cover -m message -p pad -o out
// Password mode: kometa encode -c cover -m message --password "..." -o out

program
  .command("encode")
  .description("Encode a hidden message into a cover text")
  .requiredOption("-c, --cover <file>",   "cover text file")
  .requiredOption("-m, --message <file>", "message file to hide")
  .option(        "-p, --pad <file>",     "OTP pad file (OTP mode)")
  .option(        "--password <secret>",  "passphrase (password mode)")
  .requiredOption("-o, --output <file>",  "output file for encoded cover")
  .action(opts => {
    if (opts.pad && opts.password) fatal("--pad and --password are mutually exclusive");
    if (!opts.pad && !opts.password) fatal("one of --pad or --password is required");

    if (opts.password)
      encodeWithPassword(opts.cover, opts.message, opts.password, opts.output);
    else
      encode(opts.cover, opts.message, opts.pad, opts.output);
  });

// ── decode ────────────────────────────────────
//
// OTP mode:      kometa decode -i encoded -p pad -o out
// Password mode: kometa decode -i encoded --password "..." -o out

program
  .command("decode")
  .description("Decode a hidden message from an encoded cover text")
  .requiredOption("-i, --input <file>",   "encoded cover text file")
  .option(        "-p, --pad <file>",     "OTP pad file (destroyed after decode)")
  .option(        "--password <secret>",  "passphrase (password mode)")
  .requiredOption("-o, --output <file>",  "output file for recovered message")
  .action(opts => {
    if (opts.pad && opts.password) fatal("--pad and --password are mutually exclusive");
    if (!opts.pad && !opts.password) fatal("one of --pad or --password is required");

    if (opts.password)
      decodeWithPassword(opts.input, opts.password, opts.output);
    else
      decode(opts.input, opts.pad, opts.output);
  });

// ── destroy ───────────────────────────────────

program
  .command("destroy <file>")
  .description(
    "Best-effort destruction: overwrite with zeros, then unlink.\n" +
    "  Does not guarantee low-level disk erasure — see shred(1) for stronger guarantees."
  )
  .action(file => destroy(file));

// ─────────────────────────────────────────────

const fatal = msg => {
  console.error(`error: ${msg}`);
  process.exit(1);
};

program.parse();

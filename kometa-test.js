// ─────────────────────────────────────────────
// kometa-test.js
// Roundtrip test — password mode.
// ─────────────────────────────────────────────

"use strict";
const fs     = require("fs");
const crypto = require("crypto");

// Inline encode/decode by requiring kometa.js as a library.
// We do this by temporarily hijacking process.argv so the CLI block
// doesn't fire, then pulling the functions out via module scope.
// Simpler: just duplicate the two public calls via child_process.
const { execFileSync } = require("child_process");

const KOMETA  = `${__dirname}/kometa.js`;
const run     = args => execFileSync("node", [KOMETA, ...args], { stdio: ["ignore","ignore","pipe"] });

// ── fixtures ──────────────────────────────────

const cover = `Scientology is perhaps a religion, is probably a philosophy, is definitely a business, is potentially a political force, and is also a form of therapy, or as they call it now, pastoral counseling. Most people do not realize this, since the Scientologists draw attention only to the idea that they are a religion and a philosophy. Thus, they have been able to keep the public in the dark about what is happening -- and they have also been largely able to avoid public outcry. Scientologists have devised a series of methods that they believe can and will save this "enturbulated" world. Some of their practices -- those that have been widely criticized, such as disconnecting, suppressives, investigations -- are based on their belief that anyone who questions, criticizes or tries to stop Scientology from utilizing these methods is harming not only themselves but the world. Scientologists try to keep their methods of pastoral counseling a very strict secret. While this shields them from criticism, it also makes doctors doubtful as to its efficacy. "Suppose Newton had founded a Church of Newtonian physics and refused to show his formula to anyone who doubted the tenets of Newtonian physics?" wrote William Burroughs. (In an earlier stage, when Burroughs was apparently more enchanted with Scientology, he wrote "There is nothing secret about Scientology, no talk of initiates, secret doctrines or hidden knowledge." But only someone who takes advanced Scientology courses or "grades" can find out what Scientology methods are. If any Scientologist divulges these secrets after he takes the courses, he is subject to expulsion. But even though he doesn't know what the courses are until he takes them, he must agree that they are correct in advance and cannot question them. "It's like a physicist saying 'you can't see my formulae unless you first agree that they are correct sight unseen,'" said Burroughs. Some of these secret sessions are done with the E-meter, although other sessions consist of a series of exercises to "raise the preclear's ability." When working with the meter, the auditor may first show the preclear the auditing room and ask if there is anything about it that upsets him. The preclear may also be told to remove his watch and wedding ring to prevent interference by outside metals. Then the auditor and preclear face each other in chairs, with the E-meter on a table between them. The auditor watches the needle of the meter, and if it reacts in a manner that he believes indicates that an engram is present, the auditor repeats the question until the needle "floats," which presumably means that the engram has been "erased." The preclear, who cannot see the dials, does not have to accept the word of the auditor to determine whether an engram is really gone. Hubbard stated that when a patient succeeds in erasing an engram, he will feel a sense of wild elation -- which explains, perhaps, why when one Scientologist got rid of an engram, he laughed for two days without stopping.`;

const secret   = "stop spying on me";
const password = "correct-horse-battery-staple";

const COVER   = "/tmp/kometa_cover.txt";
const MESSAGE = "/tmp/kometa_message.txt";
const ENCODED = "/tmp/kometa_encoded.txt";
const DECODED = "/tmp/kometa_decoded.txt";

fs.writeFileSync(COVER,   cover,   "utf8");
fs.writeFileSync(MESSAGE, secret,  "utf8");

// ── helpers ───────────────────────────────────

let passed = 0, failed = 0;
const assert = (label, ok, detail = "") => {
  if (ok) { console.log(`  ✓ ${label}`); passed++; }
  else     { console.log(`  ✗ ${label}${detail ? ": " + detail : ""}`); failed++; }
};

// ── tests ─────────────────────────────────────

console.log("\nkometa roundtrip tests\n");

// 1. Encode produces a file
console.log("1. encode");
run(["encode", COVER, MESSAGE, password, ENCODED]);
assert("output file exists",    fs.existsSync(ENCODED));
assert("output byte size >= cover",  fs.statSync(ENCODED).size >= fs.statSync(COVER).size);

// 2. Encoded file looks identical to cover at a glance
console.log("\n2. cover integrity");
const original = fs.readFileSync(COVER,   "utf8");
const encoded  = fs.readFileSync(ENCODED, "utf8");
assert("same length",           original.length === encoded.length);
assert("whitespace preserved",  original.replace(/\S/g, "") === encoded.replace(/\S/g, ""));

// 3. Decode recovers the message
console.log("\n3. decode — correct password");
run(["decode", ENCODED, password, DECODED]);
const recovered = fs.readFileSync(DECODED, "utf8");
assert("message matches", recovered === secret, JSON.stringify(recovered));

// 4. Wrong password produces noise, not the message
console.log("\n4. decode — wrong password");
const WRONG = "/tmp/kometa_wrong.txt";
run(["decode", ENCODED, "wrong-password", WRONG]);
const noise = fs.readFileSync(WRONG);
assert("not the original message", noise.toString() !== secret);
assert("contains non-printable bytes",
  [...noise].some(b => b < 32 || b > 126)
);

// 5. Deterministic: same password + same cover → same encoding
console.log("\n5. determinism");
const ENCODED2 = "/tmp/kometa_encoded2.txt";
run(["encode", COVER, MESSAGE, password, ENCODED2]);
const enc2 = fs.readFileSync(ENCODED2, "utf8");
assert("identical output", encoded === enc2);

// 6. Different password → different encoding
console.log("\n6. password sensitivity");
const ENCODED3 = "/tmp/kometa_encoded3.txt";
run(["encode", COVER, MESSAGE, "different-password", ENCODED3]);
const enc3 = fs.readFileSync(ENCODED3, "utf8");
assert("different output", encoded !== enc3);

// 7. Cover is unchanged after round-trip normalisation
console.log("\n7. cover survives round-trip");
const DECODED2 = "/tmp/kometa_decoded2.txt";
run(["decode", ENCODED3, "different-password", DECODED2]);
const rt = fs.readFileSync(DECODED2, "utf8");
assert("different-password round-trip", rt === secret, JSON.stringify(rt));

// ── summary ───────────────────────────────────

console.log(`\n${passed + failed} tests: ${passed} passed, ${failed} failed\n`);
if (failed > 0) process.exit(1);

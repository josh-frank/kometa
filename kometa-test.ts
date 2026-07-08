// -----------------------------------------------
// kometa-test.ts
// Roundtrip tests — password mode.
//
// Port notes vs. kometa-test.py:
//   - The Python version shells out to kometa.py as a CLI and reads/writes
//     temp files. kometa.ts is a library, not a CLI, so there's nothing to
//     subprocess and nothing to write to disk -- these tests call
//     encode/decode functions directly, in-process.
//   - Test 8 ("literal string message (no file)") doesn't map over: that
//     distinction existed because kometa.py's _read_or_literal() decided
//     whether an arg was a file path or literal text. The library only
//     ever takes a Uint8Array or string directly, so that branch doesn't
//     exist here. Replaced with a byte-level API test instead (encode()/
//     decodeText() taking/returning Uint8Array directly, vs. the string
//     convenience wrappers encodeText()/decodeToString() used elsewhere).
//   - Test 4 ("wrong password") differs in expected behavior. kometa.py
//     has a known bug where large enough messages overflow the HKDF
//     counter byte and crash instead of producing noise. kometa.ts wraps
//     instead of throwing (documented in kometa.ts's deriveKeys() comment),
//     so a wrong password is expected to produce silent garbage here, not
//     an exception. The test still tolerates a thrown error (e.g. if the
//     garbage decode result happens to be invalid enough to reject at some
//     layer) but no longer treats it as the expected path.
// -----------------------------------------------

import { encode, decodeText, encodeText, decodeToString } from "./kometa.ts";

// ── fixtures ──────────────────────────────────

const cover = `Scientology is perhaps a religion, is probably a philosophy, is definitely a business, is potentially a political force, and is also a form of therapy, or as they call it now, pastoral counseling. Most people do not realize this, since the Scientologists draw attention only to the idea that they are a religion and a philosophy. Thus, they have been able to keep the public in the dark about what is happening -- and they have also been largely able to avoid public outcry. Scientologists have devised a series of methods that they believe can and will save this "enturbulated" world. Some of their practices -- those that have been widely criticized, such as disconnecting, suppressives, investigations -- are based on their belief that anyone who questions, criticizes or tries to stop Scientology from utilizing these methods is harming not only themselves but the world. Scientologists try to keep their methods of pastoral counseling a very strict secret. While this shields them from criticism, it also makes doctors doubtful as to its efficacy. "Suppose Newton had founded a Church of Newtonian physics and refused to show his formula to anyone who doubted the tenets of Newtonian physics?" wrote William Burroughs. (In an earlier stage, when Burroughs was apparently more enchanted with Scientology, he wrote "There is nothing secret about Scientology, no talk of initiates, secret doctrines or hidden knowledge." But only someone who takes advanced Scientology courses or "grades" can find out what Scientology methods are. If any Scientologist divulges these secrets after he takes the courses, he is subject to expulsion. But even though he doesn't know what the courses are until he takes them, he must agree that they are correct in advance and cannot question them. "It's like a physicist saying 'you can't see my formulae unless you first agree that they are correct sight unseen,'" said Burroughs. Some of these secret sessions are done with the E-meter, although other sessions consist of a series of exercises to "raise the preclear's ability." When working with the meter, the auditor may first show the preclear the auditing room and ask if there is anything about it that upsets him. The preclear may also be told to remove his watch and wedding ring to prevent interference by outside metals. Then the auditor and preclear face each other in chairs, with the E-meter on a table between them. The auditor watches the needle of the meter, and if it reacts in a manner that he believes indicates that an engram is present, the auditor repeats the question until the needle "floats," which presumably means that the engram has been "erased." The preclear, who cannot see the dials, does not have to accept the word of the auditor to determine whether an engram is really gone. Hubbard stated that when a patient succeeds in erasing an engram, he will feel a sense of wild elation -- which explains, perhaps, why when one Scientologist got rid of an engram, he laughed for two days without stopping.`;

const secret = "stop spying on me";
const password = "correct-horse-battery-staple";

// ── helpers ───────────────────────────────────

let passed = 0;
let failed = 0;

function assert_(label: string, ok: boolean, detail = ""): void {
  if (ok) {
    console.log(`  \u2713 ${label}`);
    passed += 1;
  } else {
    console.log(`  \u2717 ${label}${detail ? ": " + detail : ""}`);
    failed += 1;
  }
}

function whitespaceOnly(s: string): string {
  return Array.from(s).filter((c) => /\s/.test(c)).join("");
}

// ── tests ─────────────────────────────────────

async function main(): Promise<void> {
  console.log("\nkometa roundtrip tests\n");

  // 1. Encode produces output
  console.log("1. encode");
  const encoded = await encodeText(cover, secret, password);
  assert_("output produced", typeof encoded === "string" && encoded.length > 0);
  assert_(
    "output char length >= cover char length",
    Array.from(encoded).length >= Array.from(cover).length
  );

  // 2. Cover integrity
  console.log("\n2. cover integrity");
  assert_(
    "same char length",
    Array.from(cover).length === Array.from(encoded).length
  );
  assert_(
    "whitespace preserved",
    whitespaceOnly(cover) === whitespaceOnly(encoded)
  );

  // 3. Correct password recovers message
  console.log("\n3. decode — correct password");
  const recovered = await decodeToString(encoded, password);
  assert_("message matches", recovered === secret, JSON.stringify(recovered));

  // 4. Wrong password → noise (not the overflow-crash bug from kometa.py; see header note)
  console.log("\n4. decode — wrong password");
  try {
    const noiseBytes = await decodeText(encoded, "wrong-password");
    const noise = new TextDecoder("utf-8", { fatal: false }).decode(noiseBytes);
    assert_("not the original message", noise !== secret);
  } catch (e) {
    assert_(
      "wrong password threw instead of producing noise (unexpected for this port)",
      false,
      String(e)
    );
  }

  // 5. Non-deterministic (nonce) but both decode correctly
  console.log("\n5. nonce — same inputs, different outputs, both decode");
  const encoded2 = await encodeText(cover, secret, password);
  assert_("different ciphertext", encoded !== encoded2);
  const rtB = await decodeToString(encoded2, password);
  assert_("second encode decodes correctly", rtB === secret, JSON.stringify(rtB));

  // 6. Password sensitivity
  console.log("\n6. password sensitivity");
  const encoded3 = await encodeText(cover, secret, "different-password");
  assert_("different output", encoded !== encoded3);

  // 7. Round-trip with different password
  console.log("\n7. cover survives round-trip");
  const rt = await decodeToString(encoded3, "different-password");
  assert_("different-password round-trip", rt === secret, JSON.stringify(rt));

  // 8. Byte-level API (encode()/decodeText() directly) — replaces the
  // "literal string vs. file" distinction that doesn't apply to a library.
  console.log("\n8. byte-level message (Uint8Array API)");
  const msgBytes = new TextEncoder().encode(secret);
  const encoded4 = await encode(cover, msgBytes, password);
  const decoded4 = await decodeText(encoded4, password);
  const rt2 = new TextDecoder().decode(decoded4);
  assert_("byte-level round-trip", rt2 === secret, JSON.stringify(rt2));

  // ── summary ───────────────────────────────────

  console.log(`\n${passed + failed} tests: ${passed} passed, ${failed} failed\n`);
  if (failed) process.exit(1);
}

main().catch((e) => {
  console.error(e);
  process.exit(1);
});
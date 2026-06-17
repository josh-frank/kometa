#!/usr/bin/env python3
# ─────────────────────────────────────────────
# kometa-test.py
# Roundtrip tests — password mode.
# ─────────────────────────────────────────────

import subprocess, os, sys

KOMETA  = os.path.join(os.path.dirname(__file__), "kometa.py")
def run(*args): subprocess.run(["python3", KOMETA, *args], check=True, stderr=subprocess.PIPE)

# ── fixtures ──────────────────────────────────

cover = """Scientology is perhaps a religion, is probably a philosophy, is definitely a business, is potentially a political force, and is also a form of therapy, or as they call it now, pastoral counseling. Most people do not realize this, since the Scientologists draw attention only to the idea that they are a religion and a philosophy. Thus, they have been able to keep the public in the dark about what is happening -- and they have also been largely able to avoid public outcry. Scientologists have devised a series of methods that they believe can and will save this "enturbulated" world. Some of their practices -- those that have been widely criticized, such as disconnecting, suppressives, investigations -- are based on their belief that anyone who questions, criticizes or tries to stop Scientology from utilizing these methods is harming not only themselves but the world. Scientologists try to keep their methods of pastoral counseling a very strict secret. While this shields them from criticism, it also makes doctors doubtful as to its efficacy. "Suppose Newton had founded a Church of Newtonian physics and refused to show his formula to anyone who doubted the tenets of Newtonian physics?" wrote William Burroughs. (In an earlier stage, when Burroughs was apparently more enchanted with Scientology, he wrote "There is nothing secret about Scientology, no talk of initiates, secret doctrines or hidden knowledge." But only someone who takes advanced Scientology courses or "grades" can find out what Scientology methods are. If any Scientologist divulges these secrets after he takes the courses, he is subject to expulsion. But even though he doesn't know what the courses are until he takes them, he must agree that they are correct in advance and cannot question them. "It's like a physicist saying 'you can't see my formulae unless you first agree that they are correct sight unseen,'" said Burroughs. Some of these secret sessions are done with the E-meter, although other sessions consist of a series of exercises to "raise the preclear's ability." When working with the meter, the auditor may first show the preclear the auditing room and ask if there is anything about it that upsets him. The preclear may also be told to remove his watch and wedding ring to prevent interference by outside metals. Then the auditor and preclear face each other in chairs, with the E-meter on a table between them. The auditor watches the needle of the meter, and if it reacts in a manner that he believes indicates that an engram is present, the auditor repeats the question until the needle "floats," which presumably means that the engram has been "erased." The preclear, who cannot see the dials, does not have to accept the word of the auditor to determine whether an engram is really gone. Hubbard stated that when a patient succeeds in erasing an engram, he will feel a sense of wild elation -- which explains, perhaps, why when one Scientologist got rid of an engram, he laughed for two days without stopping."""

secret   = "stop spying on me"
password = "correct-horse-battery-staple"

COVER   = "/tmp/kometa_cover.txt"
MESSAGE = "/tmp/kometa_message.txt"
ENCODED = "/tmp/kometa_encoded.txt"
DECODED = "/tmp/kometa_decoded.txt"

open(COVER,   "w").write(cover)
open(MESSAGE, "w").write(secret)

# ── helpers ───────────────────────────────────

passed = failed = 0
def assert_(label, ok, detail=""):
    global passed, failed
    if ok:  print(f"  ✓ {label}"); passed += 1
    else:   print(f"  ✗ {label}{': ' + detail if detail else ''}"); failed += 1

# ── tests ─────────────────────────────────────

print("\nkometa roundtrip tests\n")

# 1. Encode produces a file
print("1. encode")
run("encode", COVER, MESSAGE, password, ENCODED)
assert_("output file exists",       os.path.exists(ENCODED))
assert_("output byte size >= cover", os.path.getsize(ENCODED) >= os.path.getsize(COVER))

# 2. Cover integrity
print("\n2. cover integrity")
original = open(COVER,   encoding="utf-8").read()
encoded  = open(ENCODED, encoding="utf-8").read()
assert_("same char length",      len(original) == len(encoded))
assert_("whitespace preserved",
    "".join(c for c in original if c.isspace()) ==
    "".join(c for c in encoded  if c.isspace()))

# 3. Correct password recovers message
print("\n3. decode — correct password")
run("decode", ENCODED, password, DECODED)
recovered = open(DECODED, "rb").read().decode()
assert_("message matches", recovered == secret, repr(recovered))

# 4. Wrong password → noise
print("\n4. decode — wrong password")
WRONG = "/tmp/kometa_wrong.txt"
run("decode", ENCODED, "wrong-password", WRONG)
noise = open(WRONG, "rb").read()
assert_("not the original message", noise.decode(errors="replace") != secret)
assert_("different content or length", noise != secret.encode())

# 5. Non-deterministic (nonce) but both decode correctly
print("\n5. nonce — same inputs, different outputs, both decode")
ENCODED2 = "/tmp/kometa_encoded2.txt"
DECODED2b = "/tmp/kometa_decoded2b.txt"
run("encode", COVER, MESSAGE, password, ENCODED2)
assert_("different ciphertext",   open(ENCODED).read() != open(ENCODED2).read())
run("decode", ENCODED2, password, DECODED2b)
rt_b = open(DECODED2b, "rb").read().decode()
assert_("second encode decodes correctly", rt_b == secret, repr(rt_b))

# 6. Password sensitivity
print("\n6. password sensitivity")
ENCODED3 = "/tmp/kometa_encoded3.txt"
run("encode", COVER, MESSAGE, "different-password", ENCODED3)
assert_("different output", open(ENCODED).read() != open(ENCODED3).read())

# 7. Round-trip with different password
print("\n7. cover survives round-trip")
DECODED2 = "/tmp/kometa_decoded2.txt"
run("decode", ENCODED3, "different-password", DECODED2)
rt = open(DECODED2, "rb").read().decode()
assert_("different-password round-trip", rt == secret, repr(rt))

# 8. Literal string message (no file)
print("\n8. literal message string")
ENCODED4 = "/tmp/kometa_encoded4.txt"
DECODED4 = "/tmp/kometa_decoded4.txt"
run("encode", COVER, "stop spying on me", password, ENCODED4)
run("decode", ENCODED4, password, DECODED4)
rt2 = open(DECODED4, "rb").read().decode()
assert_("literal string round-trip", rt2 == secret, repr(rt2))

# ── summary ───────────────────────────────────

print(f"\n{passed + failed} tests: {passed} passed, {failed} failed\n")
if failed: sys.exit(1)
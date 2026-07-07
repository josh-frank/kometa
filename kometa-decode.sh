#!/usr/bin/env bash
# ─────────────────────────────────────────────
# kometa-decode.sh
# Fetch kometa.py + a covertext URL, decode entirely in memory,
# print the recovered message to stdout. No files are written to disk.
#
# Usage:
#   ./kometa-decode.sh https://example.com/path/to/covertext.txt
#
# Password: prompted securely via getpass (never passed as argv),
# unless KOMETA_PASSWORD is set in the environment (same behavior
# as the original kometa.py CLI).
# ─────────────────────────────────────────────
set -euo pipefail

KOMETA_SRC_URL="https://raw.githubusercontent.com/josh-frank/kometa/refs/heads/master/kometa.py"

if [[ $# -ne 1 ]]; then
    echo "usage: $0 <covertext-url>" >&2
    exit 1
fi

COVER_URL="$1"

python3 - "$COVER_URL" "$KOMETA_SRC_URL" <<'PYEOF'
import sys
import urllib.request

cover_url, src_url = sys.argv[1], sys.argv[2]

# Fetch kometa.py source and exec it into an isolated namespace.
# __name__ is deliberately NOT "__main__", so the CLI block at the
# bottom of kometa.py never runs and never touches sys.argv/disk.
src = urllib.request.urlopen(src_url).read().decode("utf-8")
ns = {"__name__": "kometa_lib"}
exec(compile(src, "kometa.py", "exec"), ns)

# Fetch the covertext itself. Held only in a local variable, never written out.
cover = urllib.request.urlopen(cover_url).read().decode("utf-8")

# Password: env var if set (e.g. for scripting/testing), else a secure prompt.
# This reuses kometa's own _get_password(), so behavior matches the CLI exactly.
password = ns["_get_password"]()

# decode_text() is already pure in-memory in kometa.py — no disk I/O.
result = ns["decode_text"](cover, password)

try:
    sys.stdout.write(result.decode("utf-8"))
except UnicodeDecodeError:
    sys.stdout.buffer.write(result)
PYEOF

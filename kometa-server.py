#!/usr/bin/env python3
# kometa-server.py
# Localhost decode interface. No dependencies beyond the standard library.
# Usage: python3 kometa-server.py [port]

import sys, os, json
sys.path.insert(0, os.path.dirname(__file__))
from http.server import HTTPServer, BaseHTTPRequestHandler
from kometa import decode_text

PORT = int(sys.argv[1]) if len(sys.argv) > 1 else 8000

HTML = """<!doctype html>
<html>
<head><meta charset="utf-8"></head>
<style>
  body { display: flex; flex-flow: column nowrap; gap: 8px; padding: 16px; font-family: sans-serif; }
  section { display: flex; align-items: center; gap: 12px; }
  textarea { flex: 1; min-height: 300px; font-family: monospace; }
  #download { display: none; }
</style>
<body>
  <section>
    <input id="file" type="file" />
    <label for="password">Password:&nbsp;</label>
    <input id="password" type="password" />
    <button id="eye" onmousedown="showpw(true)" onmouseup="showpw(false)" onmouseleave="showpw(false)">👁️</button>
    <button onclick="run()">Decode</button>
    <span id="status"></span>
  </section>
  <textarea id="out" readonly placeholder="Decoded output appears here..."></textarea>
  <button id="download" onclick="dl()">Download</button>
<script>
function showpw(show) {
  document.getElementById('password').type = show ? 'text' : 'password';
}
async function run() {
  const file = document.getElementById('file').files[0];
  const password = document.getElementById('password').value;
  const status = document.getElementById('status');
  if (!file || !password) { status.textContent = 'Need file and password.'; return; }
  status.textContent = '⏳ Decoding…';
  const body = new FormData();
  body.append('file', file);
  body.append('password', password);
  const res = await fetch('/decode', { method: 'POST', body });
  const j = await res.json();
  if (j.error) { status.textContent = '✗ ' + j.error; console.error('kometa: error —', j.error); return; }
  status.textContent = '✓ Done';
  document.getElementById('out').value = j.result;
  document.getElementById('download').style.display = 'inline';
}
function dl() {
  const text = document.getElementById('out').value;
  const a = document.createElement('a');
  a.type = 'hidden';
  a.href = URL.createObjectURL(new Blob([text], { type: 'text/plain' }));
  a.download = 'decoded.txt';
  document.body.appendChild(a);
  a.click();
  document.body.removeChild(a);
}
</script>
</body>
</html>"""


def _parse_multipart(headers, rfile):
    """Parse multipart/form-data without the deprecated cgi module."""
    content_type = headers["Content-Type"]
    # Extract boundary from e.g. "multipart/form-data; boundary=----XYZ"
    boundary = None
    for part in content_type.split(";"):
        part = part.strip()
        if part.startswith("boundary="):
            boundary = part[len("boundary="):].strip().encode()
            break
    if not boundary:
        raise ValueError("No boundary in Content-Type")

    body = rfile.read(int(headers["Content-Length"]))
    fields = {}
    for chunk in body.split(b"--" + boundary):
        if b"Content-Disposition" not in chunk:
            continue
        header_block, sep, value = chunk.partition(b"\r\n\r\n")
        if not sep:
            continue
        value = value.rstrip(b"\r\n--")
        for line in header_block.decode(errors="replace").splitlines():
            if "Content-Disposition" not in line:
                continue
            for segment in line.split(";"):
                segment = segment.strip()
                if segment.startswith("name="):
                    name = segment[5:].strip('"')
                    fields[name] = value
    return fields


class H(BaseHTTPRequestHandler):
    def do_GET(self):
        self.send_response(200)
        self.send_header("Content-Type", "text/html")
        self.end_headers()
        self.wfile.write(HTML.encode())

    def do_POST(self):
        fields    = _parse_multipart(self.headers, self.rfile)
        file_data = fields["file"]
        password  = fields["password"].decode()

        try:
            encoded = file_data.decode()
            print("⏳ Decoding…", flush=True)
            result  = decode_text(encoded, password).decode(errors="replace")
            print("✓ Done", flush=True)
            payload = json.dumps({"result": result})
        except Exception as e:
            print(f"✗ Error: {e}", flush=True)
            payload = json.dumps({"error": str(e)})

        data = payload.encode()
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", len(data))
        self.end_headers()
        self.wfile.write(data)

    def log_message(self, fmt, *args):
        pass  # silence request logs

if __name__ == "__main__":
    print(f"kometa decode server → http://127.0.0.1:{PORT}")
    HTTPServer(("127.0.0.1", PORT), H).serve_forever()
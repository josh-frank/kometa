#!/usr/bin/env python3
# kometa-server.py
# Localhost decode interface. No dependencies beyond the standard library.
# Usage: python3 kometa-server.py [port]

import sys, os, cgi, tempfile, json
sys.path.insert(0, os.path.dirname(__file__))
from http.server import HTTPServer, BaseHTTPRequestHandler
from kometa import decode as kometa_decode

PORT = int(sys.argv[1]) if len(sys.argv) > 1 else 8000

HTML = """<!doctype html>
<html>
<meta charset="utf-8">
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
    <button onclick="run()">Decode</button>
    <span id="status"></span>
  </section>
  <textarea id="out" readonly placeholder="Decoded output appears here..."></textarea>
  <button id="download" onclick="dl()">Download</button>
<script>
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
  if (j.error) { status.textContent = '✗ ' + j.error; return; }
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

class H(BaseHTTPRequestHandler):
    def do_GET(self):
        self.send_response(200)
        self.send_header("Content-Type", "text/html")
        self.end_headers()
        self.wfile.write(HTML.encode())

    def do_POST(self):
        ctype, pdict = cgi.parse_header(self.headers["Content-Type"])
        pdict["boundary"] = pdict["boundary"].encode()
        fields = cgi.parse_multipart(self.rfile, pdict)
        file_data = fields["file"][0]
        password  = fields["password"][0] if isinstance(fields["password"][0], str) \
                    else fields["password"][0].decode()

        with tempfile.NamedTemporaryFile(delete=False) as inf:
            inf.write(file_data if isinstance(file_data, bytes) else file_data.encode())
            in_path = inf.name
        out_path = in_path + ".out"

        try:
            kometa_decode(in_path, password, out_path)
            result = open(out_path, "rb").read().decode(errors="replace")
            payload = json.dumps({"result": result})
        except Exception as e:
            payload = json.dumps({"error": str(e)})
        finally:
            os.unlink(in_path)
            if os.path.exists(out_path): os.unlink(out_path)

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

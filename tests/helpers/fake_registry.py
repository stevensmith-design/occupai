"""Test-only loopback npm registry: answers the npm audit bulk endpoint with canned advisories and
records each request (path, whether an Authorization header was sent). Never reaches the internet."""
import gzip
import json
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer


def start(advisories=None):
    seen = []

    class H(BaseHTTPRequestHandler):
        def log_message(self, *a):
            pass

        def _record(self, body=b""):
            if self.headers.get("Content-Encoding") == "gzip":
                body = gzip.decompress(body)
            seen.append({"method": self.command, "path": self.path, "auth": self.headers.get("Authorization"),
                         "body": body.decode("utf-8", "replace")})

        def do_POST(self):
            n = int(self.headers.get("Content-Length") or 0)
            self._record(self.rfile.read(n))
            if "/advisories/bulk" in self.path:
                data = json.dumps(advisories or {}).encode()
                self.send_response(200)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(data)))
                self.end_headers()
                self.wfile.write(data)
            else:
                self.send_response(404)
                self.send_header("Content-Length", "0")
                self.end_headers()

        def do_GET(self):
            self._record()
            self.send_response(404)
            self.send_header("Content-Length", "0")
            self.end_headers()

    srv = ThreadingHTTPServer(("127.0.0.1", 0), H)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    return srv, f"http://127.0.0.1:{srv.server_address[1]}/", seen

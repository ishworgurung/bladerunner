#!/usr/bin/env python3
"""Guest-side web server for the benchmark: every GET returns a fixed-size body.

The size defaults to 512 KiB, a stand-in for an ordinary web page or API reply.
Run it inside the VM; scripts/vmbench.sh starts it and the host-side load
generator (scripts/vmtest/httpload.py) fetches from it while the flood runs.
"""

import sys
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

SIZE = int(sys.argv[2]) if len(sys.argv) > 2 else 512 * 1024
BODY = b"x" * SIZE


class Handler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.0"  # one request per connection, then close

    def do_GET(self):
        self.send_response(200)
        self.send_header("Content-Type", "application/octet-stream")
        self.send_header("Content-Length", str(len(BODY)))
        self.end_headers()
        self.wfile.write(BODY)

    def log_message(self, *args):  # keep the benchmark quiet
        pass


class Server(ThreadingHTTPServer):
    daemon_threads = True
    request_queue_size = 256


if __name__ == "__main__":
    port = int(sys.argv[1]) if len(sys.argv) > 1 else 8080
    Server(("0.0.0.0", port), Handler).serve_forever()

#!/usr/bin/env python3
"""Static backend for the proxy benchmark.

Deliberately trivial and identical for both proxies: it answers a fixed body
from memory with no disk I/O, no logging and no per-request allocation beyond
the socket. The point is to measure the proxy in front of it, so the backend
must never be the bottleneck or the variable.

Threaded rather than async because it only has to keep four proxy workers fed
from two pinned cores, and a thread pool is easier to reason about than an
event loop when you are trying to prove the backend was not the limit.
"""
import sys
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from socketserver import ThreadingMixIn

BODIES = {
    "/empty": b"",
    "/1k": bytes(1024),
    "/64k": bytes(65536),
}


class Handler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"
    # Silence: per-request logging to stderr would itself become the bottleneck.
    def log_message(self, fmt, *args):
        pass

    def _respond(self, body, send_body=True):
        self.send_response(200)
        self.send_header("Content-Type", "application/octet-stream")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        if send_body and body:
            self.wfile.write(body)

    def do_GET(self):
        self._respond(BODIES.get(self.path.rstrip("/") or "/empty", b""))

    def do_HEAD(self):
        self._respond(BODIES.get(self.path.rstrip("/") or "/empty", b""), send_body=False)


class Server(ThreadingHTTPServer):
    daemon_threads = True
    allow_reuse_address = True
    request_queue_size = 4096


if __name__ == "__main__":
    port = int(sys.argv[1]) if len(sys.argv) > 1 else 18080
    Server(("127.0.0.1", port), Handler).serve_forever()

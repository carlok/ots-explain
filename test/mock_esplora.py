#!/usr/bin/env python3
"""A tiny Esplora mock: serves vectors/explorer/<scenario>/<path> at http://HOST:PORT/<scenario>/<path>.

Used by the tests (no network needed) and by the headless-browser smoke test. Sends
`access-control-allow-origin: *` like the real servers. Unknown paths are 404.
Scenario `down` answers 503; scenario `slow` sleeps 3 s. Data under vectors/explorer/synthetic*
is SYNTHETIC (see tools/make_synthetic_explorer.py); real recordings go to vectors/explorer/recorded/.
"""
import argparse, http.server, os, threading, time

ROOT = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "vectors", "explorer")


class Handler(http.server.BaseHTTPRequestHandler):
    root = ROOT
    def do_GET(self):
        parts = self.path.split("?")[0].lstrip("/").split("/", 1)
        if parts[0] == "down": return self._send(503, b"down")
        if parts[0] == "proofs" and len(parts) == 2:  # /proofs/<vector-id> -> vectors/<id>/proof.ots (for the ?proof= test)
            vp = os.path.normpath(os.path.join(os.path.dirname(os.path.normpath(self.root)), parts[1], "proof.ots"))
            if os.path.isfile(vp) and vp.startswith(os.path.dirname(os.path.normpath(self.root)) + os.sep):
                with open(vp, "rb") as f: return self._send(200, f.read())
            return self._send(404, b"no such proof")
        if parts[0] == "slow": time.sleep(3)
        rel = parts[1] if len(parts) == 2 else ""
        base = os.path.normpath(self.root)
        p = os.path.normpath(os.path.join(base, parts[0].replace("slow", "synthetic"), rel))
        if not p.startswith(base + os.sep) or not os.path.isfile(p): return self._send(404, b"Block not found")
        with open(p, "rb") as f: self._send(200, f.read())

    def do_OPTIONS(self): self._send(204, b"")

    def _send(self, code, body):
        self.send_response(code)
        self.send_header("access-control-allow-origin", "*")
        self.send_header("access-control-allow-headers", "*")
        self.send_header("content-type", "text/plain")
        self.send_header("content-length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *a): pass


def serve(port=0, root=None):
    handler = type("H", (Handler,), {"root": root or ROOT})
    srv = http.server.ThreadingHTTPServer(("127.0.0.1", port), handler)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    return srv, srv.server_address[1]


if __name__ == "__main__":
    ap = argparse.ArgumentParser(); ap.add_argument("--port", type=int, default=8765); a = ap.parse_args()
    s, port = serve(a.port); print("mock esplora on http://127.0.0.1:%d/synthetic" % port, flush=True)
    while True: time.sleep(3600)

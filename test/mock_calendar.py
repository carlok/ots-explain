#!/usr/bin/env python3
"""A mock OpenTimestamps calendar + the synthetic chain it "confirms" into (for tests and the demo).

POST /digest            -> a pending timestamp (append nonce, sha256, pending attestation)
GET  /timestamp/<hex>   -> 404 until `ready` is set, then a REAL-LOOKING Bitcoin path built around the
                           commitment: a transaction with an OP_RETURN output, two sha256, one merkle
                           sibling, and a fake block (easy proof of work) written under <explorer_root>/<scenario>/
so that mock_esplora can serve it. Nothing here touches the network or the real chain.
"""
import hashlib, http.server, json, os, struct, threading

PENDING_TAG = bytes.fromhex("83dfe30d2ef90c8e")
BITCOIN_TAG = bytes.fromhex("0588960d73d71901")
def sha256(b): return hashlib.sha256(b).digest()
def sha256d(b): return sha256(sha256(b))
def vu(n):
    out = bytearray()
    while True:
        b = n & 0x7f; n >>= 7; out.append(b | (0x80 if n else 0))
        if not n: return bytes(out)
def vb(b): return vu(len(b)) + b
def att(tag, payload): return b"\x00" + tag + vb(payload)


def make_block(commitment, height, explorer_dir):
    """Write a fake block holding a tx that carries `commitment` (32 bytes); return the proof fragment bytes."""
    prefix = bytes.fromhex("01000000" "01") + b"\x00" * 32 + bytes.fromhex("00000000" "00" "ffffffff" "01" "0000000000000000" "22" "6a20")
    suffix = b"\x00\x00\x00\x00"
    tx = prefix + commitment + suffix
    txid = sha256d(tx)
    sibling = sha256(b"sibling-%d" % height)
    root = sha256d(txid + sibling)
    prev = sha256(b"prev-%d" % height)
    t = 1700000000 + height
    bits, target = 0x207fffff, 0x7fffff << (8 * (0x20 - 3))
    for nonce in range(1 << 20):
        hdr = struct.pack("<I", 0x20000000) + prev + root + struct.pack("<III", t, bits, nonce)
        if int.from_bytes(sha256d(hdr), "little") <= target: break
    bh = sha256d(hdr)[::-1].hex()
    def put(rel, text):
        p = os.path.join(explorer_dir, rel); os.makedirs(os.path.dirname(p), exist_ok=True)
        with open(p, "w") as f: f.write(text)
    put("block-height/%d" % height, bh)
    put("block/%s/header" % bh, hdr.hex())
    put("block/%s/txids" % bh, json.dumps([txid[::-1].hex(), sibling[::-1].hex()]))
    put("tx/%s/hex" % txid[::-1].hex(), tx.hex())
    ops = (b"\xf1" + vb(prefix) + b"\xf0" + vb(suffix) + b"\x08\x08" + b"\xf0" + vb(sibling) + b"\x08\x08")
    return ops + att(BITCOIN_TAG, vu(height))


class MockCalendar:
    def __init__(self, explorer_root=None, scenario="chain", height=800000):
        self.ready, self.hits, self.records, self.bodies = False, [], {}, []
        self.explorer_root, self.scenario, self.height = explorer_root, scenario, height
        outer = self

        class H(http.server.BaseHTTPRequestHandler):
            def log_message(self, *a): pass
            def _send(self, code, body=b""):
                self.send_response(code); self.send_header("content-length", str(len(body))); self.send_header("access-control-allow-origin", "*"); self.end_headers(); self.wfile.write(body)
            def do_POST(self):
                n = int(self.headers.get("content-length", 0)); data = self.rfile.read(n)
                if self.path == "/__ready": outer.ready = True; return self._send(200, b"ok")  # test control: the "next block" arrived
                if self.path == "/__hits": return self._send(200, json.dumps([[m, p, len(d)] for m, p, d in outer.bodies] ).encode())
                outer.hits.append(("POST", self.path)); outer.bodies.append(("POST", self.path, data))
                if self.path != "/digest" or len(data) != 32 or "opentimestamps" not in self.headers.get("Accept", ""): return self._send(400, b"bad")
                nonce = sha256(b"cal-nonce" + data)[:8]; m1 = sha256(data + nonce)
                outer.records[m1.hex()] = outer.height + int.from_bytes(m1[:2], 'big') % 1000  # a function of the commitment: same answer however often it is asked
                uri = ("http://127.0.0.1:%d" % self.server.server_address[1]).encode()
                self._send(200, b"\xf0" + vb(nonce) + b"\x08" + att(PENDING_TAG, vb(uri)))
            def do_GET(self):
                outer.hits.append(("GET", self.path))
                key = self.path.rsplit("/", 1)[-1]
                if not self.path.startswith("/timestamp/") or key not in outer.records: return self._send(404, b"Not found")
                if not outer.ready: return self._send(404, b"Pending confirmation in Bitcoin blockchain")
                d = os.path.join(outer.explorer_root, outer.scenario) if outer.explorer_root else "/nonexistent"
                self._send(200, make_block(bytes.fromhex(key), outer.records[key], d) if outer.explorer_root else att(BITCOIN_TAG, vu(outer.records[key])))
        self.server = http.server.ThreadingHTTPServer(("127.0.0.1", 0), H)
        threading.Thread(target=self.server.serve_forever, daemon=True).start()
        self.url = "http://127.0.0.1:%d" % self.server.server_address[1]

    def close(self): self.server.shutdown(); self.server.server_close()


if __name__ == "__main__":
    # python3 test/mock_calendar.py [--port N]: a calendar and the Esplora that serves the chain it "confirms" into.
    # POST /__ready makes the next GET /timestamp/... answer with the Bitcoin path. Prints one JSON line.
    import argparse, tempfile, time, sys
    sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
    import mock_esplora
    root = tempfile.mkdtemp(prefix="ots-mockchain-")
    cal = MockCalendar(root, scenario="chain")
    srv, port = mock_esplora.serve(root=root)
    print(json.dumps({"calendar": cal.url, "esplora": "http://127.0.0.1:%d/chain" % port}), flush=True)
    while True: time.sleep(3600)

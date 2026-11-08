#!/usr/bin/env python3
"""Write hand-made proofs to vectors/handcrafted/: one per parse-error code, plus odd-but-valid ones.
Each is checked by BOTH implementations (conformance) and its expected outcome is in vectors/handcrafted/index.json.
usage: make_handcrafted.py VECTORS_DIR"""
import json, os, sys
out = os.path.join(sys.argv[1], "handcrafted"); os.makedirs(out, exist_ok=True)
MAGIC = bytes.fromhex("004f70656e54696d657374616d7073000050726f6f6600bf89e2e884e89294")
BTC, PEND = bytes.fromhex("0588960d73d71901"), bytes.fromhex("83dfe30d2ef90c8e")
def vu(n):
    o = bytearray()
    while True:
        b = n & 0x7f; n >>= 7; o.append(b | (0x80 if n else 0))
        if not n: return bytes(o)
def vb(b): return vu(len(b)) + b
def att(tag, payload): return b"\x00" + tag + vb(payload)
def btc(h=1): return att(BTC, vu(h))
def proof(ts, op=b"\x08", digest=b"\x11" * 32, version=1): return MAGIC + bytes([version]) + op + digest + ts
ok = proof(btc(7))
errors = {
    "bad_magic": b"x" * 60, "unsupported_version": proof(btc(), version=2), "unknown_file_hash_op": proof(btc(), op=b"\x67"),
    "truncated": proof(btc(), digest=b"\x11" * 10)[:50], "trailing_garbage": ok + b"\x00", "unknown_op": proof(b"\xaa" + btc()),
    "repeated_op": proof(b"\xff\xf0\x01\xaa" + btc() + b"\xf0\x01\xaa" + btc()), "arg_length": proof(b"\xf0\x00" + btc()),
    "result_too_long": proof(b"\xf0" + vb(b"\xaa" * 4096) + btc()), "msg_too_long": proof(b"\xf0" + vb(b"\xaa" * 2100) + b"\xf3" + btc()),
    "varuint_too_long": proof(b"\xf0" + b"\x80" * 10 + b"\x01"), "payload_too_long": proof(att(b"\x01" * 8, b"\x00" * 8193)),
    "bad_attestation_payload": proof(att(BTC, vu(5) + b"\xff")), "bad_uri": proof(att(PEND, vb(b"http://a b"))),
    "height_too_large": proof(att(BTC, vu(2 ** 32))), "recursion_limit": proof(b"\x08" * 256 + btc()),
}
valid = {
    "depth_255": proof(b"\x08" * 255 + btc()), "reverse_and_hexlify": proof(b"\xf2\xf3" + btc(9), digest=bytes(range(32))),
    "unknown_litecoin_ethereum": proof(b"\xff" + att(b"\x01\x02\x03\x04\x05\x06\x07\x08", b"zz") + b"\xff" + att(bytes.fromhex("06869a0d73d71b45"), vu(3)) + b"\xff" + att(bytes.fromhex("30fe8087b5c7ead7"), vu(4)) + att(PEND, vb(b"https://a.example/x"))),
    "keccak_and_ripemd_ops": proof(b"\xff\x67" + btc(2) + b"\x03" + btc(3), digest=b"\x42" * 32),
    "sha1_header": proof(b"\x02" + btc(5), op=b"\x02", digest=b"\x07" * 20),
    "ripemd160_header": proof(att(PEND, vb(b"https://r.example")), op=b"\x03", digest=b"\x09" * 20),
    "branching_and_empty_arg_limit": proof(b"\xff\xf0" + vb(b"\x01") + btc(1) + b"\xf0" + vb(b"\x02" * 4064) + btc(2)),
    "bitcoin_no_transaction": proof(b"\x08" + btc(100)),
}
index = {}
for k, v in errors.items():
    open(os.path.join(out, k + ".ots"), "wb").write(v); index[k] = {"error": k}
for k, v in valid.items():
    open(os.path.join(out, k + ".ots"), "wb").write(v); index[k] = {"error": None}
json.dump(index, open(os.path.join(out, "index.json"), "w"), indent=1, sort_keys=True)
print(len(errors), "error cases,", len(valid), "valid")

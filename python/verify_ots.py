#!/usr/bin/env python3
# Copyright 2026 the ots-explain authors. Licensed under the Apache License, Version 2.0.
"""verify_ots.py - explain an OpenTimestamps (.ots) proof hop by hop. Standard library only.

    verify_ots.py FILE [PROOF.ots]      hash FILE, read the proof, replay every hop
    verify_ots.py --digest HEX PROOF    same, from a hash instead of a file
    verify_ots.py PROOF.ots             read and replay the proof only

Nothing touches the network unless you let it: the Bitcoin check (step 4) lists the exact URLs
first and asks (or needs --yes). --offline never asks. --steps prints every digest, --json prints
the canonical JSON report defined in spec/SPEC.md (identical to the browser page's).
Exit codes: 0 verdict PASS, 1 verdict FAIL, 3 something was not checked, 2 usage/input error.

This file is one of two independent implementations of spec/SPEC.md; it does not import or
use the `opentimestamps` package.
"""
import argparse
import base64
import hashlib
import io
import json
import os
import re
import struct
import sys
import urllib.error
import urllib.parse
import urllib.request

SPEC = "ots-explain-report/1"
VERSION = "0.1.0"
MAGIC = bytes.fromhex("004f70656e54696d657374616d7073000050726f6f6600bf89e2e884e89294")
HASH_OPS = {0x02: "sha1", 0x03: "ripemd160", 0x08: "sha256"}
DIGEST_LEN = {"sha1": 20, "ripemd160": 20, "sha256": 32}
UNARY = {0x08: "sha256", 0x02: "sha1", 0x03: "ripemd160", 0x67: "keccak256", 0xF2: "reverse", 0xF3: "hexlify"}
BINARY = {0xF0: "append", 0xF1: "prepend"}
ATT_KINDS = {
    bytes.fromhex("0588960d73d71901"): "bitcoin",
    bytes.fromhex("06869a0d73d71b45"): "litecoin",
    bytes.fromhex("30fe8087b5c7ead7"): "ethereum",
    bytes.fromhex("83dfe30d2ef90c8e"): "pending",
}
MAX_ARG = MAX_RESULT = MAX_MSG = 4096
MAX_HEXLIFY_MSG = 2048
MAX_PAYLOAD = 8192
MAX_URI = 1000
URI_CHARS = frozenset(b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-._/:")
RECURSION = 256
STEPS = [
    ("file_hash", "File to hash"), ("structure", "Proof structure"), ("hash_steps", "Hash steps"),
    ("ledger", "The ledger"), ("verdict", "Verdict"),
]
WHY = {
    "file_hash": "The proof is about one exact sequence of bytes; check first that your file (or digest) is the one the proof names.",
    "structure": "An .ots file is a small tree of operations ending in attestations; reading it yourself shows what it claims and where it points.",
    "hash_steps": "Every hop from your digest to the attestation is recomputed here, so nothing is taken on trust from the proof or a server.",
    "ledger": "Only the Bitcoin blockchain can tell that the final digest is really in a block; this asks explorers, and only when you ask.",
    "verdict": "The answer to one question: did this file exist before that block? Green only if every check passed and none was skipped.",
}
DEFAULT_SERVERS = [
    {"name": "blockstream.info", "base": "https://blockstream.info/api"},
    {"name": "mempool.space", "base": "https://mempool.space/api"},
]
CHECKS = ["block_hash", "header", "merkle_root", "txids", "raw_tx", "output"]


class OtsError(Exception):
    """A parse error; .code is one of the codes in spec/SPEC.md section 4."""

    def __init__(self, code):
        super().__init__(code)
        self.code = code


# ----------------------------------------------------------------------------------- hashes

def sha256(b): return hashlib.sha256(b).digest()
def sha1(b): return hashlib.sha1(b).digest()
def sha256d(b): return sha256(sha256(b))


def _rol(x, n): return ((x << n) | (x >> (32 - n))) & 0xFFFFFFFF


_RL = [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 7, 4, 13, 1, 10, 6, 15, 3, 12, 0, 9, 5, 2, 14, 11, 8,
       3, 10, 14, 4, 9, 15, 8, 1, 2, 7, 0, 6, 13, 11, 5, 12, 1, 9, 11, 10, 0, 8, 12, 4, 13, 3, 7, 15, 14, 5, 6, 2,
       4, 0, 5, 9, 7, 12, 2, 10, 14, 1, 3, 8, 11, 6, 15, 13]
_RR = [5, 14, 7, 0, 9, 2, 11, 4, 13, 6, 15, 8, 1, 10, 3, 12, 6, 11, 3, 7, 0, 13, 5, 10, 14, 15, 8, 12, 4, 9, 1, 2,
       15, 5, 1, 3, 7, 14, 6, 9, 11, 8, 12, 2, 10, 0, 4, 13, 8, 6, 4, 1, 3, 11, 15, 0, 5, 12, 2, 13, 9, 7, 10, 14,
       12, 15, 10, 4, 1, 5, 8, 7, 6, 2, 13, 14, 0, 3, 9, 11]
_SL = [11, 14, 15, 12, 5, 8, 7, 9, 11, 13, 14, 15, 6, 7, 9, 8, 7, 6, 8, 13, 11, 9, 7, 15, 7, 12, 15, 9, 11, 7, 13, 12,
       11, 13, 6, 7, 14, 9, 13, 15, 14, 8, 13, 6, 5, 12, 7, 5, 11, 12, 14, 15, 14, 15, 9, 8, 9, 14, 5, 6, 8, 6, 5, 12,
       9, 15, 5, 11, 6, 8, 13, 12, 5, 12, 13, 14, 11, 8, 5, 6]
_SR = [8, 9, 9, 11, 13, 15, 15, 5, 7, 7, 8, 11, 14, 14, 12, 6, 9, 13, 15, 7, 12, 8, 9, 11, 7, 7, 12, 7, 6, 15, 13, 11,
       9, 7, 15, 11, 8, 6, 6, 14, 12, 13, 5, 14, 13, 13, 7, 5, 15, 5, 8, 11, 14, 14, 6, 14, 6, 9, 12, 9, 12, 5, 15, 8,
       8, 5, 12, 9, 12, 5, 14, 6, 8, 13, 6, 5, 15, 13, 11, 11]
_KL = [0x00000000, 0x5A827999, 0x6ED9EBA1, 0x8F1BBCDC, 0xA953FD4E]
_KR = [0x50A28BE6, 0x5C4DD124, 0x6D703EF3, 0x7A6D76E9, 0x00000000]


def _rf(j, x, y, z):
    if j < 16: return x ^ y ^ z
    if j < 32: return (x & y) | (~x & 0xFFFFFFFF & z)
    if j < 48: return (x | (~y & 0xFFFFFFFF)) ^ z
    if j < 64: return (x & z) | (y & (~z & 0xFFFFFFFF))
    return x ^ (y | (~z & 0xFFFFFFFF))


def ripemd160_pure(data):
    """RIPEMD-160, pure Python (OpenSSL 3 builds often lack it)."""
    h = [0x67452301, 0xEFCDAB89, 0x98BADCFE, 0x10325476, 0xC3D2E1F0]
    msg = bytes(data) + b"\x80"
    msg += b"\x00" * ((56 - len(msg)) % 64) + struct.pack("<Q", len(data) * 8)
    for off in range(0, len(msg), 64):
        x = struct.unpack("<16I", msg[off:off + 64])
        a, b, c, d, e = h
        a2, b2, c2, d2, e2 = h
        for j in range(80):
            t = (_rol((a + _rf(j, b, c, d) + x[_RL[j]] + _KL[j // 16]) & 0xFFFFFFFF, _SL[j]) + e) & 0xFFFFFFFF
            a, e, d, c, b = e, d, _rol(c, 10), b, t
            t = (_rol((a2 + _rf(79 - j, b2, c2, d2) + x[_RR[j]] + _KR[j // 16]) & 0xFFFFFFFF, _SR[j]) + e2) & 0xFFFFFFFF
            a2, e2, d2, c2, b2 = e2, d2, _rol(c2, 10), b2, t
        t = (h[1] + c + d2) & 0xFFFFFFFF
        h[1] = (h[2] + d + e2) & 0xFFFFFFFF
        h[2] = (h[3] + e + a2) & 0xFFFFFFFF
        h[3] = (h[4] + a + b2) & 0xFFFFFFFF
        h[4] = (h[0] + b + c2) & 0xFFFFFFFF
        h[0] = t
    return struct.pack("<5I", *h)


def ripemd160(data):
    try:
        return hashlib.new("ripemd160", data).digest()
    except ValueError:
        return ripemd160_pure(data)


_KECCAK_RC = [
    0x0000000000000001, 0x0000000000008082, 0x800000000000808A, 0x8000000080008000, 0x000000000000808B,
    0x0000000080000001, 0x8000000080008081, 0x8000000000008009, 0x000000000000008A, 0x0000000000000088,
    0x0000000080008009, 0x000000008000000A, 0x000000008000808B, 0x800000000000008B, 0x8000000000008089,
    0x8000000000008003, 0x8000000000008002, 0x8000000000000080, 0x000000000000800A, 0x800000008000000A,
    0x8000000080008081, 0x8000000000008080, 0x0000000080000001, 0x8000000080008008]
_KECCAK_ROT = [[0, 36, 3, 41, 18], [1, 44, 10, 45, 2], [62, 6, 43, 15, 61], [28, 55, 25, 21, 56], [27, 20, 39, 8, 14]]
_M64 = 0xFFFFFFFFFFFFFFFF


def _keccak_f(s):
    for rc in _KECCAK_RC:
        c = [s[x][0] ^ s[x][1] ^ s[x][2] ^ s[x][3] ^ s[x][4] for x in range(5)]
        d = [c[(x - 1) % 5] ^ (((c[(x + 1) % 5] << 1) | (c[(x + 1) % 5] >> 63)) & _M64) for x in range(5)]
        for x in range(5):
            for y in range(5): s[x][y] ^= d[x]
        b = [[0] * 5 for _ in range(5)]
        for x in range(5):
            for y in range(5):
                r = _KECCAK_ROT[x][y]
                v = s[x][y]
                b[y][(2 * x + 3 * y) % 5] = ((v << r) | (v >> (64 - r))) & _M64 if r else v
        for x in range(5):
            for y in range(5): s[x][y] = b[x][y] ^ ((~b[(x + 1) % 5][y] & _M64) & b[(x + 2) % 5][y])
        s[0][0] ^= rc


def keccak256(data):
    """Keccak-256 with the original 0x01 padding (as used by Ethereum), not NIST SHA3-256."""
    rate = 136
    msg = bytearray(data)
    msg.append(0x01)
    msg += b"\x00" * ((-len(msg)) % rate)
    msg[-1] |= 0x80
    s = [[0] * 5 for _ in range(5)]
    for off in range(0, len(msg), rate):
        for i in range(rate // 8):
            s[i % 5][i // 5] ^= struct.unpack_from("<Q", msg, off + 8 * i)[0]
        _keccak_f(s)
    out = b"".join(struct.pack("<Q", s[i % 5][i // 5]) for i in range(4))
    return out


class Hasher:
    """Incremental hasher for files (sha256 and sha1)."""

    def __init__(self, alg):
        if alg not in ("sha256", "sha1"):
            raise ValueError("unsupported algorithm: %s" % alg)
        self._h = hashlib.new(alg)

    def update(self, chunk): self._h.update(chunk)
    def digest(self): return self._h.digest()


class FileInput:
    """What build_report needs to know about a file: its size and a way to hash it."""

    def __init__(self, size, digest_fn):
        self.size, self.digest = size, digest_fn

    @classmethod
    def from_bytes(cls, data):
        def digest(alg):
            h = Hasher(alg)
            h.update(data)
            return h.digest()
        return cls(len(data), digest)

    @classmethod
    def from_path(cls, path):
        def digest(alg):
            h = Hasher(alg)
            with open(path, "rb") as f:
                for chunk in iter(lambda: f.read(1 << 20), b""):
                    h.update(chunk)
            return h.digest()
        return cls(os.path.getsize(path), digest)


def apply_op(op, arg, msg):
    """Apply a tree operation to a message with the reference's limits."""
    if len(msg) > (MAX_HEXLIFY_MSG if op == "hexlify" else MAX_MSG):
        raise OtsError("msg_too_long")
    if op == "append": r = msg + arg
    elif op == "prepend": r = arg + msg
    elif op == "sha256": r = sha256(msg)
    elif op == "sha1": r = sha1(msg)
    elif op == "ripemd160": r = ripemd160(msg)
    elif op == "keccak256": r = keccak256(msg)
    elif op in ("reverse", "hexlify"):
        if not msg: raise OtsError("empty_message")
        r = msg[::-1] if op == "reverse" else msg.hex().encode()
    else: raise ValueError(op)
    if len(r) > MAX_RESULT: raise OtsError("result_too_long")
    return r


# ----------------------------------------------------------------------------------- parser

class Reader:
    def __init__(self, data): self.b, self.i = data, 0

    def raw(self, n):
        if n < 0 or self.i + n > len(self.b): raise OtsError("truncated")
        r = self.b[self.i:self.i + n]
        self.i += n
        return r

    def u8(self): return self.raw(1)[0]

    def varuint(self):
        v = shift = 0
        for _ in range(9):
            b = self.u8()
            v |= (b & 0x7F) << shift
            if not b & 0x80: return v
            shift += 7
        raise OtsError("varuint_too_long")

    def varbytes(self, max_len, too_long_code, min_len=0, short_code=None):
        n = self.varuint()
        if n > max_len: raise OtsError(too_long_code)
        if n < min_len: raise OtsError(short_code or too_long_code)
        return self.raw(n)

    def eof(self): return self.i == len(self.b)


def read_varuint(stream):
    """varuint from a file-like object (used by tests)."""
    data = stream.read()
    return Reader(data).varuint()


class Node:
    __slots__ = ("id", "parent", "op", "arg", "digest")

    def __init__(self, id, parent, op, arg, digest): self.id, self.parent, self.op, self.arg, self.digest = id, parent, op, arg, digest


class Att:
    __slots__ = ("index", "node", "kind", "height", "uri", "tag", "payload")

    def __init__(self, index, node, kind, height, uri, tag, payload):
        self.index, self.node, self.kind, self.height, self.uri, self.tag, self.payload = index, node, kind, height, uri, tag, payload


class Proof:
    def __init__(self, size, version, hash_op, digest):
        self.size, self.version, self.hash_op, self.digest = size, version, hash_op, digest
        self.nodes, self.atts = [], []
        self.max_depth = 0

    def path(self, node_id):
        p = []
        while node_id != -1:
            p.append(node_id)
            node_id = self.nodes[node_id].parent
        return p[::-1]


def _attestation(r, proof, node_id):
    tag = r.raw(8)
    payload = r.varbytes(MAX_PAYLOAD, "payload_too_long")
    kind = ATT_KINDS.get(tag, "unknown")
    height = uri = None
    if kind in ("bitcoin", "litecoin", "ethereum"):
        sub = Reader(payload)
        try:
            height = sub.varuint()
        except OtsError:
            raise OtsError("bad_attestation_payload")
        if height > 0xFFFFFFFF: raise OtsError("height_too_large")
        if not sub.eof(): raise OtsError("bad_attestation_payload")
    elif kind == "pending":
        sub = Reader(payload)
        try:
            n = sub.varuint()
            if n > MAX_URI: raise OtsError("bad_uri")
            raw = sub.raw(n)
        except OtsError as e:
            raise OtsError("bad_uri" if e.code == "bad_uri" else "bad_attestation_payload")
        # the reference checks the characters before it checks that the payload was consumed exactly
        if any(c not in URI_CHARS for c in raw): raise OtsError("bad_uri")
        if not sub.eof(): raise OtsError("bad_attestation_payload")
        uri = raw.decode("ascii")
    proof.atts.append(Att(len(proof.atts), node_id, kind, height, uri, tag, payload))


def _timestamp(r, proof, node_id, depth, budget):
    if budget == 0: raise OtsError("recursion_limit")
    proof.max_depth = max(proof.max_depth, depth)
    seen = set()
    msg = proof.nodes[node_id].digest

    def entry(tag):
        if tag == 0x00:
            _attestation(r, proof, node_id)
            return
        if tag in BINARY:
            op, arg = BINARY[tag], r.varbytes(MAX_ARG, "arg_length", 1)
        elif tag in UNARY:
            op, arg = UNARY[tag], None
        else:
            raise OtsError("unknown_op")
        if (op, arg) in seen: raise OtsError("repeated_op")
        seen.add((op, arg))
        result = apply_op(op, arg, msg)
        child = Node(len(proof.nodes), node_id, op, arg, result)
        proof.nodes.append(child)
        _timestamp(r, proof, child.id, depth + 1, budget - 1)

    tag = r.u8()
    while tag == 0xFF:
        entry(r.u8())
        tag = r.u8()
    entry(tag)


def parse_proof(data):
    """Parse an .ots file; raises OtsError(code). Builds nodes/attestations as spec section 5."""
    data = bytes(data)
    r = Reader(data)
    if data[:len(MAGIC)] != MAGIC: raise OtsError("bad_magic")
    r.i = len(MAGIC)
    if r.u8() != 1: raise OtsError("unsupported_version")
    op = HASH_OPS.get(r.u8())
    if op is None: raise OtsError("unknown_file_hash_op")
    digest = r.raw(DIGEST_LEN[op])
    p = Proof(len(data), 1, op, digest)
    p.nodes.append(Node(0, -1, None, None, digest))
    _timestamp(r, p, 0, 0, RECURSION)
    if not r.eof(): raise OtsError("trailing_garbage")
    return p


# ----------------------------------------------------------------------------------- bitcoin

def _compact(b, i):
    n = b[i]
    if n < 0xFD: return n, i + 1
    w = {0xFD: 2, 0xFE: 4, 0xFF: 8}[n]
    if i + 1 + w > len(b): raise ValueError("short")
    return int.from_bytes(b[i + 1:i + 1 + w], "little"), i + 1 + w


class Tx:
    def __init__(self, outputs): self.outputs = outputs


def _parse_body(b, i, n_in):
    for _ in range(n_in):
        i += 36
        n, i = _compact(b, i)
        i += n + 4
    n_out, i = _compact(b, i)
    outs = []
    for _ in range(n_out):
        i += 8
        n, i = _compact(b, i)
        if i + n > len(b): raise ValueError("short")
        outs.append(b[i:i + n])
        i += n
    return i, outs


def parse_tx(b):
    """Strict legacy (non-witness) transaction parser; None if b is not exactly one."""
    try:
        if len(b) < 10: return None
        n_in, i = _compact(b, 4)
        if n_in < 1: return None
        j, outs = _parse_body(b, i, n_in)
        if not outs or j + 4 != len(b): return None
        return Tx(outs)
    except (ValueError, IndexError):
        return None


def strip_witness(raw):
    """Return the transaction without witness data (unchanged if it has none)."""
    if len(raw) < 6 or raw[4:6] != b"\x00\x01": return raw
    try:
        n_in, i = _compact(raw, 6)
        start = i
        j, _ = _parse_body(raw, i, n_in)
        body = raw[start:j]
        for _ in range(n_in):
            items, j = _compact(raw, j)
            for _ in range(items):
                n, j = _compact(raw, j)
                j += n
        if j + 4 != len(raw): raise ValueError("length")
        return raw[:4] + _varint(n_in) + body + raw[j:j + 4]
    except (ValueError, IndexError):
        raise ValueError("malformed segwit transaction")


def _varint(n):
    if n < 0xFD: return bytes([n])
    if n <= 0xFFFF: return b"\xfd" + struct.pack("<H", n)
    if n <= 0xFFFFFFFF: return b"\xfe" + struct.pack("<I", n)
    return b"\xff" + struct.pack("<Q", n)


def classify_script(script, commitment):
    if script[:1] == b"\x6a": return "op_return"
    if len(script) == 23 and script[:2] == b"\xa9\x14" and script[22] == 0x87: return "p2sh"
    if len(script) == 25 and script[:3] == b"\x76\xa9\x14" and script[23:] == b"\x88\xac": return "p2pkh"
    return "other"


def find_output(tx, commitment):
    for n, s in enumerate(tx.outputs):
        if commitment in s: return {"index": n, "kind": classify_script(s, commitment), "script": s.hex()}
    return None


def compact_target(bits):
    exp, mant = bits >> 24, bits & 0x7FFFFF
    if bits & 0x800000: return None
    return mant >> (8 * (3 - exp)) if exp <= 3 else mant << (8 * (exp - 3))


def pow_ok(header):
    target = compact_target(struct.unpack_from("<I", header, 72)[0])
    return bool(target) and int.from_bytes(sha256d(header), "little") <= target


def phases(proof, att):
    """SPEC section 6; None when no transaction (or no txid hash) is found on the path."""
    if att.kind != "bitcoin": return None
    path = proof.path(att.node)
    msgs = [proof.nodes[n].digest for n in path]
    ops = [None] + [proof.nodes[n].op for n in path[1:]]
    t = next((i for i in range(1, len(msgs)) if parse_tx(msgs[i])), None)
    if t is None: return None
    c = t
    while c > 0 and ops[c] in ("append", "prepend"): c -= 1
    if c == t: return None
    if len(msgs) <= t + 2 or ops[t + 1] != "sha256" or ops[t + 2] != "sha256": return None
    return {"path": path, "commitment_index": c, "transaction_index": t, "txid_index": t + 2,
            "root_index": len(path) - 1, "commitment": msgs[c].hex(), "txid": msgs[t + 2][::-1].hex(),
            "output": find_output(parse_tx(msgs[t]), msgs[c])}


# ----------------------------------------------------------------------------------- misc encodings

def canonical_json(o):
    if o is None: return "null"
    if o is True: return "true"
    if o is False: return "false"
    if isinstance(o, int): return str(o)
    if isinstance(o, str):
        out = ['"']
        for ch in o:
            if ch == '"': out.append('\\"')
            elif ch == "\\": out.append("\\\\")
            elif ch == "\n": out.append("\\n")
            elif ch == "\r": out.append("\\r")
            elif ch == "\t": out.append("\\t")
            elif ord(ch) < 0x20: out.append("\\u%04x" % ord(ch))
            else: out.append(ch)
        out.append('"')
        return "".join(out)
    if isinstance(o, list): return "[" + ",".join(canonical_json(x) for x in o) + "]"
    if isinstance(o, dict): return "{" + ",".join(canonical_json(k) + ":" + canonical_json(o[k]) for k in sorted(o)) + "}"
    raise TypeError("not canonical: %r" % (o,))


def b64u(b): return base64.urlsafe_b64encode(b).rstrip(b"=").decode()
_B64U = frozenset("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_")


def unb64u(s):
    """Strict unpadded base64url (SPEC 9): None for any other alphabet, padding, or an impossible length."""
    if not all(c in _B64U for c in s) or len(s) % 4 == 1: return None
    try: return base64.urlsafe_b64decode(s + "=" * (-len(s) % 4))
    except ValueError: return None


def encode_permalink(base, digest_hex, ots, proof_url):
    url = base
    if proof_url: url += ("&" if "?" in url else "?") + "proof=" + urllib.parse.quote(proof_url, safe="")
    frag = []
    if digest_hex: frag.append("h=" + digest_hex.lower())
    if ots is not None: frag.append("ots=" + b64u(ots))
    return url + ("#" + "&".join(frag) if frag else "")


def _params(text):
    out = {}
    for part in text.split("&") if text else []:
        k, eq, v = part.partition("=")
        if eq and k not in out: out[k] = v
    return out


def _unquote_strict(v):
    try: return urllib.parse.unquote(v, errors="strict")
    except UnicodeDecodeError: return None


def decode_permalink(url):
    """SPEC 9: first duplicate key wins, unknown keys ignored, invalid pieces decode to None."""
    frag = url.partition("#")
    before = frag[0]
    query = before.partition("?")[2]
    q, f = _params(query), _params(frag[2])
    h = f.get("h")
    if h is not None and not (len(h) % 2 == 0 and h and all(c in "0123456789abcdefABCDEF" for c in h)): h = None
    return {"h": h.lower() if h else None, "ots": unb64u(f["ots"]) if "ots" in f else None,
            "proof": _unquote_strict(q["proof"]) if "proof" in q else None}


# ----------------------------------------------------------------------------------- report

def _is_hex(s): return bool(re.fullmatch(r"([0-9a-fA-F]{2})+", s))


def _where_to_look(height, txid):
    out = []
    for name, host, api in (("blockstream.info", "https://blockstream.info", "https://blockstream.info/api"),
                            ("mempool.space", "https://mempool.space", "https://mempool.space/api")):
        out.append({"kind": "block", "server": name, "url": "%s/block%s%d" % (host, "-height/" if name == "blockstream.info" else "/", height)})
        out.append({"kind": "tx", "server": name, "url": "%s/tx/%s" % (host, txid)})
        out.append({"kind": "raw_hex", "server": name, "url": "%s/tx/%s/hex" % (api, txid)})
    return out


def ledger_plan(proof, servers):
    plan = []
    for a in proof.atts:
        if a.kind != "bitcoin": continue
        ph = phases(proof, a)
        for s in servers:
            plan.append({"attestation": a.index, "server": s["name"], "url": "%s/block-height/%d" % (s["base"], a.height)})
            plan.append({"attestation": a.index, "server": s["name"], "url": "%s/block/{block_hash}/header" % s["base"]})
            if ph:
                plan.append({"attestation": a.index, "server": s["name"], "url": "%s/block/{block_hash}/txids" % s["base"]})
                plan.append({"attestation": a.index, "server": s["name"], "url": "%s/tx/%s/hex" % (s["base"], ph["txid"])})
    return plan


def _get(fetch, url):
    """-> (kind, body): kind in ok / not_found / unreachable."""
    try:
        status, body = fetch(url)
    except Exception:
        return "unreachable", ""
    if status == 200: return "ok", body
    if status == 404: return "not_found", ""
    return "unreachable", ""


def _check_server(proof, att, ph, server, fetch):
    base = server["base"]
    res = {"server": server["name"], "status": "PASS", "block_hash": None, "header": None, "time": None, "checks": []}
    state = {"stop": False}
    root = proof.nodes[att.node].digest

    def run(cid, fn):
        if state["stop"]:
            res["checks"].append({"id": cid, "status": "SKIP", "code": "not_run"})
            return
        if ph is None and cid in ("txids", "raw_tx", "output"):
            res["checks"].append({"id": cid, "status": "SKIP", "code": "no_transaction"})
            state["stop"] = True
            return
        status, code = fn()
        res["checks"].append({"id": cid, "status": status, "code": code})
        if status != "PASS": state["stop"] = True

    def block_hash():
        k, body = _get(fetch, "%s/block-height/%d" % (base, att.height))
        if k == "not_found": return "FAIL", "not_found"
        if k != "ok": return "SKIP", "unreachable"
        h = body.strip().lower()
        if not re.fullmatch(r"[0-9a-f]{64}", h): return "FAIL", "bad_response"
        res["block_hash"] = h
        return "PASS", "ok"

    def header():
        k, body = _get(fetch, "%s/block/%s/header" % (base, res["block_hash"]))
        if k == "not_found": return "FAIL", "not_found"
        if k != "ok": return "SKIP", "unreachable"
        h = body.strip().lower()
        if not re.fullmatch(r"[0-9a-f]{160}", h): return "FAIL", "bad_response"
        res["header"] = h
        raw = bytes.fromhex(h)
        if sha256d(raw)[::-1].hex() != res["block_hash"]: return "FAIL", "bad_hash"
        if not pow_ok(raw): return "FAIL", "bad_pow"
        res["time"] = struct.unpack_from("<I", raw, 68)[0]
        return "PASS", "ok"

    def merkle_root():
        return ("PASS", "ok") if bytes.fromhex(res["header"])[36:68] == root else ("FAIL", "mismatch")

    def txids():
        k, body = _get(fetch, "%s/block/%s/txids" % (base, res["block_hash"]))
        if k == "not_found": return "FAIL", "not_found"
        if k != "ok": return "SKIP", "unreachable"
        try:
            lst = json.loads(body)
        except ValueError:
            return "FAIL", "bad_response"
        if not isinstance(lst, list) or not all(isinstance(x, str) for x in lst): return "FAIL", "bad_response"
        return ("PASS", "ok") if ph["txid"] in lst else ("FAIL", "not_in_block")

    tx_holder = {}

    def raw_tx():
        k, body = _get(fetch, "%s/tx/%s/hex" % (base, ph["txid"]))
        if k == "not_found": return "FAIL", "not_found"
        if k != "ok": return "SKIP", "unreachable"
        h = body.strip()
        if not _is_hex(h): return "FAIL", "bad_response"
        try:
            stripped = strip_witness(bytes.fromhex(h))
        except ValueError:
            return "FAIL", "bad_response"
        tx_holder["tx"] = stripped
        mine = proof.nodes[ph["path"][ph["transaction_index"]]].digest
        return ("PASS", "ok") if stripped == mine else ("FAIL", "mismatch")

    def output():
        tx = parse_tx(tx_holder["tx"])
        out = find_output(tx, bytes.fromhex(ph["commitment"])) if tx else None
        return ("PASS", "ok") if out else ("FAIL", "no_output")

    for cid, fn in zip(CHECKS, (block_hash, header, merkle_root, txids, raw_tx, output)): run(cid, fn)
    sts = [c["status"] for c in res["checks"]]
    res["status"] = "FAIL" if "FAIL" in sts else "SKIP" if "SKIP" in sts else "PASS"
    return res


def _run_ledger(proof, fetch, servers):
    atts = []
    for a in proof.atts:
        if a.kind != "bitcoin": continue
        ph = phases(proof, a)
        srv = [_check_server(proof, a, ph, s, fetch) for s in servers]
        headers = [s["header"] for s in srv if s["header"] and s["time"] is not None]
        headers_any = [s["header"] for s in srv if s["header"]]
        agree = None
        if len(headers_any) >= 2: agree = len(set(headers_any)) == 1
        del headers
        atts.append({"attestation": a.index, "agree": agree, "servers": srv})
    return atts


def build_report(proof_bytes, file=None, digest_hex=None, ledger=None):
    """Assemble the report of spec/SPEC.md. `ledger` = None (not asked) or
    {"fetch": fn(url) -> (status, body), "servers": [{"name","base"}] (optional)}."""
    if file is not None and digest_hex is not None: raise ValueError("file and digest_hex are exclusive")
    try:
        proof, err = parse_proof(proof_bytes), None
    except OtsError as e:
        proof, err = None, e.code
    mode = "file" if file is not None else "digest" if digest_hex is not None else "none"
    inp = {"mode": mode, "size": file.size if file is not None else None, "digest": None,
           "digest_alg": proof.hash_op if proof else None}
    st = {}

    # step 1: without a readable proof nothing can be judged (no_proof wins over every other code)
    if mode == "digest" and _is_hex(digest_hex): inp["digest"] = digest_hex.lower()
    if proof is None:
        st["file_hash"] = ("SKIP", "no_proof")
    elif mode == "none":
        st["file_hash"] = ("SKIP", "no_input")
    elif mode == "digest":
        if inp["digest"] is None or len(inp["digest"]) != 2 * DIGEST_LEN[proof.hash_op]: st["file_hash"] = ("FAIL", "bad_digest")
        else: st["file_hash"] = ("PASS", "ok") if bytes.fromhex(inp["digest"]) == proof.digest else ("FAIL", "mismatch")
    elif proof.hash_op == "ripemd160":
        st["file_hash"] = ("SKIP", "alg_unsupported")
    else:
        d = file.digest(proof.hash_op)
        inp["digest"] = d.hex()
        st["file_hash"] = ("PASS", "ok") if d == proof.digest else ("FAIL", "mismatch")
    # step 2, 3
    st["structure"] = ("FAIL", err) if err else ("PASS", "ok")
    if proof is None: st["hash_steps"] = ("SKIP", "no_proof")
    else: st["hash_steps"] = ("PASS", "ok") if st["file_hash"][0] == "PASS" else ("SKIP", "not_tied")

    # proof object
    pobj = None
    led = None
    if proof is not None:
        atts = []
        for a in proof.atts:
            ph = phases(proof, a)
            atts.append({"index": a.index, "node": a.node, "kind": a.kind, "height": a.height, "uri": a.uri,
                         "tag": a.tag.hex(), "payload": a.payload.hex(), "phases": ph,
                         "where_to_look": _where_to_look(a.height, ph["txid"]) if ph and a.kind == "bitcoin" else []})
        pobj = {"size": proof.size, "version": 1, "hash_op": proof.hash_op, "digest": proof.digest.hex(),
                "nodes": len(proof.nodes), "ops": len(proof.nodes) - 1, "max_depth": proof.max_depth,
                "tree": [{"id": n.id, "parent": n.parent, "op": n.op, "arg": n.arg.hex() if n.arg is not None else None,
                          "digest": n.digest.hex()} for n in proof.nodes],
                "attestations": atts}

    # step 4
    has_btc = proof is not None and any(a.kind == "bitcoin" for a in proof.atts)
    if proof is None: st["ledger"] = ("SKIP", "no_proof")
    elif ledger is None: st["ledger"] = ("SKIP", "not_requested")
    elif not has_btc: st["ledger"] = ("SKIP", "no_bitcoin")
    else:
        servers = ledger.get("servers") or DEFAULT_SERVERS
        results = _run_ledger(proof, ledger["fetch"], servers)
        led = {"servers": [dict(name=s["name"], base=s["base"]) for s in servers], "plan": ledger_plan(proof, servers), "attestations": results}
        flat = [c["status"] for r in results for s in r["servers"] for c in s["checks"]]
        if any(r["agree"] is False for r in results): st["ledger"] = ("FAIL", "disagree")
        elif "FAIL" in flat: st["ledger"] = ("FAIL", "check_failed")
        elif "SKIP" in flat: st["ledger"] = ("SKIP", "incomplete")
        else: st["ledger"] = ("PASS", "ok")

    # step 5
    order = ["file_hash", "structure", "hash_steps", "ledger"]
    sts = [st[k][0] for k in order]
    status = "FAIL" if "FAIL" in sts else "SKIP" if "SKIP" in sts else "PASS"
    code = {"PASS": "proved", "FAIL": "failed", "SKIP": "incomplete"}[status]
    st["verdict"] = (status, code)
    block = time = None
    if status == "PASS":
        best = min((a for a in proof.atts if a.kind == "bitcoin"), key=lambda a: (a.height, a.index))
        block = best.height
        entry = next(r for r in led["attestations"] if r["attestation"] == best.index)
        time = next(s["time"] for s in entry["servers"] if s["time"] is not None)
    return {
        "spec": SPEC, "input": inp, "error": {"code": err} if err else None, "proof": pobj,
        "steps": [{"id": i, "title": t, "status": st[i][0], "code": st[i][1]} for i, t in STEPS],
        "ledger": led,
        "verdict": {"status": status, "code": code, "block": block, "time": time,
                    "unverified": [a.index for a in proof.atts if a.kind != "bitcoin"] if proof else []},
    }


# ----------------------------------------------------------------------------------- network

def http_fetch(timeout=15.0):
    def fetch(url):
        req = urllib.request.Request(url, headers={"User-Agent": "ots-explain/" + VERSION, "Accept": "*/*"})
        try:
            with urllib.request.urlopen(req, timeout=timeout) as r:
                return r.status, r.read(8 << 20).decode("utf-8", "replace")
        except urllib.error.HTTPError as e:
            return e.code, ""
        except (urllib.error.URLError, OSError, ValueError) as e:
            raise OSError(str(e))
    return fetch


# ----------------------------------------------------------------------------------- text output

MSG = {
    "file_hash": {
        "ok": "the digest of your input equals the digest the proof names", "mismatch": "your input does not hash to the digest in the proof: this proof is not about it",
        "bad_digest": "that digest is not valid hex or has the wrong length for the proof's algorithm", "no_input": "no file or digest given, so nothing ties the proof to your data",
        "no_proof": "the proof could not be read, so the algorithm is unknown", "alg_unsupported": "this proof names RIPEMD-160, which this tool does not use to hash files; pass --digest HEX instead",
    },
    "hash_steps": {"ok": "every operation was recomputed from your digest", "not_tied": "shown from the digest inside the proof, not confirmed against your input", "no_proof": "no readable proof"},
    "ledger": {
        "ok": "every Bitcoin attestation was confirmed by every server asked", "not_requested": "not asked: no network was used", "no_bitcoin": "the proof has no Bitcoin attestation to check",
        "no_proof": "no readable proof", "check_failed": "at least one check failed", "disagree": "the servers gave different headers", "incomplete": "nothing failed, but some check could not be completed",
    },
    "verdict": {"proved": "", "failed": "at least one check failed", "incomplete": "some checks were skipped, so no verdict is given"},
}
KIND_NAME = {"bitcoin": "Bitcoin", "litecoin": "Litecoin", "ethereum": "Ethereum", "pending": "pending", "unknown": "unknown"}


def _when(ts):
    import datetime
    return datetime.datetime.fromtimestamp(ts, datetime.timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")


def render_text(report, steps=False):
    L = []
    inp, proof = report["input"], report["proof"]
    L.append("OpenTimestamps proof, hop by hop")
    L.append("input: " + {"file": "file (%s bytes)" % inp["size"], "digest": "a digest", "none": "proof only"}[inp["mode"]])
    for s in report["steps"]:
        n = [i for i, _ in STEPS].index(s["id"]) + 1
        L.append("")
        L.append("[%s] %d. %s" % (s["status"], n, s["title"]))
        L.append("    " + WHY[s["id"]])
        if s["id"] == "structure":
            if report["error"]: L.append("    cannot read it: " + report["error"]["code"])
            else:
                L.append("    version 1, header algorithm %s, %d bytes, %d nodes, %d operations, depth %d" % (proof["hash_op"], proof["size"], proof["nodes"], proof["ops"], proof["max_depth"]))
                L.append("    proof digest: " + proof["digest"])
                for a in proof["attestations"]:
                    what = "block %d" % a["height"] if a["height"] is not None else a["uri"] if a["uri"] else "tag " + a["tag"]
                    L.append("    attestation %d: %s (%s)" % (a["index"], KIND_NAME[a["kind"]], what))
        elif s["id"] == "file_hash" and inp["digest"]:
            L.append("    digest: " + inp["digest"])
        elif s["id"] == "verdict" and s["status"] == "PASS":
            v = report["verdict"]
            L.append("    This file existed before block %d (header time %s; miners' clocks are approximate)." % (v["block"], _when(v["time"])))
            if v["unverified"]: L.append("    Not checked here: attestation(s) %s." % ", ".join(str(i) for i in v["unverified"]))
        if s["id"] in MSG and MSG[s["id"]].get(s["code"]): L.append("    -> " + MSG[s["id"]][s["code"]])
        if s["id"] == "hash_steps" and proof and steps: L += _render_hops(proof)
        if s["id"] == "ledger" and report["ledger"]:
            for r in report["ledger"]["attestations"]:
                for sv in r["servers"]:
                    L.append("    attestation %d on %s: %s%s" % (r["attestation"], sv["server"], sv["status"],
                             "  (" + ", ".join("%s %s" % (c["id"], c["code"]) for c in sv["checks"] if c["status"] != "PASS") + ")" if sv["status"] != "PASS" else ""))
        if s["id"] == "ledger" and proof:
            for a in proof["attestations"]:
                for w in a["where_to_look"]: L.append("    look: %s %s %s" % (w["server"], w["kind"], w["url"]))
    return "\n".join(L) + "\n"


def _render_hops(proof):
    L = []
    nodes = {n["id"]: n for n in proof["tree"]}
    for a in proof["attestations"]:
        L.append("    path to attestation %d (%s):" % (a["index"], KIND_NAME[a["kind"]]))
        ph = a["phases"]
        path = []
        k = a["node"]
        while k != -1:
            path.append(nodes[k]); k = nodes[k]["parent"]
        path.reverse()
        names = {}
        if ph:
            for i in range(1, ph["commitment_index"] + 1): names[i] = "calendar's tree"
            for i in range(ph["commitment_index"] + 1, ph["txid_index"] + 1): names[i] = "the transaction"
            for i in range(ph["txid_index"] + 1, len(path)): names[i] = "the block's merkle path"
        last = None
        L.append("      0  start        %s" % path[0]["digest"])
        for i, n in enumerate(path[1:], 1):
            if names.get(i) != last and names.get(i):
                last = names[i]
                L.append("      -- phase: %s" % last)
            arg = (" " + n["arg"]) if n["arg"] else ""
            L.append("    %3d  %s%s" % (i, n["op"], (arg if len(arg) < 70 else arg[:34] + ".." + arg[-30:])))
            L.append("           = %s" % n["digest"])
    return L


# ----------------------------------------------------------------------------------- cli

def _parser():
    p = argparse.ArgumentParser(prog="verify_ots.py", description="Explain an OpenTimestamps proof hop by hop (standard library only).",
                                epilog="exit codes: 0 verdict PASS, 1 verdict FAIL, 3 something not checked, 2 usage or input error")
    p.add_argument("paths", nargs="*", metavar="FILE PROOF", help="FILE PROOF.ots, or just PROOF.ots (FILE is then looked up by dropping .ots)")
    p.add_argument("--digest", metavar="HEX", help="use this hex digest instead of hashing a file")
    p.add_argument("--offline", action="store_true", help="never use the network (the default when not interactive)")
    p.add_argument("-y", "--yes", action="store_true", help="after listing the URLs, call them without asking")
    p.add_argument("--esplora", action="append", metavar="URL", help="an Esplora base URL to ask instead of the two defaults (repeatable)")
    p.add_argument("--timeout", type=float, default=15.0, help="seconds per request (default 15)")
    p.add_argument("--steps", action="store_true", help="show every digest after every operation")
    p.add_argument("--json", action="store_true", help="print the canonical JSON report instead of text")
    p.add_argument("--link", metavar="BASE", help="also print a permalink for this digest and proof under BASE")
    p.add_argument("--version", action="version", version="verify_ots " + VERSION)
    return p


def main(argv=None, stdin=None, stdout=None, stderr=None):
    stdout, stderr = stdout or sys.stdout, stderr or sys.stderr
    stdin = stdin or sys.stdin
    args = _parser().parse_args(argv)
    out = lambda s: stdout.write(s)
    err = lambda s: stderr.write(s + "\n")
    paths = list(args.paths)
    if not paths or len(paths) > 2: err("usage: verify_ots.py [FILE] PROOF.ots [--digest HEX] ... (see --help)"); return 2
    proof_path = paths[-1] if len(paths) == 2 or args.digest or paths[0].endswith(".ots") else paths[0] + ".ots"
    file_path = paths[0] if len(paths) == 2 else None
    if len(paths) == 1 and not args.digest and not paths[0].endswith(".ots"):
        file_path = paths[0]
    elif len(paths) == 1 and not args.digest and os.path.isfile(paths[0][:-4]) and paths[0][:-4] != paths[0]:
        file_path = paths[0][:-4]
    if args.digest and file_path: err("use either a FILE or --digest, not both"); return 2
    try:
        with open(proof_path, "rb") as f: proof_bytes = f.read()
        file_input = FileInput.from_path(file_path) if file_path else None
    except OSError as e:
        err("cannot read %s: %s" % (e.filename, e.strerror)); return 2

    servers = [{"name": u.rstrip("/"), "base": u.rstrip("/")} for u in args.esplora] if args.esplora else DEFAULT_SERVERS
    ledger = None
    try:
        probe = parse_proof(proof_bytes)
    except OtsError:
        probe = None
    if not args.offline and probe is not None and any(a.kind == "bitcoin" for a in probe.atts):
        plan = ledger_plan(probe, servers)
        err("Step 4 would ask these URLs (GET only; {block_hash} comes from the first answer):")
        for e in plan: err("  " + e["url"])
        go = args.yes
        if not go and stdin.isatty():
            stderr.write("Ask these servers now? [y/N] "); stderr.flush()
            go = stdin.readline().strip().lower() in ("y", "yes")
        elif not go: err("Not asked (no --yes and not interactive): staying offline.")
        if go: ledger = {"fetch": http_fetch(args.timeout), "servers": servers}
    report = build_report(proof_bytes, file=file_input, digest_hex=args.digest, ledger=ledger)
    if args.json: out(canonical_json(report) + "\n")
    else: out(render_text(report, steps=args.steps))
    if args.link:
        d = report["input"]["digest"]
        out(("" if args.json else "\n") + encode_permalink(args.link, d, proof_bytes, None) + "\n")
    return {"PASS": 0, "FAIL": 1, "SKIP": 3}[report["verdict"]["status"]]


if __name__ == "__main__":
    sys.exit(main())

#!/usr/bin/env python3
# Copyright 2026 the ots-explain authors. Licensed under the Apache License, Version 2.0.
"""ots_stamp.py - stamp a file, upgrade pending proofs, and watch a folder (cron-friendly).
Standard library only; needs verify_ots.py next to it. You run it; nothing here runs by itself.

    ots_stamp.py stamp FILE            hash FILE, ask the calendars to timestamp it, write FILE.ots
    ots_stamp.py stamp --digest HEX    same for a SHA-256 digest (writes HEX.ots)
    ots_stamp.py upgrade FILE.ots      ask the calendars whether Bitcoin has confirmed yet
    ots_stamp.py watch DIR             for every *.ots in DIR: upgrade pending ones, then check them

What leaves your machine when you stamp: only SHA-256(digest + 16 random bytes), never the file and
never its own digest (the random bytes stay inside the .ots). Upgrade and watch send only that same
commitment to the calendar named in the proof, and only if that calendar is on the allowed list.
"""
import argparse
import json
import os
import sys
import time
import urllib.error
import urllib.parse
import urllib.request

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import verify_ots as V  # noqa: E402

DEFAULT_CALENDARS = [
    "https://alice.btc.calendar.opentimestamps.org",
    "https://bob.btc.calendar.opentimestamps.org",
    "https://finney.calendar.eternitywall.com",
]
# calendars seen in the public example proofs; a URI inside a proof is untrusted input, so only these
# (plus --allow) may be contacted by `upgrade` and `watch`.
KNOWN_CALENDARS = DEFAULT_CALENDARS + ["https://btc.calendar.catallaxy.com", "https://ots.btc.catallaxy.com"]
OP_BYTE = {"append": 0xF0, "prepend": 0xF1, "sha256": 0x08, "sha1": 0x02, "ripemd160": 0x03, "keccak256": 0x67, "reverse": 0xF2, "hexlify": 0xF3}
HASH_BYTE = {"sha256": 0x08, "sha1": 0x02, "ripemd160": 0x03}
MAX_CALENDAR_RESPONSE = 10000
PENDING_TAG = bytes.fromhex("83dfe30d2ef90c8e")
BITCOIN_TAG = bytes.fromhex("0588960d73d71901")


# ---------------------------------------------------------------------------------- tree <-> bytes

class T:
    """A mutable timestamp tree, for writing: a message, attestations and (op, arg, subtree) edges."""
    def __init__(self, msg): self.msg, self.atts, self.ops = msg, [], []


def to_tree(proof):
    nodes = {n.id: T(n.digest) for n in proof.nodes}
    for n in proof.nodes[1:]: nodes[n.parent].ops.append((n.op, n.arg, nodes[n.id]))
    for a in proof.atts: nodes[a.node].atts.append((a.tag, a.payload, a.kind, a.height, a.uri))
    return nodes[0]


def _att_key(a):
    tag, payload, kind, height, uri = a
    return (tag, height if height is not None else 0, uri.encode() if uri else payload)


def _ser(t):
    entries = []
    for a in sorted(t.atts, key=_att_key): entries.append(b"\x00" + a[0] + _vb(a[1]))
    for op, arg, sub in sorted(t.ops, key=lambda e: (OP_BYTE[e[0]], e[1] or b"")):
        entries.append(bytes([OP_BYTE[op]]) + (_vb(arg) if arg is not None else b"") + _ser(sub))
    if not entries: raise ValueError("empty timestamp")
    return b"".join(b"\xff" + e for e in entries[:-1]) + entries[-1]


def _vu(n):
    out = bytearray()
    while True:
        b = n & 0x7F
        n >>= 7
        out.append(b | (0x80 if n else 0))
        if not n: return bytes(out)


def _vb(b): return _vu(len(b)) + b


def serialize_proof(hash_op, digest, tree):
    return V.MAGIC + b"\x01" + bytes([HASH_BYTE[hash_op]]) + digest + _ser(tree)


def parse_fragment(data, msg):
    """Parse a calendar response (a bare timestamp over `msg`) into a T."""
    if len(data) > MAX_CALENDAR_RESPONSE: raise V.OtsError("payload_too_long")
    if not 1 <= len(msg) <= 4096: raise V.OtsError("arg_length")
    p = V.Proof(len(data), 1, "sha256", msg)
    p.nodes.append(V.Node(0, -1, None, None, msg))
    r = V.Reader(data)
    V._timestamp(r, p, 0, 0, V.RECURSION)
    if not r.eof(): raise V.OtsError("trailing_garbage")
    return to_tree(p)


def merge(into, frag):
    """Add the attestations and edges of `frag` to `into`; an edge that already exists (same op and argument) is
    merged, not repeated, because a proof may not contain the same operation twice at one node."""
    for a in frag.atts:
        if not any(a[0] == b[0] and a[1] == b[1] for b in into.atts): into.atts.append(a)
    for op, arg, sub in frag.ops:
        for op2, arg2, sub2 in into.ops:
            if op == op2 and arg == arg2: merge(sub2, sub); break
        else: into.ops.append((op, arg, sub))


def walk(t):
    yield t
    for _, _, sub in t.ops: yield from walk(sub)


def has_bitcoin(t): return any(a[2] == "bitcoin" for n in walk(t) for a in n.atts)
def pending_uris(t): return [(n, a[4]) for n in walk(t) for a in n.atts if a[2] == "pending"]


# ---------------------------------------------------------------------------------- network

class _SameHostHttps(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        old, new = urllib.parse.urlparse(req.full_url), urllib.parse.urlparse(newurl)
        if new.hostname != old.hostname or (new.scheme != "https" and old.scheme == "https"): return None
        return super().redirect_request(req, fp, code, msg, headers, newurl)


def http_call(timeout=20.0):
    opener = urllib.request.build_opener(_SameHostHttps)

    def call(url, data=None):
        req = urllib.request.Request(url, data=data, headers={"Accept": "application/vnd.opentimestamps.v1", "User-Agent": "ots-explain/" + V.VERSION})
        try:
            with opener.open(req, timeout=timeout) as r: return r.status, r.read(MAX_CALENDAR_RESPONSE + 1)
        except urllib.error.HTTPError as e: return e.code, b""
        except (urllib.error.URLError, OSError) as e: raise OSError(str(e))
    return call


def _join(base, path): return base.rstrip("/") + "/" + path


# ---------------------------------------------------------------------------------- operations

def stamp_digest(digest, calendars, call, nonce=None, log=lambda s: None):
    """-> .ots bytes. `call(url, data)` returns (status, body). `nonce` is for tests only."""
    nonce = nonce if nonce is not None else os.urandom(16)
    root = T(digest)
    mid = T(digest + nonce); root.ops.append(("append", nonce, mid))
    tip = T(V.sha256(digest + nonce)); mid.ops.append(("sha256", None, tip))
    ok = 0
    for cal in calendars:
        try:
            status, body = call(_join(cal, "digest"), tip.msg)
            if status != 200: raise OSError("HTTP %d" % status)
            frag = parse_fragment(body, tip.msg)
        except (OSError, V.OtsError) as e:
            log("calendar %s failed: %s" % (cal, e.code if isinstance(e, V.OtsError) else e)); continue
        merge(tip, frag); ok += 1
        log("calendar %s accepted the commitment" % cal)
    if not ok: raise RuntimeError("no calendar accepted the commitment")
    return serialize_proof("sha256", digest, root)


def upgrade_proof(proof_bytes, call, allowed, log=lambda s: None):
    """-> (new_bytes, changed, status) where status is 'complete', 'pending' or 'nothing_to_do'."""
    p = V.parse_proof(proof_bytes)
    t = to_tree(p)
    if has_bitcoin(t) and not pending_uris(t): return proof_bytes, False, "nothing_to_do"
    changed = False
    for node, uri in pending_uris(t):
        if uri.rstrip("/") not in {a.rstrip("/") for a in allowed}:
            log("not asking %s: not on the allowed list (use --allow)" % uri); continue
        try:
            status, body = call(_join(uri, "timestamp/" + node.msg.hex()))
        except OSError as e:
            log("%s unreachable: %s" % (uri, e)); continue
        if status == 404: log("%s: not confirmed yet" % uri); continue
        if status != 200: log("%s: HTTP %d" % (uri, status)); continue
        try:
            frag = parse_fragment(body, node.msg)
        except V.OtsError as e:
            log("%s sent an unreadable answer: %s" % (uri, e.code)); continue
        if not has_bitcoin(frag): log("%s: answer has no Bitcoin attestation yet" % uri); continue
        node.atts = [a for a in node.atts if not (a[2] == "pending" and a[4] == uri)]
        merge(node, frag)
        changed = True
    if not changed: return proof_bytes, False, "pending"
    new = serialize_proof(p.hash_op, p.digest, t)
    V.parse_proof(new)  # never write something we cannot read back
    return new, True, "complete"


def state_path(proof_path): return proof_path + ".state.json"


def watch(directory, call, allowed, min_interval=3600, base_url=None, ledger=None, now=None, log=print):
    """One pass over DIR. -> list of (file, event). Events: upgraded, still_pending, verified, failed, skipped."""
    now = now if now is not None else time.time()
    events = []
    for name in sorted(os.listdir(directory)):
        if not name.endswith(".ots"): continue
        path = os.path.join(directory, name)
        with open(path, "rb") as f: data = f.read()
        try:
            proof = V.parse_proof(data)
        except V.OtsError as e:
            events.append((name, "failed:" + e.code)); log("%s: unreadable (%s)" % (name, e.code)); continue
        sp = state_path(path)
        st = {}
        if os.path.exists(sp):
            with open(sp) as f: st = json.load(f)
        if any(a.kind == "pending" for a in proof.atts) and not any(a.kind == "bitcoin" for a in proof.atts):
            if now - st.get("last_try", 0) < min_interval: events.append((name, "skipped")); continue
            st["last_try"] = now
            new, changed, status = upgrade_proof(data, call, allowed, lambda s: None)
            if changed:
                with open(path + ".bak", "wb") as f: f.write(data)
                with open(path, "wb") as f: f.write(new)
                data = new; proof = V.parse_proof(data)
                events.append((name, "upgraded")); log("%s: upgraded, Bitcoin attestation added" % name)
            else:
                events.append((name, "still_pending"))
                with open(sp, "w") as f: json.dump(st, f)
                continue
        target = os.path.join(directory, name[:-4])
        digest_hex = proof.digest.hex()
        file_input = V.FileInput.from_path(target) if os.path.isfile(target) else None
        rep = V.build_report(data, file=file_input, digest_hex=None if file_input else digest_hex, ledger=ledger)
        with open(path + ".report.json", "w") as f: f.write(V.canonical_json(rep) + "\n")
        st["verdict"] = rep["verdict"]["status"]
        if base_url:
            st["link"] = V.encode_permalink(base_url, digest_hex, data, None)
        with open(sp, "w") as f: json.dump(st, f)
        if any(a.kind == "bitcoin" for a in proof.atts):
            ev = {"PASS": "verified", "FAIL": "failed", "SKIP": "skipped"}[rep["verdict"]["status"]]
            events.append((name, ev))
            if ev != "skipped": log("%s: %s" % (name, rep["verdict"]["code"]))
    if base_url:
        links = [(n[:-4], json.load(open(state_path(os.path.join(directory, n)))).get("link", ""))
                 for n in sorted(os.listdir(directory)) if n.endswith(".ots") and os.path.exists(state_path(os.path.join(directory, n)))]
        with open(os.path.join(directory, "links.tsv"), "w") as f:
            f.write("".join("%s\t%s\n" % x for x in links if x[1]))
    return events


# ---------------------------------------------------------------------------------- cli

def main(argv=None, stdin=None, stdout=None, stderr=None, call=None):
    stdout, stderr, stdin = stdout or sys.stdout, stderr or sys.stderr, stdin or sys.stdin
    ap = argparse.ArgumentParser(prog="ots_stamp.py", description=__doc__.split("\n\n")[0])
    sub = ap.add_subparsers(dest="cmd", required=True)
    s = sub.add_parser("stamp"); s.add_argument("file", nargs="?"); s.add_argument("--digest"); s.add_argument("--calendar", action="append")
    s.add_argument("--out"); s.add_argument("-y", "--yes", action="store_true"); s.add_argument("--force", action="store_true")
    u = sub.add_parser("upgrade"); u.add_argument("proof"); u.add_argument("--allow", action="append", default=[])
    w = sub.add_parser("watch"); w.add_argument("dir"); w.add_argument("--allow", action="append", default=[])
    w.add_argument("--min-interval", type=int, default=3600, help="seconds between calendar asks per proof (default 3600)")
    w.add_argument("--links-base", metavar="URL", help="also write links.tsv with permalinks under this page URL")
    w.add_argument("--esplora", action="append", metavar="URL", help="check confirmed proofs against this Esplora (repeatable); default: no ledger check")
    w.add_argument("--ledger", action="store_true", help="check confirmed proofs against blockstream.info and mempool.space")
    for x in (s, u, w): x.add_argument("--timeout", type=float, default=20.0)
    a = ap.parse_args(argv)
    p = lambda m: stderr.write(m + "\n")
    call = call or http_call(a.timeout)
    if a.cmd == "stamp":
        if bool(a.file) == bool(a.digest): p("give a FILE or --digest, not both"); return 2
        try:
            digest = bytes.fromhex(a.digest) if a.digest else V.FileInput.from_path(a.file).digest("sha256")
        except (OSError, ValueError) as e: p("cannot read input: %s" % e); return 2
        if len(digest) != 32: p("a SHA-256 digest is 32 bytes"); return 2
        cals = a.calendar or DEFAULT_CALENDARS
        out = a.out or ((a.file or digest.hex()) + ".ots")
        if os.path.exists(out) and not a.force: p("%s exists (use --force)" % out); return 2
        p("This will POST one 32-byte commitment (SHA-256 of your digest plus 16 random bytes) to:")
        for c in cals: p("  " + _join(c, "digest"))
        if not a.yes:
            if not stdin.isatty(): p("Not asked (no --yes and not interactive): nothing sent."); return 3
            stderr.write("Send it? [y/N] "); stderr.flush()
            if stdin.readline().strip().lower() not in ("y", "yes"): return 3
        try: data = stamp_digest(digest, cals, call, log=p)
        except RuntimeError as e: p(str(e)); return 1
        with open(out, "wb") as f: f.write(data)
        stdout.write("wrote %s (%d bytes); pending: run `ots_stamp.py upgrade %s` in a few hours\n" % (out, len(data), out))
        return 0
    if a.cmd == "upgrade":
        try:
            with open(a.proof, "rb") as f: data = f.read()
            new, changed, status = upgrade_proof(data, call, KNOWN_CALENDARS + a.allow, p)
        except (OSError, V.OtsError) as e: p("cannot upgrade: %s" % (e.code if isinstance(e, V.OtsError) else e)); return 2
        if changed:
            with open(a.proof + ".bak", "wb") as f: f.write(data)
            with open(a.proof, "wb") as f: f.write(new)
        stdout.write({"complete": "upgraded: Bitcoin attestation added (previous file kept as .bak)\n", "pending": "still pending\n", "nothing_to_do": "already has a Bitcoin attestation\n"}[status])
        return 0 if status != "pending" else 3
    if a.cmd == "watch":
        ledger = None
        if a.ledger or a.esplora:
            ledger = {"fetch": V.http_fetch(a.timeout), "servers": [{"name": u.rstrip("/"), "base": u.rstrip("/")} for u in a.esplora] if a.esplora else None}
        try: events = watch(a.dir, call, KNOWN_CALENDARS + a.allow, a.min_interval, a.links_base, ledger, log=lambda m: stdout.write(m + "\n"))
        except OSError as e: p("cannot read %s: %s" % (a.dir, e)); return 2
        return 1 if any(ev.startswith("failed") for _, ev in events) else 0


if __name__ == "__main__":
    sys.exit(main())

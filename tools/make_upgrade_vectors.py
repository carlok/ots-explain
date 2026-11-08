#!/usr/bin/env python3
# Copyright 2026 the ots-explain authors. Licensed under the Apache License, Version 2.0.
"""Writes vectors/upgrade/index.json: upgrade cases on the official proofs (pending attestations hang on 44-byte nodes).

Each case: the proof (a vector id), the calendar answers (url -> status + hex body), the allow-list, and the expected
log lines, status and resulting proof, produced by python/ots_stamp.py. test/js/upgrade-vectors.test.mjs replays the cases
through the independently written TypeScript module and requires the same lines and the same bytes."""
import json, os, sys
ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(ROOT, "python"))
import ots_stamp as S, verify_ots as V

def varuint(n):
    out = bytearray()
    while True:
        b = n & 0x7f; n >>= 7
        out.append(b | (0x80 if n else 0))
        if not n: return bytes(out)

def btc(height):
    p = varuint(height)
    return b"\x00" + bytes.fromhex("0588960d73d71901") + varuint(len(p)) + p

ALICE, BOB = "https://alice.btc.calendar.opentimestamps.org", "https://bob.btc.calendar.opentimestamps.org"
CASES = [
    ("two-calendars: only alice has it", "two-calendars", {ALICE: (200, bytes.fromhex("f008") + bytes(range(8)) + b"\x08" + btc(358391)), BOB: (404, b"")}, [ALICE, BOB]),
    ("two-calendars: both have it, merged", "two-calendars", {ALICE: (200, btc(358391)), BOB: (200, btc(358391))}, [ALICE, BOB]),
    ("two-calendars: neither has it", "two-calendars", {ALICE: (404, b""), BOB: (500, b"")}, [ALICE, BOB]),
    ("two-calendars: answer has no Bitcoin attestation", "two-calendars", {ALICE: (200, b"\x00" + bytes.fromhex("83dfe30d2ef90c8e") + b"\x07\x06foobar"), BOB: (404, b"")}, [ALICE, BOB]),
    ("two-calendars: only bob is allowed", "two-calendars", {ALICE: (200, btc(1)), BOB: (200, btc(2))}, [BOB + "/"]),
    ("two-calendars: unreadable answer", "two-calendars", {ALICE: (200, b"\xff\xff"), BOB: (200, btc(5) + b"junk")}, [ALICE, BOB]),
    ("incomplete: one calendar, upgraded", "incomplete", None, None),
]

def main():
    out = []
    for title, vid, answers, allowed in CASES:
        proof = open(os.path.join(ROOT, "vectors", vid, "proof.ots"), "rb").read()
        t = S.to_tree(V.parse_proof(proof))
        uris = [u for _, u in S.pending_uris(t)]
        if answers is None:
            answers = {u: (200, btc(400000)) for u in uris}; allowed = list(uris)
        def call(url, body=None):
            for u, (st, b) in answers.items():
                if url.startswith(u.rstrip("/") + "/timestamp/"): return st, b
            raise OSError("no route " + url)
        log = []
        new, changed, status = S.upgrade_proof(proof, call, allowed, log=log.append)
        out.append({"title": title, "proof": vid, "answers": {u: {"status": s, "body_hex": b.hex()} for u, (s, b) in answers.items()},
                    "allowed": allowed, "expect": {"status": status, "changed": changed, "log": log, "proof_hex": new.hex()}})
    json.dump(out, open(os.path.join(ROOT, "vectors", "upgrade", "index.json"), "w"), indent=1, sort_keys=True)
    print("wrote", len(out), "upgrade cases"); print(*[("%s -> %s" % (c["title"], c["expect"]["status"])) for c in out], sep="\n  ")

if __name__ == "__main__": main()

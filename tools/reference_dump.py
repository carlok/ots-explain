#!/usr/bin/env python3
"""Dump each vector's tree as computed by the reference library (python-opentimestamps) to
vectors/<id>/reference.tree.json: edges (parent digest, op, arg, child digest) and attestations
(node digest, kind, value), sorted, so that both implementations can be checked against a third
party without needing that library at test time.   dev only: pip install opentimestamps
usage: reference_dump.py VECTORS_DIR
"""
import io, json, os, sys
from opentimestamps.core.timestamp import DetachedTimestampFile
from opentimestamps.core.serialize import StreamDeserializationContext
from opentimestamps.core import notary

vec = sys.argv[1]
KIND = {notary.PendingAttestation: "pending", notary.BitcoinBlockHeaderAttestation: "bitcoin",
        notary.LitecoinBlockHeaderAttestation: "litecoin", notary.UnknownAttestation: "unknown"}

def walk(ts, edges, atts):
    for a in ts.attestations:
        k = KIND.get(type(a), "ethereum" if type(a).__name__.startswith("Ethereum") else "?")
        v = getattr(a, "height", None)
        if v is None: v = getattr(a, "uri", None)
        if v is None: v = a.TAG.hex() + ":" + a.payload.hex()
        atts.append([ts.msg.hex(), k, v])
    for op, sub in ts.ops.items():
        arg = op[0].hex() if len(op) else None
        edges.append([ts.msg.hex(), op.TAG_NAME, arg, sub.msg.hex()])
        walk(sub, edges, atts)

for e in json.load(open(os.path.join(vec, "index.json")))["vectors"]:
    p = os.path.join(vec, e["id"], "proof.ots")
    try:
        d = DetachedTimestampFile.deserialize(StreamDeserializationContext(open(p, "rb")))
    except Exception as ex:
        json.dump({"valid": False, "error": type(ex).__name__ + ": " + str(ex)[:200]}, open(os.path.join(vec, e["id"], "reference.tree.json"), "w"), indent=1)
        continue
    edges, atts = [], []
    walk(d.timestamp, edges, atts)
    out = {"valid": True, "file_hash_op": d.file_hash_op.TAG_NAME, "digest": d.file_digest.hex(),
           "edges": sorted(edges, key=lambda x: [str(y) for y in x]), "attestations": sorted(atts, key=lambda x: [str(y) for y in x])}
    json.dump(out, open(os.path.join(vec, e["id"], "reference.tree.json"), "w"), indent=1)
print("ok")

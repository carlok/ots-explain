#!/usr/bin/env python3
"""Build SYNTHETIC explorer responses (Esplora format) for the Bitcoin vectors.

These are NOT recorded from real servers (the sandbox this was written in cannot reach them).
Each fake block is built around the proof's own data: header merkle root = the proof's final digest,
a trivially easy nBits (0x207fffff) ground to a valid proof of work, the proof's transaction listed in
`txids`, and the same transaction served (one of them wrapped in segwit form with a dummy witness)
at /tx/<txid>/hex. They exercise the code paths; they do not prove anything about real blocks.
Use test/record_explorer.py on a machine with network access to record real ones into
vectors/explorer/recorded/.

Needs python-opentimestamps and python-bitcoinlib (dev only): pip install opentimestamps
usage: make_synthetic_explorer.py VECTORS_DIR
"""
import hashlib, io, json, os, struct, sys
from bitcoin.core import CTransaction
from opentimestamps.core.timestamp import DetachedTimestampFile
from opentimestamps.core.serialize import StreamDeserializationContext
from opentimestamps.core.notary import BitcoinBlockHeaderAttestation

vec = sys.argv[1]
OUT = os.path.join(vec, "explorer")

def sha256d(b): return hashlib.sha256(hashlib.sha256(b).digest()).digest()

def walk(ts, path, found):
    for att in ts.attestations:
        if isinstance(att, BitcoinBlockHeaderAttestation):
            found.append((att.height, path + [ts.msg]))
    for op, sub in ts.ops.items():
        walk(sub, path + [ts.msg], found)

def is_tx(m):
    try:
        CTransaction.deserialize(m); return True
    except Exception:
        return False

def put(scenario, rel, data):
    p = os.path.join(OUT, scenario, rel); os.makedirs(os.path.dirname(p), exist_ok=True)
    open(p, "w").write(data if isinstance(data, str) else json.dumps(data))

def mine(height, merkle_root):
    prev = hashlib.sha256(b"prev-%d" % height).digest()
    t = 1400000000 + height * 600
    bits = 0x207fffff
    target = 0x7fffff << (8 * (0x20 - 3))
    for nonce in range(1 << 20):
        hdr = struct.pack("<I", 0x20000000) + prev + merkle_root + struct.pack("<III", t, bits, nonce)
        if int.from_bytes(sha256d(hdr), "little") <= target:
            return hdr
    raise SystemExit("no nonce")

def segwit_wrap(tx):  # legacy -> segwit serialization with a dummy witness; returns bytes
    def varint(b, i):
        n = b[i]
        if n < 0xfd: return n, i + 1
        if n == 0xfd: return int.from_bytes(b[i+1:i+3], "little"), i + 3
        raise SystemExit("big varint")
    i = 4; n_in, i = varint(tx, i); body_start = i
    for _ in range(n_in):
        i += 36; sl, i = varint(tx, i); i += sl + 4
    n_out, i = varint(tx, i)
    for _ in range(n_out):
        i += 8; sl, i = varint(tx, i); i += sl
    witness = b"".join(b"\x02\x02\xab\xcd\x01\xee" for _ in range(n_in))  # 2 items: abcd, ee... see below
    witness = b"".join(bytes([2, 2]) + b"\xab\xcd" + bytes([1]) + b"\xee" for _ in range(n_in))
    return tx[:4] + b"\x00\x01" + tx[4:i] + witness + tx[i:]

index = json.load(open(os.path.join(vec, "index.json")))["vectors"]
blocks = {}
for e in index:
    if e["id"].startswith("invalid") or e["id"] == "bad-stamp": continue
    d = DetachedTimestampFile.deserialize(StreamDeserializationContext(open(os.path.join(vec, e["id"], "proof.ots"), "rb")))
    found = []; walk(d.timestamp, [], found)
    for height, path in found:
        if height in blocks: continue
        txi = next((i for i, m in enumerate(path) if i > 0 and is_tx(m)), None)
        if txi is None: print("no tx in", e["id"], height); continue
        tx = path[txi]; txid = sha256d(tx)[::-1].hex()
        root = path[-1]
        hdr = mine(height, root); bh = sha256d(hdr)[::-1].hex()
        fakes = [hashlib.sha256(b"fake-%d-%d" % (height, k)).hexdigest() for k in range(5)]
        txids = fakes[:2] + [txid] + fakes[2:]
        raw = segwit_wrap(tx) if e["id"] == "gdp2q25" else tx
        for sc in ("synthetic",):
            put(sc, "block-height/%d" % height, bh)
            put(sc, "block/%s/header" % bh, hdr.hex())
            put(sc, "block/%s/txids" % bh, txids)
            put(sc, "tx/%s/hex" % txid, raw.hex())
        blocks[height] = (bh, txid, e["id"])
# a lying second server: same block hello-world, header with a different merkle root, correctly mined
h = 358391; bh, txid, _ = blocks[h]
good = bytes.fromhex(open(os.path.join(OUT, "synthetic", "block", bh, "header")).read())
lie = mine(h, hashlib.sha256(b"a different root").digest())
lbh = sha256d(lie)[::-1].hex()
put("synthetic-lying", "block-height/%d" % h, lbh)
put("synthetic-lying", "block/%s/header" % lbh, lie.hex())
json.dump({"note": "SYNTHETIC, not recorded from real servers", "blocks": {str(k): {"hash": v[0], "txid": v[1], "vector": v[2]} for k, v in sorted(blocks.items())}},
          open(os.path.join(OUT, "synthetic", "INDEX.json"), "w"), indent=1)
print(len(blocks), "synthetic blocks:", sorted(blocks))

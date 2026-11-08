#!/usr/bin/env python3
"""Record REAL Esplora responses for the Bitcoin vectors, once, on a machine that has network access.

    python3 tools/record_explorer.py --yes            # writes vectors/explorer/recorded-blockstream and recorded-mempool

It lists every URL first, calls each one at most once (GET only, 0.5 s apart), and refuses to
overwrite files that already exist. The tests (test/test_recorded.py, the JS and conformance runs)
pick the recordings up automatically. Standard library only.
"""
import argparse, json, os, sys, time, urllib.request, urllib.error
ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(ROOT, "python"))
import verify_ots as V

SERVERS = {"recorded-blockstream": "https://blockstream.info/api", "recorded-mempool": "https://mempool.space/api"}

def get(url):
    req = urllib.request.Request(url, headers={"User-Agent": "ots-explain-recorder/" + V.VERSION})
    with urllib.request.urlopen(req, timeout=30) as r: return r.read(8 << 20).decode()

def main():
    ap = argparse.ArgumentParser(); ap.add_argument("--yes", action="store_true"); a = ap.parse_args()
    with open(os.path.join(ROOT, "vectors", "index.json")) as f: index = json.load(f)["vectors"]
    wanted = {}
    for e in index:
        if e["id"].startswith("invalid") or e["id"] == "bad-stamp": continue
        with open(os.path.join(ROOT, "vectors", e["id"], "proof.ots"), "rb") as f: p = V.parse_proof(f.read())
        for at in p.atts:
            ph = V.phases(p, at)
            if at.kind == "bitcoin" and ph: wanted[at.height] = ph["txid"]
    print("heights:", sorted(wanted))
    for name, base in SERVERS.items():
        print(name, base, "-> 4 GETs per height: /block-height/H, /block/HASH/header, /block/HASH/txids, /tx/TXID/hex")
    if not a.yes: print("add --yes to go"); return 3
    for name, base in SERVERS.items():
        for h, txid in sorted(wanted.items()):
            def save(rel, text):
                p = os.path.join(ROOT, "vectors", "explorer", name, rel)
                if os.path.exists(p): return
                os.makedirs(os.path.dirname(p), exist_ok=True)
                with open(p, "w") as f: f.write(text)
            try:
                bh = get("%s/block-height/%d" % (base, h)).strip(); save("block-height/%d" % h, bh); time.sleep(.5)
                save("block/%s/header" % bh, get("%s/block/%s/header" % (base, bh)).strip()); time.sleep(.5)
                save("block/%s/txids" % bh, get("%s/block/%s/txids" % (base, bh))); time.sleep(.5)
                save("tx/%s/hex" % txid, get("%s/tx/%s/hex" % (base, txid)).strip()); time.sleep(.5)
                print("recorded", name, h)
            except (urllib.error.URLError, OSError) as e: print("FAILED", name, h, e)
    return 0

if __name__ == "__main__": sys.exit(main())

#!/usr/bin/env python3
"""LIVE check: run the real Bitcoin vectors against the real explorers (blockstream.info, mempool.space).

This is the one test the author could not run from his sandbox. It is what turns "works against synthetic data" into
"works against Bitcoin". GET requests only, 0.5 s apart; it lists them first and needs --yes.

    python3 tools/live_check.py            # lists the URLs and stops
    python3 tools/live_check.py --yes      # asks the two default servers about every Bitcoin vector

Exit code 0 only if every vector gets the verdict listed in EXPECTED (the real proofs PASS, bad-stamp FAILs on the
merkle root). A FAIL on a real proof usually means an Esplora response format the code did not expect: please open an
issue with the output.
"""
import argparse, json, os, sys, time
ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(ROOT, "python"))
import verify_ots as V

EXPECTED = {"hello-world": "PASS", "empty": "PASS", "osdsp": "PASS", "bitcoin-pdf": "PASS", "different-blockchains": "PASS", "gdp2q25": "PASS", "bad-stamp": "FAIL"}


def main():
    ap = argparse.ArgumentParser(); ap.add_argument("--yes", action="store_true"); ap.add_argument("--only", nargs="*"); a = ap.parse_args()
    ids = a.only or sorted(EXPECTED)
    fetch_real = V.http_fetch()
    urls = []

    def fetch(url):
        urls.append(url)
        if not a.yes: return 0, ""  # dry run: nothing is requested
        time.sleep(0.5)
        return fetch_real(url)

    rows = []
    for vid in ids:
        d = os.path.join(ROOT, "vectors", vid)
        proof = open(os.path.join(d, "proof.ots"), "rb").read()
        dp = os.path.join(d, "data.bin")
        file = V.FileInput.from_path(dp) if os.path.exists(dp) else None
        digest = None if file else V.parse_proof(proof).digest.hex()
        rep = V.build_report(proof, file=file, digest_hex=digest, ledger={"fetch": fetch, "servers": V.DEFAULT_SERVERS})
        rows.append((vid, rep))
    if not a.yes:
        print("would request (GET):"); [print("  " + u) for u in dict.fromkeys(urls)]
        print("\nadd --yes to go"); return 3
    bad = 0
    for vid, rep in rows:
        st = rep["verdict"]["status"]; ok = st == EXPECTED[vid]; bad += not ok
        det = []
        for att in (rep["ledger"] or {}).get("attestations", []):
            for sv in att["servers"]:
                det.append("%s:%s" % (sv["server"], sv["status"] if sv["status"] == "PASS" else ",".join("%s=%s" % (c["id"], c["code"]) for c in sv["checks"] if c["status"] != "PASS")))
        print("%-22s expected %s got %s %s  %s" % (vid, EXPECTED[vid], st, "OK " if ok else "MISMATCH", " ".join(det)))
    return 1 if bad else 0


if __name__ == "__main__": sys.exit(main())

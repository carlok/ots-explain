#!/usr/bin/env python3
"""Import the public example proofs from the three OpenTimestamps repos into
vectors/ (read-only copies, with provenance) and record the reference client's
`ots info` output next to each proof.

usage: import_vectors.py CLONES_DIR REF_OTS_BINARY OUT_VECTORS_DIR
CLONES_DIR holds javascript-opentimestamps/, opentimestamps-client/, java-opentimestamps/.
"""
import hashlib, json, os, shutil, subprocess, sys

clones, ots_bin, out = sys.argv[1:4]
J, C, V = "javascript-opentimestamps", "opentimestamps-client", "java-opentimestamps"

# id, repo, data-file (or None), proof, shipped .info (repo, path) or None, note
SPEC = [
 ("hello-world",        J, "examples/hello-world.txt", "examples/hello-world.txt.ots", None, "valid Bitcoin proof from 2015; first op is RIPEMD-160"),
 ("bad-stamp",          J, "examples/bad-stamp.txt", "examples/bad-stamp.txt.ots", None, "meant to fail"),
 ("empty",              J, "examples/empty", "examples/empty.ots", None, "zero-byte file"),
 ("incomplete",         J, "examples/incomplete.txt", "examples/incomplete.txt.ots", (J, "examples/incomplete.txt.ots.info"), "pending only"),
 ("merkle1",            J, "examples/merkle1.txt", "examples/merkle1.txt.ots", None, "merkle path"),
 ("merkle2",            J, "examples/merkle2.txt", "examples/merkle2.txt.ots", (J, "examples/merkle2.txt.ots.info"), "merkle path"),
 ("merkle3",            J, "examples/merkle3.txt", "examples/merkle3.txt.ots", None, "merkle path"),
 ("two-calendars",      J, "examples/two-calendars.txt", "examples/two-calendars.txt.ots", None, "two pending calendars"),
 ("known-and-unknown-notary", J, "examples/known-and-unknown-notary.txt", "examples/known-and-unknown-notary.txt.ots", None, "one known and one unknown attestation"),
 ("unknown-notary",     J, "examples/unknown-notary.txt", "examples/unknown-notary.txt.ots", None, "unknown attestation only"),
 ("osdsp",              J, "examples/osdsp.txt", "examples/osdsp.txt.ots", None, "extra example in the JS repo"),
 ("ripemd160-readme",   J, "examples/ripemd160/README.md", "examples/ripemd160/README.md.ots", None, "proof whose header names RIPEMD-160"),
 ("sha1-a",             J, "examples/sha1/a", "examples/sha1/a_or_b.ots", None, "SHA-1 header; file a of the shattered pair"),
 ("sha1-b",             J, "examples/sha1/b", "examples/sha1/a_or_b.ots", None, "SHA-1 header; file b of the shattered pair (same proof)"),
 ("different-blockchains", C, "examples/different-blockchains.txt", "examples/different-blockchains.txt.ots", (V, "examples/different-blockchains.txt.ots.info"), "Bitcoin and Litecoin"),
 ("eth",                V, "examples/hello-world.txt.eth", "examples/hello-world.txt.eth.ots", None, "Ethereum attestation (java repo)"),
 ("bitcoin-pdf",        C, None, "examples/bitcoin.pdf.ots", None, "long proof (about 100 levels); the PDF is not in the repo: proof-only"),
 ("gdp2q25",            C, None, "examples/gdp2q25-2nd.pdf.ots", None, "proof only; file not in the repo"),
 ("invalid-bad-major-version",      C, None, "examples/invalid/bad-major-version.ots", None, "must be rejected"),
 ("invalid-exceeds-max-msg-length", C, None, "examples/invalid/exceeds-max-msg-length.ots", None, "must be rejected"),
 ("invalid-file-digest-type",       C, None, "examples/invalid/invalid-file-digest-type.ots", None, "must be rejected"),
]

index = []
for vid, repo, data, proof, info, note in SPEC:
    d = os.path.join(out, vid); os.makedirs(d, exist_ok=True)
    entry = {"id": vid, "note": note, "source": {"repo": "opentimestamps/" + repo,
             "proof": proof, "data": data}}
    if data:
        shutil.copyfile(os.path.join(clones, repo, data), os.path.join(d, "data.bin"))
        entry["data_sha256"] = hashlib.sha256(open(os.path.join(d, "data.bin"), "rb").read()).hexdigest()
        entry["data_size"] = os.path.getsize(os.path.join(d, "data.bin"))
    shutil.copyfile(os.path.join(clones, repo, proof), os.path.join(d, "proof.ots"))
    entry["proof_sha256"] = hashlib.sha256(open(os.path.join(d, "proof.ots"), "rb").read()).hexdigest()
    if info:
        shutil.copyfile(os.path.join(clones, info[0], info[1]), os.path.join(d, "shipped.info"))
        entry["shipped_info"] = {"repo": "opentimestamps/" + info[0], "path": info[1]}
    r = subprocess.run([ots_bin, "info", os.path.join(d, "proof.ots")], capture_output=True, text=True)
    open(os.path.join(d, "reference.info.txt"), "w").write(r.stdout if r.returncode == 0 else "")
    entry["reference_ots_info"] = {"exit": r.returncode, "stderr": r.stderr.strip()[-300:]}
    index.append(entry)

json.dump({"vectors": index}, open(os.path.join(out, "index.json"), "w"), indent=1)
print(len(index), "vectors")

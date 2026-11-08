"""Differential fuzzing: mutate real and handcrafted proofs; both implementations must agree on every mutant and
neither may crash or hang. A disagreement here is a bug in one of them (or a spec gap): the report says which case.

OTS_FUZZ_N sets the number of mutants (default 1500), OTS_FUZZ_SEED the seed (default 1; print it when you fail).
"""
import json, os, random, shutil, subprocess, sys, tempfile, time, unittest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(ROOT, "python"))
import verify_ots as V

NODE = shutil.which("node")
INTERESTING = [0x00, 0x01, 0x02, 0x03, 0x08, 0x67, 0x7f, 0x80, 0xf0, 0xf1, 0xf2, 0xf3, 0xff]


def seeds():
    out = []
    idx = json.load(open(os.path.join(ROOT, "vectors", "index.json")))["vectors"]
    for e in idx: out.append(open(os.path.join(ROOT, "vectors", e["id"], "proof.ots"), "rb").read())
    hd = os.path.join(ROOT, "vectors", "handcrafted")
    for n in sorted(json.load(open(os.path.join(hd, "index.json")))): out.append(open(os.path.join(hd, n + ".ots"), "rb").read())
    return out


def mutate(rnd, data):
    b = bytearray(data)
    for _ in range(rnd.choice([1, 1, 1, 2, 3])):
        kind = rnd.randrange(7)
        if not b: b = bytearray(rnd.randbytes(rnd.randrange(1, 8))); continue
        i = rnd.randrange(len(b))
        if kind == 0: b[i] ^= 1 << rnd.randrange(8)
        elif kind == 1: b[i] = rnd.choice(INTERESTING)
        elif kind == 2: del b[i:i + rnd.randrange(1, 12)]
        elif kind == 3: b[i:i] = rnd.randbytes(rnd.randrange(1, 12))
        elif kind == 4: del b[i:]
        elif kind == 5:
            j = rnd.randrange(len(b)); b[i:i] = b[j:j + rnd.randrange(1, 40)]
        else: b[i:i + 1] = bytes([rnd.choice(INTERESTING)]) * rnd.randrange(1, 4)
    return bytes(b)


@unittest.skipUnless(NODE and os.path.isdir(os.path.join(ROOT, "node_modules", "esbuild")), "needs node and `npm install`")
class Fuzz(unittest.TestCase):
    def test_mutants_agree(self):
        n = int(os.environ.get("OTS_FUZZ_N", "1500")); seed = int(os.environ.get("OTS_FUZZ_SEED", "1"))
        rnd = random.Random(seed); base = seeds()
        tmp = tempfile.mkdtemp(prefix="ots-fuzz-")
        try:
            cases, pyout, slow = [], {}, []
            for k in range(n):
                data = mutate(rnd, rnd.choice(base))
                path = os.path.join(tmp, "m%05d.ots" % k); open(path, "wb").write(data)
                try: own = V.parse_proof(data).digest.hex()
                except V.OtsError: own = "00" * 32
                for mode, extra in (("none", {}), ("digest", {"digest": own})):
                    name = "m%05d.%s" % (k, mode); cases.append(dict({"name": name, "proof": path}, **extra))
                    t = time.time()
                    rep = V.build_report(data, digest_hex=extra.get("digest"))
                    if time.time() - t > 2: slow.append(name)
                    pyout[name] = V.canonical_json(rep) + "\n"
            man = os.path.join(tmp, "manifest.json"); json.dump(cases, open(man, "w"))
            out = os.path.join(tmp, "ts")
            r = subprocess.run([NODE, os.path.join(ROOT, "test", "js", "conformance-run.mjs"), man, out], capture_output=True, text=True, timeout=600)
            self.assertEqual(r.returncode, 0, r.stderr[-2000:])
            bad = [nm for nm in pyout if open(os.path.join(out, nm + ".json"), encoding="utf-8").read() != pyout[nm]]
            parsed = sum(1 for nm in pyout if json.loads(pyout[nm])["error"] is None and nm.endswith(".none"))
            codes = {}
            for nm in pyout:
                if nm.endswith(".none"):
                    e = json.loads(pyout[nm])["error"]; codes[e["code"] if e else "ok"] = codes.get(e["code"] if e else "ok", 0) + 1
            print("\nfuzz: seed %d, %d mutants x 2 modes, %d still parse, %d distinct outcomes %s, diffs %d, slow %d" % (seed, n, parsed, len(codes), json.dumps(codes, sort_keys=True), len(bad), len(slow)))
            self.assertEqual(slow, [], "cases slower than 2 s")
            self.assertEqual(bad, [], "implementations disagree (seed %d): %s" % (seed, bad[:10]))
            self.assertGreaterEqual(len(codes), 8, "the mutations should reach many different parse errors")
        finally:
            shutil.rmtree(tmp, ignore_errors=True)


if __name__ == "__main__":
    unittest.main()

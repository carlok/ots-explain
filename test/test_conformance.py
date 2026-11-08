"""The conformance test: two independent implementations of one spec must print the same bytes.

For every vector (the 21 imported ones and the 24 handcrafted ones) and every input mode (file, own digest, wrong
digest, malformed digest, proof only) and every ledger scenario (two agreeing mirrors, one honest and one lying,
one server only, a server that is down, a server that has never heard of the block), this builds the report with
python/verify_ots.py and with the TypeScript core (through test/js/conformance-run.mjs), then compares
  * the canonical JSON, byte for byte,
  * the text report, with and without --steps, byte for byte,
  * and the permalink encoder/decoder on every proof.
Run:  python3 -m unittest test.test_conformance -v     (needs node and `npm install` once)
"""
import json, os, shutil, subprocess, sys, tempfile, unittest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(ROOT, "python")); sys.path.insert(0, os.path.join(ROOT, "test"))
import verify_ots as V
import mock_esplora

NODE = shutil.which("node")


def cases(port):
    base = "http://127.0.0.1:%d" % port
    S = lambda name, scen: {"name": name, "base": base + "/" + scen}
    scen = {
        "agree": [S("mirror-a", "synthetic"), S("mirror-b", "synthetic")],
        "lying": [S("honest", "synthetic"), S("liar", "synthetic-lying")],
        "one": [S("only", "synthetic")],
        "down": [S("down", "down")],
        "unknown": [S("unknown", "nowhere")],
    }
    out, vecs = [], []
    idx = json.load(open(os.path.join(ROOT, "vectors", "index.json")))["vectors"]
    for e in idx:
        d = os.path.join(ROOT, "vectors", e["id"])
        vecs.append((e["id"], os.path.join(d, "proof.ots"), os.path.join(d, "data.bin") if os.path.exists(os.path.join(d, "data.bin")) else None))
    hd = os.path.join(ROOT, "vectors", "handcrafted")
    for name in sorted(json.load(open(os.path.join(hd, "index.json")))):
        vecs.append(("hc-" + name, os.path.join(hd, name + ".ots"), None))
    rd = os.path.join(ROOT, "vectors", "real")  # a real stamp made by tools/e2e_real.sh, before and after Bitcoin confirmed it
    for kind in ("pending", "confirmed"):
        vecs.append(("real-dummy-" + kind, os.path.join(rd, "dummy-2026-11-08." + kind + ".ots"), os.path.join(rd, "dummy-2026-11-08.bin")))
    for vid, proof, data in vecs:
        try: own = V.parse_proof(open(proof, "rb").read()).digest.hex()
        except V.OtsError: own = "00" * 32
        out.append({"name": vid + ".none", "proof": proof})
        if data: out.append({"name": vid + ".file", "proof": proof, "file": data})
        out.append({"name": vid + ".hc-file", "proof": proof, "file": proof})  # hash of the proof file itself: a mismatch
        out.append({"name": vid + ".digest", "proof": proof, "digest": own})
        out.append({"name": vid + ".digest-upper", "proof": proof, "digest": own.upper()})
        out.append({"name": vid + ".digest-wrong", "proof": proof, "digest": "ff" * 32})
        out.append({"name": vid + ".digest-bad", "proof": proof, "digest": "xyz"})
        for k, servers in scen.items():
            c = {"name": vid + ".ledger-" + k, "proof": proof, "servers": servers}
            if data: c["file"] = data
            else: c["digest"] = own
            out.append(c)
    return out


def py_report(c, fetch):
    proof = open(c["proof"], "rb").read()
    file = V.FileInput.from_bytes(open(c["file"], "rb").read()) if c.get("file") else None
    ledger = {"fetch": fetch, "servers": c["servers"]} if c.get("servers") else None
    return V.build_report(proof, file=file, digest_hex=c.get("digest"), ledger=ledger)


@unittest.skipUnless(NODE and os.path.isdir(os.path.join(ROOT, "node_modules", "esbuild")), "needs node and `npm install`")
class Conformance(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        os.environ["no_proxy"] = os.environ["NO_PROXY"] = "127.0.0.1,localhost"  # the mock is local; never go through a proxy
        cls.srv, port = mock_esplora.serve()
        cls.cases = cases(port)
        cls.tmp = tempfile.mkdtemp(prefix="ots-conf-")
        man = os.path.join(cls.tmp, "manifest.json")
        json.dump(cls.cases, open(man, "w"))
        cls.out = os.path.join(cls.tmp, "ts")
        r = subprocess.run([NODE, os.path.join(ROOT, "test", "js", "conformance-run.mjs"), man, cls.out], capture_output=True, text=True)
        if r.returncode: raise RuntimeError(r.stderr)
        cls.ran = r.stdout.strip()
        cls.diffs = {"json": 0, "text": 0, "steps": 0}
        cls.fetch = staticmethod(V.http_fetch())

    @classmethod
    def tearDownClass(cls):
        cls.srv.shutdown(); shutil.rmtree(cls.tmp, ignore_errors=True)
        print("\nconformance: %d cases, diffs: json %d, text %d, text --steps %d" % (len(cls.cases), cls.diffs["json"], cls.diffs["text"], cls.diffs["steps"]))

    def test_every_case_is_identical(self):
        bad = []
        verdicts = {}
        for c in self.cases:
            rep = py_report(c, self.fetch)
            verdicts[rep["verdict"]["status"]] = verdicts.get(rep["verdict"]["status"], 0) + 1
            for kind, suffix, mine in (("json", ".json", V.canonical_json(rep) + "\n"), ("text", ".txt", V.render_text(rep, False)), ("steps", ".steps.txt", V.render_text(rep, True))):
                theirs = open(os.path.join(self.out, c["name"] + suffix), encoding="utf-8").read()
                if mine != theirs:
                    type(self).diffs[kind] += 1
                    i = next((k for k, (a, b) in enumerate(zip(mine, theirs)) if a != b), min(len(mine), len(theirs)))
                    bad.append("%s %s @%d\n   py: %r\n   ts: %r" % (c["name"], kind, i, mine[max(0, i - 60):i + 80], theirs[max(0, i - 60):i + 80]))
        type(self).verdicts = verdicts
        self.assertEqual(bad, [], "\n" + "\n".join(bad[:12]) + "\n(%d diffs)" % len(bad))

    def test_the_comparison_can_fail(self):
        """A guard against a vacuous test: the cases cover every verdict and the runner really wrote files."""
        self.assertGreater(len(self.cases), 400)
        self.assertEqual(len(os.listdir(self.out)), 3 * len(self.cases))
        v = {py_report(c, self.fetch)["verdict"]["status"] for c in self.cases}
        self.assertEqual(v, {"PASS", "FAIL", "SKIP"})

    def test_permalinks(self):
        """Encoding in Python and TypeScript agree; each decodes the other's output."""
        lines = []
        for c in self.cases:
            if "." not in c["name"] or not c["name"].endswith(".digest"): continue
            proof = open(c["proof"], "rb").read()
            lines.append({"name": c["name"], "ots": proof.hex(), "digest": c["digest"]})
        man = os.path.join(self.tmp, "links.json"); json.dump(lines, open(man, "w"))
        script = os.path.join(self.tmp, "links.mjs")
        open(script, "w").write('''
import { readFileSync } from "node:fs";
const core = await import(process.argv[2]);
const out = {};
for (const c of JSON.parse(readFileSync(process.argv[3], "utf8"))) {
  const ots = Uint8Array.from(Buffer.from(c.ots, "hex"));
  const url = core.encodePermalink("https://example.org/x/", { digestHex: c.digest, ots, proofUrl: "https://a.example/p q.ots?x=1&y=é" });
  const d = core.decodePermalink(url);
  out[c.name] = { url, digest: d.digestHex, ots: Buffer.from(d.ots).toString("hex"), proofUrl: d.proofUrl };
}
console.log(JSON.stringify(out));''')
        r = subprocess.run([NODE, script, os.path.join(ROOT, "web", "build", "core.mjs"), man], capture_output=True, text=True)
        self.assertEqual(r.returncode, 0, r.stderr)
        ts = json.loads(r.stdout)
        for c in lines:
            proof = bytes.fromhex(c["ots"])
            url = V.encode_permalink("https://example.org/x/", c["digest"], proof, "https://a.example/p q.ots?x=1&y=é")
            self.assertEqual(url, ts[c["name"]]["url"], c["name"])
            d = V.decode_permalink(ts[c["name"]]["url"])
            self.assertEqual((d["h"], d["ots"], d["proof"]), (c["digest"], proof, "https://a.example/p q.ots?x=1&y=é"))
            self.assertEqual(ts[c["name"]]["ots"], c["ots"])


if __name__ == "__main__":
    unittest.main()

"""Unit tests for python/verify_ots.py (stdlib unittest). Written before the implementation."""
import hashlib, io, json, os, random, subprocess, sys, tempfile, unittest, contextlib

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(ROOT, "python")); sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import verify_ots as V
from schema_lite import validate

VEC = os.path.join(ROOT, "vectors")
def vec_bytes(vid, name):
    with open(os.path.join(VEC, vid, name), "rb") as f: return f.read()
def jload(*parts):
    with open(os.path.join(*parts)) as f: return json.load(f)
def tload(*parts):
    with open(os.path.join(*parts)) as f: return f.read()
SCHEMA = jload(ROOT, "spec", "report.schema.json")
INDEX = jload(VEC, "index.json")["vectors"]
MAGIC = bytes.fromhex("004f70656e54696d657374616d7073000050726f6f6600bf89e2e884e89294")
BTC, PEND = bytes.fromhex("0588960d73d71901"), bytes.fromhex("83dfe30d2ef90c8e")

def vu(n):
    out = bytearray()
    while True:
        b = n & 0x7f; n >>= 7
        out.append(b | (0x80 if n else 0))
        if not n: return bytes(out)
def vb(b): return vu(len(b)) + b
def att(tag, payload): return b"\x00" + tag + vb(payload)
def btc_att(h=1): return att(BTC, vu(h))
def proof(ts, op=b"\x08", digest=b"\x11" * 32, version=1): return MAGIC + bytes([version]) + op + digest + ts
def parse_err(data):
    with unittest.TestCase().assertRaises(V.OtsError) as c: V.parse_proof(data)
    return c.exception.code

class FileFetch:
    """Serves vectors/explorer/<scenario>/<path> like a server; absent file = 404."""
    def __init__(self, calls=None): self.calls = calls if calls is not None else []
    def __call__(self, url):
        self.calls.append(url)
        assert url.startswith("mock://")
        rel = url[len("mock://"):]
        if rel.startswith("down/"): raise OSError("connection refused")
        p = os.path.join(VEC, "explorer", rel)
        if os.path.isfile(p): return 200, tload(p)
        return 404, "Block not found"

class Hashes(unittest.TestCase):
    def test_standard_vectors(self):
        hv = jload(VEC, "hash-vectors.json")
        for alg, fn in (("sha256", V.sha256), ("sha1", V.sha1), ("ripemd160", V.ripemd160), ("keccak256", V.keccak256)):
            for h, d in hv[alg]: self.assertEqual(fn(bytes.fromhex(h)).hex(), d, alg)
    def test_boundaries_and_streaming(self):
        rnd = random.Random(1)
        for n in (0, 1, 55, 56, 63, 64, 65, 119, 120, 127, 128, 1000):
            data = bytes(rnd.randrange(256) for _ in range(n))
            self.assertEqual(V.sha256(data), hashlib.sha256(data).digest())
            self.assertEqual(V.sha1(data), hashlib.sha1(data).digest())
            if "ripemd160" in hashlib.algorithms_available:
                self.assertEqual(V.ripemd160(data), hashlib.new("ripemd160", data).digest())
            h = V.Hasher("sha256"); i = 0
            while i < n:
                j = i + rnd.randrange(1, 90); h.update(data[i:j]); i = j
            self.assertEqual(h.digest(), hashlib.sha256(data).digest())
    def test_pure_ripemd_and_keccak_long(self):
        # pure-python implementations must work regardless of the platform's hashlib
        self.assertEqual(V.ripemd160_pure(b"a" * 1000).hex(), V.ripemd160(b"a" * 1000).hex())
        try:
            from Cryptodome.Hash import keccak as K  # optional cross-check, not required
            self.assertEqual(V.keccak256(b"a" * 300), K.new(digest_bits=256, data=b"a" * 300).digest())
        except ImportError:
            pass
    def test_hasher_rejects_unknown(self):
        with self.assertRaises(ValueError): V.Hasher("md5")

class Varints(unittest.TestCase):
    def test_roundtrip_and_limits(self):
        for n in (0, 1, 127, 128, 300, 4096, 2**32, 2**56):
            self.assertEqual(V.read_varuint(io.BytesIO(vu(n))), n)
        self.assertEqual(parse_err(proof(b"\xf0" + b"\x80" * 9 + b"\x01")), "varuint_too_long")

class ParseErrors(unittest.TestCase):
    ok = proof(btc_att(7))
    def test_minimal_valid(self):
        p = V.parse_proof(self.ok)
        self.assertEqual((p.version, p.hash_op, len(p.nodes), p.atts[0].kind, p.atts[0].height), (1, "sha256", 1, "bitcoin", 7))
    def test_codes(self):
        cases = {
            "bad_magic": b"x" * 60,
            "unsupported_version": proof(btc_att(), version=2),
            "unknown_file_hash_op": proof(btc_att(), op=b"\x67"),
            "truncated": proof(btc_att(), digest=b"\x11" * 10)[:50],
            "trailing_garbage": self.ok + b"\x00",
            "unknown_op": proof(b"\xaa" + btc_att()),
            "repeated_op": proof(b"\xff\xf0\x01\xaa" + btc_att() + b"\xf0\x01\xaa" + btc_att()),
            "arg_length": proof(b"\xf0\x00" + btc_att()),
            "result_too_long": proof(b"\xf0" + vb(b"\xaa" * 4096) + btc_att()),
            "msg_too_long": proof(b"\xf0" + vb(b"\xaa" * 2100) + b"\xf3" + btc_att()),
            "varuint_too_long": proof(b"\xf0" + b"\x80" * 10 + b"\x01"),
            "payload_too_long": proof(att(b"\x01" * 8, b"\x00" * 8193)),
            "bad_attestation_payload": proof(att(BTC, vu(5) + b"\xff")),
            "bad_uri": proof(att(PEND, vb(b"http://a b"))),
            "height_too_large": proof(att(BTC, vu(2**32))),
            "recursion_limit": proof(b"\x08" * 256 + btc_att()),
        }
        for code, data in cases.items(): self.assertEqual(parse_err(data), code, code)
    def test_depth_255_ok(self):
        p = V.parse_proof(proof(b"\x08" * 255 + btc_att())); self.assertEqual(p.nodes[-1].id, 255)
    def test_truncated_everywhere(self):
        for n in range(len(self.ok)): 
            with self.assertRaises(V.OtsError): V.parse_proof(self.ok[:n])
    def test_unary_ops_and_limits(self):
        p = V.parse_proof(proof(b"\xf2" + btc_att(), digest=bytes(range(32))))
        self.assertEqual(p.nodes[1].digest, bytes(reversed(range(32))))
        p = V.parse_proof(proof(b"\xf3" + btc_att(), digest=b"\x01" * 32)); self.assertEqual(p.nodes[1].digest, b"01" * 32)
        with self.assertRaises(V.OtsError) as c: V.apply_op("reverse", None, b"")
        self.assertEqual(c.exception.code, "empty_message")
    def test_unknown_and_multiple_attestations(self):
        p = V.parse_proof(proof(b"\xff" + att(b"\x01\x02\x03\x04\x05\x06\x07\x08", b"zz") + b"\xff" + att(PEND, vb(b"https://a.example/x")) + att(BTC, vu(9))))
        self.assertEqual([a.kind for a in p.atts], ["unknown", "pending", "bitcoin"])
        self.assertEqual(p.atts[1].uri, "https://a.example/x"); self.assertEqual([a.index for a in p.atts], [0, 1, 2])
        self.assertEqual({a.kind for a in V.parse_proof(proof(att(bytes.fromhex("06869a0d73d71b45"), vu(3)))).atts}, {"litecoin"})
        self.assertEqual({a.kind for a in V.parse_proof(proof(att(bytes.fromhex("30fe8087b5c7ead7"), vu(3)))).atts}, {"ethereum"})

class Vectors(unittest.TestCase):
    def test_every_vector_against_reference_tree(self):
        n = 0
        for e in INDEX:
            ref = jload(VEC, e["id"], "reference.tree.json")
            data = vec_bytes(e["id"], "proof.ots")
            if not ref["valid"]:
                want = {"invalid-bad-major-version": "unsupported_version", "invalid-exceeds-max-msg-length": "result_too_long",
                        "invalid-file-digest-type": "unknown_file_hash_op"}[e["id"]]
                self.assertEqual(parse_err(data), want, e["id"]); continue
            p = V.parse_proof(data); n += 1
            self.assertEqual(p.hash_op, ref["file_hash_op"]); self.assertEqual(p.digest.hex(), ref["digest"])
            edges = sorted([p.nodes[x.parent].digest.hex(), x.op, x.arg.hex() if x.arg else None, x.digest.hex()] for x in p.nodes[1:])
            self.assertEqual(edges, ref["edges"], e["id"])
            def val(a): return a.height if a.height is not None else (a.uri if a.uri is not None else a.tag.hex() + ":" + a.payload.hex())
            atts = sorted([[p.nodes[a.node].digest.hex(), a.kind, val(a)] for a in p.atts], key=lambda x: [str(y) for y in x])
            self.assertEqual(atts, ref["attestations"], e["id"])
        self.assertEqual(n, 18)
    def test_file_hash_matches_for_vectors_with_data(self):
        for e in INDEX:
            if "data_sha256" not in e or e["id"] in ("ripemd160-readme",): continue
            p = V.parse_proof(vec_bytes(e["id"], "proof.ots"))
            h = V.Hasher(p.hash_op); h.update(vec_bytes(e["id"], "data.bin"))
            self.assertEqual(h.digest(), p.digest, e["id"])
    def test_hello_world_phases(self):
        p = V.parse_proof(vec_bytes("hello-world", "proof.ots")); a = p.atts[0]
        ph = V.phases(p, a)
        self.assertEqual((ph["commitment_index"], ph["transaction_index"], ph["txid_index"]), (1, 3, 5))
        self.assertEqual(ph["txid"], "7e9f0f7d9daa2d9e51b2e22f4abe814c3f90539afa778a9bef88dc64627cb2ec")
        self.assertEqual(ph["output"]["kind"], "p2pkh"); self.assertEqual(ph["root_index"], len(ph["path"]) - 1)
        self.assertEqual(p.nodes[ph["path"][-1]].digest.hex(), "007ee445d23ad061af4a36b809501fab1ac4f2d7e7a739817dd0cbb7ec661b8a")
    def test_phases_all_bitcoin_vectors(self):
        got = {}
        for e in INDEX:
            if e["id"].startswith("invalid"): continue
            p = V.parse_proof(vec_bytes(e["id"], "proof.ots"))
            for a in p.atts:
                if a.kind == "bitcoin":
                    ph = V.phases(p, a); got[(e["id"], a.height)] = None if ph is None else (ph["output"] or {}).get("kind")
        self.assertTrue(got); self.assertTrue(all(v is not None for v in got.values()), got)
    def test_no_transaction(self):
        p = V.parse_proof(proof(b"\x08" + btc_att())); self.assertIsNone(V.phases(p, p.atts[0]))

class Tx(unittest.TestCase):
    def test_strip_and_classify(self):
        p = V.parse_proof(vec_bytes("gdp2q25", "proof.ots")); ph = V.phases(p, p.atts[0])
        tx = p.nodes[ph["path"][ph["transaction_index"]]].digest
        wrapped = bytes.fromhex(tload(VEC, "explorer", "synthetic", "tx", ph["txid"], "hex"))
        self.assertNotEqual(wrapped, tx); self.assertEqual(wrapped[4:6], b"\x00\x01")
        self.assertEqual(V.strip_witness(wrapped), tx); self.assertEqual(V.strip_witness(tx), tx)
        self.assertIsNone(V.parse_tx(wrapped)); self.assertIsNotNone(V.parse_tx(tx))
    def test_classify(self):
        c = b"\xab" * 20
        self.assertEqual(V.classify_script(b"\x6a\x14" + c, c), "op_return")
        self.assertEqual(V.classify_script(b"\xa9\x14" + c + b"\x87", c), "p2sh")
        self.assertEqual(V.classify_script(b"\x76\xa9\x14" + c + b"\x88\xac", c), "p2pkh")
        self.assertEqual(V.classify_script(b"\x51" + c, c), "other")
    def test_pow_and_target(self):
        hdr = bytes.fromhex(tload(VEC, "explorer", "synthetic", "block", jload(VEC, "explorer", "synthetic", "INDEX.json")["blocks"]["358391"]["hash"], "header"))
        self.assertTrue(V.pow_ok(hdr)); self.assertFalse(V.pow_ok(hdr[:72] + bytes.fromhex("ffff7f1f") + hdr[76:]) and V.pow_ok(hdr[:72] + b"\x01\x00\x00\x03" + hdr[76:]))
        self.assertEqual(V.compact_target(0x1d00ffff), 0xffff * 2 ** (8 * (0x1d - 3)))

class Canonical(unittest.TestCase):
    def test_form(self):
        self.assertEqual(V.canonical_json({"b": [1, None, True, False], "a": "x\"\\\n\x01"}), '{"a":"x\\"\\\\\\n\\u0001","b":[1,null,true,false]}')

class Permalink(unittest.TestCase):
    def test_roundtrip(self):
        ots = vec_bytes("empty", "proof.ots"); d = "ab" * 32
        for base, purl in (("https://x.example/v/", None), ("file:///tmp/index.html", "https://h.example/a b.ots")):
            u = V.encode_permalink(base, d, ots, purl)
            self.assertEqual(V.decode_permalink(u), {"h": d, "ots": ots, "proof": purl})
        self.assertEqual(V.encode_permalink("https://x/", None, None, None), "https://x/")
        self.assertEqual(V.encode_permalink("https://x/", d, None, None), "https://x/#h=" + d)
        self.assertEqual(V.decode_permalink("https://x/#zz=1&h=" + d), {"h": d, "ots": None, "proof": None})
        self.assertNotIn("=", V.encode_permalink("https://x/", None, b"\xff\xfe", None).split("ots=")[1])

class Reports(unittest.TestCase):
    def rep(self, vid, mode="file", ledger=None):
        data = vec_bytes(vid, "proof.ots"); kw = {}
        if mode == "file": kw["file"] = V.FileInput.from_bytes(vec_bytes(vid, "data.bin"))
        elif mode == "digest": kw["digest_hex"] = jload(VEC, vid, "reference.tree.json")["digest"]
        r = V.build_report(data, ledger=ledger, **kw)
        self.assertEqual(validate(r, SCHEMA), [], vid)
        return r
    def codes(self, r): return [(s["id"], s["status"], s["code"]) for s in r["steps"]]
    def test_file_pass_offline(self):
        r = self.rep("hello-world")
        self.assertEqual(self.codes(r), [("file_hash", "PASS", "ok"), ("structure", "PASS", "ok"), ("hash_steps", "PASS", "ok"), ("ledger", "SKIP", "not_requested"), ("verdict", "SKIP", "incomplete")])
        self.assertIsNone(r["ledger"]); self.assertEqual(r["input"]["mode"], "file")
    def test_mismatch(self):
        r = V.build_report(vec_bytes("hello-world", "proof.ots"), file=V.FileInput.from_bytes(b"other"))
        self.assertEqual(self.codes(r)[:3], [("file_hash", "FAIL", "mismatch"), ("structure", "PASS", "ok"), ("hash_steps", "SKIP", "not_tied")]); self.assertEqual(r["verdict"]["code"], "failed")
    def test_modes(self):
        self.assertEqual(self.rep("merkle1", "digest")["steps"][0]["code"], "ok")
        r = self.rep("merkle1", "none"); self.assertEqual(r["steps"][0]["code"], "no_input"); self.assertEqual(r["steps"][2]["code"], "not_tied")
        r = V.build_report(vec_bytes("merkle1", "proof.ots"), digest_hex="zz"); self.assertEqual(r["steps"][0], {"id": "file_hash", "title": "File to hash", "status": "FAIL", "code": "bad_digest"})
        r = V.build_report(vec_bytes("merkle1", "proof.ots"), digest_hex="ab" * 4); self.assertEqual(r["steps"][0]["code"], "bad_digest")
        r = V.build_report(vec_bytes("merkle1", "proof.ots"), digest_hex=("AB" * 32)); self.assertEqual(r["steps"][0]["code"], "mismatch"); self.assertEqual(r["input"]["digest"], "ab" * 32)
    def test_ripemd_header(self):
        r = self.rep("ripemd160-readme", "file"); self.assertEqual(r["steps"][0]["code"], "alg_unsupported"); self.assertIsNone(r["input"]["digest"])
        r = self.rep("ripemd160-readme", "digest"); self.assertEqual(r["steps"][0]["code"], "ok")
    def test_unparsable(self):
        r = V.build_report(b"junk", file=V.FileInput.from_bytes(b"x"))
        self.assertEqual(self.codes(r)[:3], [("file_hash", "SKIP", "no_proof"), ("structure", "FAIL", "bad_magic"), ("hash_steps", "SKIP", "no_proof")])
        self.assertEqual(r["error"], {"code": "bad_magic"}); self.assertIsNone(r["proof"]); self.assertEqual(validate(r, SCHEMA), [])
        r = V.build_report(b"junk", ledger={"fetch": FileFetch()}); self.assertEqual(r["steps"][3]["code"], "no_proof")
    def test_pending_only(self):
        r = self.rep("incomplete", ledger={"servers": [{"name": "s", "base": "mock://synthetic"}], "fetch": FileFetch()})
        self.assertEqual((r["steps"][3]["status"], r["steps"][3]["code"]), ("SKIP", "no_bitcoin")); self.assertEqual(r["verdict"]["unverified"], [0]); self.assertIsNone(r["ledger"])
    def test_ledger_pass(self):
        calls = []
        led = {"servers": [{"name": "blockstream.info", "base": "mock://synthetic"}, {"name": "mempool.space", "base": "mock://synthetic"}], "fetch": FileFetch(calls)}
        r = self.rep("hello-world", ledger=led)
        self.assertEqual(self.codes(r)[3:], [("ledger", "PASS", "ok"), ("verdict", "PASS", "proved")])
        self.assertEqual(r["verdict"]["block"], 358391); self.assertEqual(r["verdict"]["time"], 1400000000 + 358391 * 600)
        a = r["ledger"]["attestations"][0]; self.assertTrue(a["agree"]); self.assertEqual(len(a["servers"]), 2)
        self.assertEqual([c["id"] for c in a["servers"][0]["checks"]], ["block_hash", "header", "merkle_root", "txids", "raw_tx", "output"])
        self.assertEqual(len(calls), 8); self.assertEqual(len(r["ledger"]["plan"]), 8)
        self.assertTrue(r["ledger"]["plan"][0]["url"].endswith("/block-height/358391")); self.assertIn("{block_hash}", r["ledger"]["plan"][1]["url"])
        self.assertEqual([w["kind"] for w in r["proof"]["attestations"][0]["where_to_look"]], ["block", "tx", "raw_hex"] * 2)
    def test_ledger_other_vectors_pass(self):
        led = lambda: {"servers": [{"name": "a", "base": "mock://synthetic"}], "fetch": FileFetch()}
        for vid in ("empty", "sha1-a", "osdsp", "different-blockchains", "bitcoin-pdf", "gdp2q25"):
            r = self.rep(vid, "digest", ledger=led()); self.assertEqual(r["steps"][3]["status"], "PASS", vid)
        r = self.rep("different-blockchains", "file", ledger=led()); self.assertEqual(r["verdict"]["status"], "PASS"); self.assertEqual(len(r["verdict"]["unverified"]), 3)
    def test_bad_stamp_fails_merkle_root(self):
        r = self.rep("bad-stamp", ledger={"servers": [{"name": "a", "base": "mock://synthetic"}], "fetch": FileFetch()})
        chk = {c["id"]: (c["status"], c["code"]) for c in r["ledger"]["attestations"][0]["servers"][0]["checks"]}
        self.assertEqual(chk["header"], ("PASS", "ok")); self.assertEqual(chk["merkle_root"], ("FAIL", "mismatch")); self.assertEqual(chk["txids"], ("SKIP", "not_run"))
        self.assertEqual(self.codes(r)[3:], [("ledger", "FAIL", "check_failed"), ("verdict", "FAIL", "failed")]); self.assertIsNone(r["verdict"]["block"])
    def test_lying_server_disagrees(self):
        r = self.rep("hello-world", ledger={"servers": [{"name": "a", "base": "mock://synthetic"}, {"name": "b", "base": "mock://synthetic-lying"}], "fetch": FileFetch()})
        self.assertFalse(r["ledger"]["attestations"][0]["agree"]); self.assertEqual(r["steps"][3]["status"], "FAIL")
    def test_not_found_and_unreachable(self):
        r = self.rep("hello-world", ledger={"servers": [{"name": "a", "base": "mock://nothing"}], "fetch": FileFetch()})
        self.assertEqual(r["ledger"]["attestations"][0]["servers"][0]["checks"][0], {"id": "block_hash", "status": "FAIL", "code": "not_found"})
        r = self.rep("hello-world", ledger={"servers": [{"name": "a", "base": "mock://down"}], "fetch": FileFetch()})
        self.assertEqual(r["ledger"]["attestations"][0]["servers"][0]["checks"][0]["code"], "unreachable"); self.assertEqual((r["steps"][3]["status"], r["steps"][3]["code"]), ("SKIP", "incomplete"))
    def test_bad_responses(self):
        def mk(mut):
            def f(url):
                s, b = FileFetch()(url)
                return mut(url, s, b)
            return {"servers": [{"name": "a", "base": "mock://synthetic"}], "fetch": f}
        for name, mut, check, code in (
            ("hash", lambda u, s, b: (200, "xyz") if "block-height" in u else (s, b), "block_hash", "bad_response"),
            ("header", lambda u, s, b: (200, "00" * 80) if u.endswith("/header") else (s, b), "header", "bad_hash"),
            ("header-len", lambda u, s, b: (200, "00") if u.endswith("/header") else (s, b), "header", "bad_response"),
            ("txids", lambda u, s, b: (200, "{}") if u.endswith("/txids") else (s, b), "txids", "bad_response"),
            ("txids-missing", lambda u, s, b: (200, "[]") if u.endswith("/txids") else (s, b), "txids", "not_in_block"),
            ("rawtx", lambda u, s, b: (200, "00") if u.endswith("/hex") else (s, b), "raw_tx", "mismatch"),
            ("rawtx-bad", lambda u, s, b: (200, "nothex") if u.endswith("/hex") else (s, b), "raw_tx", "bad_response"),
            ("500", lambda u, s, b: (500, "") if "block-height" in u else (s, b), "block_hash", "unreachable")):
            r = self.rep("hello-world", ledger=mk(mut)); c = {x["id"]: x["code"] for x in r["ledger"]["attestations"][0]["servers"][0]["checks"]}
            self.assertEqual(c[check], code, name)
    def test_bad_pow(self):
        def f(url):
            s, b = FileFetch()(url)
            if url.endswith("/header"): b = b[:152] + "00000000"  # nonce zeroed: hash no longer matches
            return s, b
        r = self.rep("hello-world", ledger={"servers": [{"name": "a", "base": "mock://synthetic"}], "fetch": f})
        self.assertIn(r["ledger"]["attestations"][0]["servers"][0]["checks"][1]["code"], ("bad_hash", "bad_pow"))
    def test_deterministic_and_canonical(self):
        a = V.canonical_json(self.rep("osdsp")); b = V.canonical_json(self.rep("osdsp")); self.assertEqual(a, b); self.assertNotIn(" ", a.replace("File to hash", "").replace("Proof structure", "").replace("Hash steps", "").replace("The ledger", ""))

class Cli(unittest.TestCase):
    SCRIPT = os.path.join(ROOT, "python", "verify_ots.py")
    def run_cli(self, *args, stdin=None):
        return subprocess.run([sys.executable, "-I", self.SCRIPT, *args], capture_output=True, text=True, input=stdin, timeout=60)
    def d(self, vid): return os.path.join(VEC, vid)
    def test_json_offline_exit3(self):
        r = self.run_cli(os.path.join(self.d("hello-world"), "data.bin"), os.path.join(self.d("hello-world"), "proof.ots"), "--offline", "--json")
        self.assertEqual(r.returncode, 3, r.stderr); j = json.loads(r.stdout); self.assertEqual(validate(j, SCHEMA), []); self.assertTrue(r.stdout.endswith("}\n"))
        self.assertEqual(r.stdout[:-1], V.canonical_json(j))
    def test_exit_codes_and_text(self):
        r = self.run_cli("--digest", "00" * 32, os.path.join(self.d("hello-world"), "proof.ots"), "--offline"); self.assertEqual(r.returncode, 1)
        self.assertIn("File to hash", r.stdout); self.assertIn("FAIL", r.stdout)
        r = self.run_cli("--offline", "nonexistent.txt", os.path.join(self.d("hello-world"), "proof.ots")); self.assertEqual(r.returncode, 2)
        r = self.run_cli(); self.assertEqual(r.returncode, 2)
        r = self.run_cli(os.path.join(self.d("hello-world"), "data.bin"), os.path.join(self.d("hello-world"), "proof.ots"), "--offline", "--steps")
        self.assertIn("007ee445d23ad061af4a36b809501fab1ac4f2d7e7a739817dd0cbb7ec661b8a", r.stdout); self.assertIn("calendar", r.stdout.lower())
    def test_proof_only_and_nonparsable(self):
        r = self.run_cli(os.path.join(self.d("incomplete"), "proof.ots"), "--offline"); self.assertEqual(r.returncode, 3); self.assertIn("pending", r.stdout.lower())
        r = self.run_cli(os.path.join(self.d("invalid-bad-major-version"), "proof.ots"), "--offline"); self.assertEqual(r.returncode, 1); self.assertIn("unsupported_version", r.stdout)
    def test_no_network_without_consent(self):
        # non-interactive and no --yes: must not call out; shows the URLs it would use
        r = self.run_cli(os.path.join(self.d("hello-world"), "data.bin"), os.path.join(self.d("hello-world"), "proof.ots"), stdin="")
        self.assertEqual(r.returncode, 3); self.assertIn("https://blockstream.info/api/block-height/358391", r.stdout + r.stderr)
    def test_link(self):
        r = self.run_cli("--digest", "ab" * 32, os.path.join(self.d("incomplete"), "proof.ots"), "--offline", "--link", "https://x.example/v/")
        self.assertIn("https://x.example/v/#h=" + "ab" * 32 + "&ots=", r.stdout)

class Main(unittest.TestCase):
    def test_main_returns_int(self):
        out = io.StringIO()
        with contextlib.redirect_stdout(out):
            rc = V.main(["--offline", "--digest", "00" * 32, os.path.join(VEC, "incomplete", "proof.ots")])
        self.assertEqual(rc, 1)

if __name__ == "__main__":
    unittest.main()

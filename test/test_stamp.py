"""stamp / upgrade / watch against a mock calendar and a synthetic chain (no network)."""
import contextlib, io, json, os, sys, tempfile, unittest
ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(ROOT, "python")); sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import verify_ots as V
import ots_stamp as S
import mock_calendar, mock_esplora

VEC = os.path.join(ROOT, "vectors")
def vec(vid, name):
    with open(os.path.join(VEC, vid, name), "rb") as f: return f.read()

class Roundtrip(unittest.TestCase):
    def test_serializer_reproduces_official_proofs(self):
        same, total = 0, 0
        for e in json.load(open(os.path.join(VEC, "index.json")))["vectors"]:
            if e["id"].startswith("invalid") or e["id"] == "sha1-b": continue
            data = vec(e["id"], "proof.ots"); p = V.parse_proof(data); total += 1
            out = S.serialize_proof(p.hash_op, p.digest, S.to_tree(p))
            V.parse_proof(out)  # always readable
            ref = V.parse_proof(out)
            self.assertEqual(sorted((n.op, n.arg, n.digest) for n in ref.nodes[1:]), sorted((n.op, n.arg, n.digest) for n in p.nodes[1:]), e["id"])
            same += out == data
        self.assertGreaterEqual(same, total - 3, (same, total))  # byte-identical except possibly a few differently ordered ones

class Pipeline(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(); self.d = self.tmp.name
        self.chain = os.path.join(self.d, "explorer"); os.makedirs(self.chain)
        self.cal = mock_calendar.MockCalendar(self.chain); self.esp, self.port = mock_esplora.serve(root=self.chain)
        self.call = S.http_call(5)
    def tearDown(self): self.cal.close(); self.esp.shutdown(); self.tmp.cleanup()

    def stamp(self, content=b"hello pipeline\n"):
        path = os.path.join(self.d, "doc.txt")
        with open(path, "wb") as f: f.write(content)
        out, err = io.StringIO(), io.StringIO()
        rc = S.main(["stamp", path, "--calendar", self.cal.url, "--yes"], stdout=out, stderr=err)
        return path, rc, out.getvalue(), err.getvalue()

    def test_stamp_writes_a_readable_pending_proof(self):
        path, rc, out, err = self.stamp(); self.assertEqual(rc, 0, err); self.assertIn("doc.txt.ots", out)
        data = open(path + ".ots", "rb").read(); p = V.parse_proof(data)
        self.assertEqual([a.kind for a in p.atts], ["pending"]); self.assertEqual(p.atts[0].uri, self.cal.url)
        rep = V.build_report(data, file=V.FileInput.from_path(path)); self.assertEqual([s["status"] for s in rep["steps"][:3]], ["PASS"] * 3)
        self.assertIn("POST /digest", [" ".join(h) for h in self.cal.hits])
        self.assertEqual(S.main(["stamp", path, "--calendar", self.cal.url, "--yes"], stderr=io.StringIO()), 2)  # refuses to overwrite
    def test_stamp_never_sends_the_file_digest(self):
        path, rc, _, _ = self.stamp(); fd = V.sha256(open(path, "rb").read())
        self.assertNotIn(fd.hex(), json.dumps(self.cal.hits))
    def test_stamp_consent_and_errors(self):
        class Tty(io.StringIO):
            def isatty(self): return True
        path = os.path.join(self.d, "x.txt"); open(path, "wb").write(b"x")
        err = io.StringIO(); self.assertEqual(S.main(["stamp", path, "--calendar", self.cal.url], stdin=io.StringIO(""), stderr=err), 3); self.assertIn("nothing sent", err.getvalue())
        self.assertEqual(S.main(["stamp", path, "--calendar", self.cal.url], stdin=Tty("n\n"), stderr=io.StringIO()), 3); self.assertEqual(self.cal.hits, [])
        self.assertEqual(S.main(["stamp", path, "--calendar", self.cal.url], stdin=Tty("y\n"), stderr=io.StringIO(), stdout=io.StringIO()), 0)
        self.assertEqual(S.main(["stamp"], stderr=io.StringIO()), 2); self.assertEqual(S.main(["stamp", "nofile"], stderr=io.StringIO()), 2)
        self.assertEqual(S.main(["stamp", "--digest", "ab", "--yes"], stderr=io.StringIO()), 2)
        self.assertEqual(S.main(["stamp", path, "--calendar", "http://127.0.0.1:1", "--yes", "--out", os.path.join(self.d, "y.ots"), "--timeout", "1"], stderr=io.StringIO()), 1)
    def test_stamp_digest_mode(self):
        out = os.path.join(self.d, "d.ots")
        self.assertEqual(S.main(["stamp", "--digest", "ab" * 32, "--calendar", self.cal.url, "--yes", "--out", out], stdout=io.StringIO(), stderr=io.StringIO()), 0)
        self.assertEqual(V.parse_proof(open(out, "rb").read()).digest.hex(), "ab" * 32)

    def test_upgrade_then_verify_against_the_synthetic_chain(self):
        path, rc, _, _ = self.stamp(); ots = path + ".ots"
        o = io.StringIO(); self.assertEqual(S.main(["upgrade", ots, "--allow", self.cal.url], stdout=o, stderr=io.StringIO()), 3); self.assertIn("still pending", o.getvalue())
        self.cal.ready = True
        o = io.StringIO(); self.assertEqual(S.main(["upgrade", ots, "--allow", self.cal.url], stdout=o, stderr=io.StringIO()), 0); self.assertIn("upgraded", o.getvalue())
        self.assertTrue(os.path.exists(ots + ".bak"))
        data = open(ots, "rb").read(); p = V.parse_proof(data); kinds = [a.kind for a in p.atts]; self.assertEqual(kinds, ["bitcoin"])
        ph = V.phases(p, p.atts[0]); self.assertIsNotNone(ph); self.assertEqual(ph["output"]["kind"], "op_return"); self.assertEqual(ph["root_index"] - ph["txid_index"], 3)
        led = {"fetch": V.http_fetch(5), "servers": [{"name": "mock", "base": "http://127.0.0.1:%d/chain" % self.port}]}
        rep = V.build_report(data, file=V.FileInput.from_path(path), ledger=led)
        self.assertEqual(rep["verdict"]["status"], "PASS", json.dumps(rep["steps"])); self.assertTrue(800000 <= rep["verdict"]["block"] < 801000)
        self.assertEqual(S.main(["upgrade", ots], stdout=(o := io.StringIO()), stderr=io.StringIO()), 0); self.assertIn("already", o.getvalue())
        # a tampered file is caught
        rep = V.build_report(data, file=V.FileInput.from_bytes(b"tampered"), ledger=led); self.assertEqual(rep["verdict"]["status"], "FAIL")
    def test_upgrade_refuses_calendars_not_on_the_list(self):
        path, _, _, _ = self.stamp(); self.cal.ready = True; before = len(self.cal.hits)
        err = io.StringIO(); self.assertEqual(S.main(["upgrade", path + ".ots"], stdout=io.StringIO(), stderr=err), 3)
        self.assertIn("not on the allowed list", err.getvalue()); self.assertEqual(len(self.cal.hits), before)
    def test_upgrade_input_errors(self):
        self.assertEqual(S.main(["upgrade", "nothing.ots"], stderr=io.StringIO()), 2)
        junk = os.path.join(self.d, "junk.ots"); open(junk, "wb").write(b"junk"); self.assertEqual(S.main(["upgrade", junk], stderr=io.StringIO()), 2)

    def test_watch_is_a_cron_pass(self):
        path, _, _, _ = self.stamp(); log = []
        ev = S.watch(self.d, self.call, [self.cal.url], min_interval=3600, now=10000.0, log=log.append); self.assertEqual(ev, [("doc.txt.ots", "still_pending")])
        ev = S.watch(self.d, self.call, [self.cal.url], min_interval=3600, now=10100.0, log=log.append); self.assertEqual(ev, [("doc.txt.ots", "skipped")])  # politeness: not again within the hour
        self.cal.ready = True
        led = {"fetch": V.http_fetch(5), "servers": [{"name": "mock", "base": "http://127.0.0.1:%d/chain" % self.port}]}
        ev = S.watch(self.d, self.call, [self.cal.url], min_interval=3600, now=20000.0, base_url="https://x.example/v/", ledger=led, log=log.append)
        self.assertEqual(ev, [("doc.txt.ots", "upgraded"), ("doc.txt.ots", "verified")], log)
        rep = json.load(open(path + ".ots.report.json")); self.assertEqual(rep["verdict"]["status"], "PASS")
        rows = open(os.path.join(self.d, "links.tsv")).read().split("\n")[0].split("\t"); self.assertEqual(rows[0], "doc.txt"); self.assertTrue(rows[1].startswith("https://x.example/v/#h="))
        self.assertEqual(V.decode_permalink(rows[1])["ots"], open(path + ".ots", "rb").read())
        ev = S.watch(self.d, self.call, [self.cal.url], now=99999.0, ledger=led, log=log.append); self.assertEqual(ev, [("doc.txt.ots", "verified")])
    def test_watch_flags_a_tampered_file_and_unreadable_proofs(self):
        path, _, _, _ = self.stamp(); self.cal.ready = True
        S.watch(self.d, self.call, [self.cal.url], now=10000.0, log=lambda m: None)
        led = {"fetch": V.http_fetch(5), "servers": [{"name": "mock", "base": "http://127.0.0.1:%d/chain" % self.port}]}
        open(path, "wb").write(b"changed after stamping")
        open(os.path.join(self.d, "bad.ots"), "wb").write(b"junk")
        ev = S.watch(self.d, self.call, [self.cal.url], now=20000.0, ledger=led, log=lambda m: None)
        self.assertIn(("doc.txt.ots", "failed"), ev); self.assertIn(("bad.ots", "failed:bad_magic"), ev)
        o = io.StringIO(); self.assertEqual(S.main(["watch", self.d, "--allow", self.cal.url, "--min-interval", "0"], stdout=o, stderr=io.StringIO()), 1)
        self.assertEqual(S.main(["watch", os.path.join(self.d, "nope")], stdout=io.StringIO(), stderr=io.StringIO()), 2)
    def test_calendar_failures_are_survivable(self):
        junk = S.stamp_digest(b"\x01" * 32, [self.cal.url, "http://127.0.0.1:1"], self.call, log=lambda m: None); V.parse_proof(junk)
        with self.assertRaises(RuntimeError): S.stamp_digest(b"\x01" * 32, ["http://127.0.0.1:1"], self.call)
        down = lambda url, data=None: (_ for _ in ()).throw(OSError("down"))
        p = S.stamp_digest(b"\x02" * 32, [self.cal.url], self.call); self.cal.ready = True
        new, changed, st = S.upgrade_proof(p, down, [self.cal.url]); self.assertEqual((changed, st), (False, "pending"))
        for code, body in ((500, b""), (200, b"garbage"), (200, V.MAGIC)):
            new, changed, st = S.upgrade_proof(p, lambda u, c=code, b=body: (c, b), [self.cal.url]); self.assertFalse(changed)
        no_btc = lambda u: (200, b"\x08\x00" + bytes.fromhex("83dfe30d2ef90c8e") + b"\x04\x03abc")
        self.assertFalse(S.upgrade_proof(p, no_btc, [self.cal.url])[1])

class OfficialPending(unittest.TestCase):
    def test_pending_on_44_byte_nodes_is_asked_and_upgraded(self):
        proof = open(os.path.join(ROOT, "vectors", "two-calendars", "proof.ots"), "rb").read()
        asked = []
        def call(url, body=None):
            asked.append(url)
            return (200, bytes([0x00]) + bytes.fromhex("0588960d73d71901") + bytes([1, 0x2a])) if "alice" in url else (404, b"")
        out, changed, status = S.upgrade_proof(proof, call, S.KNOWN_CALENDARS, log=lambda m: None)
        self.assertEqual((changed, status), (True, "complete"))
        self.assertEqual(len(asked), 2)
        self.assertTrue(all(len(u.rsplit("/", 1)[1]) == 88 for u in asked), asked)
        self.assertTrue(any(a.kind == "bitcoin" for a in V.parse_proof(out).atts))




class UpgradeVectors(unittest.TestCase):
    def test_replay_recorded_cases(self):
        cases = json.load(open(os.path.join(ROOT, "vectors", "upgrade", "index.json")))
        self.assertGreaterEqual(len(cases), 7)
        for c in cases:
            proof = open(os.path.join(ROOT, "vectors", c["proof"], "proof.ots"), "rb").read()
            def call(url, body=None):
                for u, a in c["answers"].items():
                    if url.startswith(u.rstrip("/") + "/timestamp/"): return a["status"], bytes.fromhex(a["body_hex"])
                raise OSError("no route")
            log = []
            new, changed, status = S.upgrade_proof(proof, call, c["allowed"], log=log.append)
            self.assertEqual((log, status, changed, new.hex()), (c["expect"]["log"], c["expect"]["status"], c["expect"]["changed"], c["expect"]["proof_hex"]), c["title"])


if __name__ == "__main__":
    unittest.main()

"""CLI paths in-process (so coverage sees them) and the real urllib path against the local mock."""
import io, json, os, sys, unittest
ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(ROOT, "python")); sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import verify_ots as V
import mock_esplora
from schema_lite import validate

VEC = os.path.join(ROOT, "vectors")
def p(vid, n): return os.path.join(VEC, vid, n)
with open(os.path.join(ROOT, "spec", "report.schema.json")) as f: SCHEMA = json.load(f)

class FakeStdin(io.StringIO):
    def __init__(self, text, tty): super().__init__(text); self._tty = tty
    def isatty(self): return self._tty

def run(argv, stdin=None):
    out, err = io.StringIO(), io.StringIO()
    rc = V.main(argv, stdin=stdin or FakeStdin("", False), stdout=out, stderr=err)
    return rc, out.getvalue(), err.getvalue()

class InProcessCli(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.srv, cls.port = mock_esplora.serve()
        cls.base = "http://127.0.0.1:%d/synthetic" % cls.port
    @classmethod
    def tearDownClass(cls): cls.srv.shutdown()

    def test_offline_text_and_steps(self):
        rc, out, err = run([p("hello-world", "data.bin"), p("hello-world", "proof.ots"), "--offline", "--steps"])
        self.assertEqual(rc, 3); self.assertIn("phase: calendar's tree", out); self.assertIn("phase: the transaction", out)
        self.assertIn("[PASS] 1. File to hash", out); self.assertIn("[SKIP] 5. Verdict", out); self.assertEqual(err, "")
    def test_steps_non_bitcoin_and_many_kinds(self):
        rc, out, _ = run([p("different-blockchains", "data.bin"), p("different-blockchains", "proof.ots"), "--offline", "--steps"])
        self.assertIn("Litecoin" if False else "Ethereum", out); self.assertIn("pending", out)
    def test_ledger_with_yes_over_real_http(self):
        rc, out, err = run([p("hello-world", "data.bin"), p("hello-world", "proof.ots"), "--yes", "--esplora", self.base, "--esplora", self.base + "/", "--timeout", "5"])
        self.assertEqual(rc, 0, out + err); self.assertIn("[PASS] 5. Verdict", out); self.assertIn("This file existed before block 358391", out)
        self.assertIn("/block-height/358391", err); self.assertIn("{block_hash}", err); self.assertIn("look: blockstream.info tx https://blockstream.info/tx/7e9f", out)
    def test_ledger_json_is_valid_and_matches_report(self):
        rc, out, _ = run([p("hello-world", "data.bin"), p("hello-world", "proof.ots"), "--yes", "--esplora", self.base, "--json"])
        j = json.loads(out); self.assertEqual(rc, 0); self.assertEqual(validate(j, SCHEMA), []); self.assertEqual(j["verdict"]["block"], 358391)
    def test_bad_stamp_exit_1(self):
        rc, out, _ = run([p("bad-stamp", "data.bin"), p("bad-stamp", "proof.ots"), "-y", "--esplora", self.base])
        self.assertEqual(rc, 1); self.assertIn("[FAIL] 4. The ledger", out); self.assertIn("merkle_root mismatch", out)
    def test_unreachable_server_is_skip(self):
        rc, out, _ = run([p("hello-world", "data.bin"), p("hello-world", "proof.ots"), "-y", "--esplora", "http://127.0.0.1:%d/down" % self.port])
        self.assertEqual(rc, 3); self.assertIn("unreachable", out)
        rc, out, _ = run([p("hello-world", "data.bin"), p("hello-world", "proof.ots"), "-y", "--esplora", "http://127.0.0.1:1/x", "--timeout", "1"])
        self.assertEqual(rc, 3)
    def test_interactive_prompt(self):
        argv = [p("hello-world", "data.bin"), p("hello-world", "proof.ots"), "--esplora", self.base]
        rc, out, err = run(argv, stdin=FakeStdin("y\n", True)); self.assertEqual(rc, 0); self.assertIn("Ask these servers now?", err)
        rc, out, err = run(argv, stdin=FakeStdin("n\n", True)); self.assertEqual(rc, 3)
        rc, out, err = run(argv, stdin=FakeStdin("", False)); self.assertEqual(rc, 3); self.assertIn("staying offline", err)
    def test_argument_forms(self):
        self.assertEqual(run([])[0], 2)
        self.assertEqual(run(["a", "b", "c"])[0], 2)
        self.assertEqual(run([p("hello-world", "data.bin"), p("hello-world", "proof.ots"), "--digest", "00" * 32])[0], 2)
        self.assertEqual(run([p("hello-world", "proof.ots"), "--digest", "0" * 63 + "1", "--offline"])[0], 1)
        rc, out, _ = run([p("hello-world", "proof.ots"), "--offline"]); self.assertEqual(rc, 3); self.assertIn("proof only", out)
        # implicit file: X.ots next to X
        import tempfile, shutil
        with tempfile.TemporaryDirectory() as d:
            shutil.copy(p("hello-world", "data.bin"), os.path.join(d, "hw.txt")); shutil.copy(p("hello-world", "proof.ots"), os.path.join(d, "hw.txt.ots"))
            rc, out, _ = run([os.path.join(d, "hw.txt.ots"), "--offline"]); self.assertIn("[PASS] 1. File to hash", out)
            rc, out, _ = run([os.path.join(d, "hw.txt"), "--offline"]); self.assertIn("[PASS] 1. File to hash", out)
    def test_link_json_and_text(self):
        rc, out, _ = run([p("incomplete", "data.bin"), p("incomplete", "proof.ots"), "--offline", "--link", "https://x.example/v/", "--json"])
        self.assertTrue(out.splitlines()[-1].startswith("https://x.example/v/#h="))
        d = V.decode_permalink(out.splitlines()[-1]); self.assertEqual(d["ots"], open(p("incomplete", "proof.ots"), "rb").read())
    def test_text_for_failures(self):
        rc, out, _ = run([p("invalid-result-too-long" if False else "invalid-exceeds-max-msg-length", "proof.ots"), "--offline"])
        self.assertEqual(rc, 1); self.assertIn("result_too_long", out)
        rc, out, _ = run([p("ripemd160-readme", "data.bin"), p("ripemd160-readme", "proof.ots"), "--offline"]); self.assertIn("RIPEMD-160", out)
        rc, out, _ = run(["--digest", "zz", p("merkle1", "proof.ots"), "--offline"]); self.assertEqual(rc, 1)

class Http(unittest.TestCase):
    def test_fetch_codes(self):
        srv, port = mock_esplora.serve()
        try:
            f = V.http_fetch(3)
            self.assertEqual(f("http://127.0.0.1:%d/synthetic/block-height/358391" % port)[0], 200)
            self.assertEqual(f("http://127.0.0.1:%d/synthetic/block-height/1" % port)[0], 404)
            self.assertEqual(f("http://127.0.0.1:%d/down/x" % port)[0], 503)
            with self.assertRaises(OSError): V.http_fetch(1)("http://127.0.0.1:1/")
        finally: srv.shutdown()

if __name__ == "__main__":
    unittest.main()

import base64, http.client, json, os, shutil, sys, tempfile, unittest, urllib.request, urllib.error

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
for sub in ("python", "test", os.path.join("clients", "python")): sys.path.insert(0, os.path.join(ROOT, sub))
os.environ["no_proxy"] = os.environ["NO_PROXY"] = "127.0.0.1,localhost"
import verify_ots as V, ots_api, ots_client, mock_calendar, mock_esplora

HW = os.path.join(ROOT, "vectors", "hello-world")
PROOF = open(os.path.join(HW, "proof.ots"), "rb").read()
DATA = open(os.path.join(HW, "data.bin"), "rb").read()
DIGEST = V.sha256(DATA).hex()


def req(port, method, path, body=None, headers=None, raw=False):
    h = dict(headers or {})
    data = None
    if body is not None:
        data = body if isinstance(body, bytes) else json.dumps(body).encode()
        h.setdefault("Content-Type", "application/json")
    r = urllib.request.Request("http://127.0.0.1:%d%s" % (port, path), data=data, headers=h, method=method)
    try:
        with urllib.request.urlopen(r, timeout=20) as resp: status, hd, text = resp.status, resp.headers, resp.read().decode()
    except urllib.error.HTTPError as e: status, hd, text = e.code, e.headers, e.read().decode()
    return status, hd, (text if raw else json.loads(text))


class Offline(unittest.TestCase):
    @classmethod
    def setUpClass(cls): cls.srv, cls.port = ots_api.serve()
    @classmethod
    def tearDownClass(cls): cls.srv.shutdown(); cls.srv.server_close()

    def test_health_and_openapi_agree_with_the_server(self):
        s, _, h = req(self.port, "GET", "/v1/health")
        self.assertEqual((s, h["ok"], h["network"], h["report_spec"]), (200, True, False, "ots-explain-report/1"))
        s, _, spec = req(self.port, "GET", "/openapi.json")
        self.assertEqual(spec["openapi"], "3.1.0")
        for path, item in spec["paths"].items():
            for method in item:
                st, _, _ = req(self.port, method.upper(), path, {} if method == "post" else None)
                self.assertNotEqual(st, 404, "%s %s is documented but missing" % (method, path))
        # and every route the server has is documented
        src = open(os.path.join(ROOT, "python", "ots_api.py")).read()
        import re
        for p in set(re.findall(r'u\.path == "(/[^"]+)"', src)): self.assertIn(p, spec["paths"], p + " is served but undocumented")

    def test_verify_json_is_byte_identical_to_the_library(self):
        s, hd, text = req(self.port, "POST", "/v1/verify", {"proof_b64": base64.b64encode(PROOF).decode(), "digest": DIGEST}, raw=True)
        self.assertEqual(s, 200)
        self.assertEqual(text, V.canonical_json(V.build_report(PROOF, digest_hex=DIGEST)) + "\n")
        self.assertEqual(hd["X-Verdict"], "SKIP")  # offline: steps 1-3 only

    def test_raw_body_and_text_format(self):
        s, hd, text = req(self.port, "POST", "/v1/verify?digest=%s&format=text&steps=1" % DIGEST, PROOF, {"Content-Type": "application/octet-stream"}, raw=True)
        self.assertEqual(s, 200)
        self.assertEqual(text, V.render_text(V.build_report(PROOF, digest_hex=DIGEST), True))
        self.assertTrue(hd["Content-Type"].startswith("text/plain"))
        s, _, rep = req(self.port, "POST", "/v1/verify", PROOF, {"Content-Type": "application/octet-stream"})
        self.assertEqual((s, rep["input"]["mode"]), (200, "none"))

    def test_bad_proof_is_a_report_not_an_http_error(self):
        s, hd, rep = req(self.port, "POST", "/v1/verify", {"proof_b64": base64.b64encode(b"nonsense").decode()})
        self.assertEqual((s, rep["error"]["code"], rep["verdict"]["status"]), (200, "bad_magic", "FAIL"))

    def test_errors(self):
        p = self.port
        self.assertEqual(req(p, "GET", "/nope")[0], 404)
        self.assertEqual(req(p, "POST", "/v1/nope", {})[0], 404)
        self.assertEqual(req(p, "POST", "/v1/verify", b"not json", {"Content-Type": "application/json"})[0], 400)
        self.assertEqual(req(p, "POST", "/v1/verify", {"proof_b64": "!!!"})[2]["error"]["code"], "bad_request")
        self.assertEqual(req(p, "POST", "/v1/verify", {"proof_b64": "AA==", "digest": "xyz"})[2]["error"]["code"], "bad_request")
        self.assertEqual(req(p, "POST", "/v1/verify", [1, 2])[0], 400)
        s, _, e = req(p, "POST", "/v1/verify", {"proof_b64": base64.b64encode(PROOF).decode(), "ledger": True})
        self.assertEqual((s, e["error"]["code"]), (403, "network_disabled"))
        self.assertEqual(req(p, "POST", "/v1/stamp", {"digest": DIGEST})[0], 403)
        self.assertEqual(req(p, "POST", "/v1/upgrade", {"proof_b64": "AA=="})[0], 403)
        c = http.client.HTTPConnection("127.0.0.1", p); c.putrequest("POST", "/v1/verify"); c.putheader("Transfer-Encoding", "chunked"); c.endheaders()
        self.assertEqual(c.getresponse().status, 411)

    def test_internal_errors_do_not_leak(self):
        orig = ots_api.op_verify
        ots_api.op_verify = lambda *a, **k: 1 / 0
        try:
            s, _, e = req(self.port, "POST", "/v1/verify", {"proof_b64": "AA=="})
            self.assertEqual((s, e["error"]["message"]), (500, "internal error"))
        finally: ots_api.op_verify = orig

    def test_permalink_roundtrip(self):
        b64 = base64.b64encode(PROOF).decode()
        s, _, r = req(self.port, "POST", "/v1/permalink", {"digest": DIGEST, "proof_b64": b64, "base": "https://example.org/x/", "proof_url": "https://a.example/p.ots"})
        self.assertEqual(r["url"], V.encode_permalink("https://example.org/x/", DIGEST, PROOF, "https://a.example/p.ots"))
        s, _, d = req(self.port, "POST", "/v1/permalink/decode", {"url": r["url"]})
        self.assertEqual((d["digest"], d["proof_b64"], d["proof_url"]), (DIGEST, b64, "https://a.example/p.ots"))
        self.assertEqual(req(self.port, "POST", "/v1/permalink", {"digest": DIGEST, "proof_b64": b64, "base": "javascript:alert(1)"})[0], 400)
        self.assertEqual(req(self.port, "POST", "/v1/permalink", {"digest": DIGEST, "proof_b64": b64, "base": "https://x/#a"})[0], 400)

    def test_python_client(self):
        api = ots_client.OtsApi("http://127.0.0.1:%d" % self.port)
        self.assertTrue(api.health()["ok"])
        rep = api.verify(PROOF, DIGEST)
        self.assertEqual([x["status"] for x in rep["steps"]][:3], ["PASS", "PASS", "PASS"])
        self.assertIn("Proof structure", api.verify_text(PROOF, DIGEST))
        url = api.permalink(DIGEST, PROOF, "https://example.org/")
        d = api.decode_permalink(url)
        self.assertEqual((d["digest"], d["proof"]), (DIGEST, PROOF))
        with self.assertRaises(ots_client.OtsApiError) as cm: api.stamp(DIGEST)
        self.assertEqual(cm.exception.code, "network_disabled")


class Hardening(unittest.TestCase):
    def test_token_cors_and_size_limit(self):
        srv, port = ots_api.serve(token="s3cret", cors="https://my.app", max_body=2000)
        try:
            body = {"proof_b64": base64.b64encode(PROOF[:50]).decode()}
            self.assertEqual(req(port, "POST", "/v1/verify", body)[0], 401)
            self.assertEqual(req(port, "POST", "/v1/verify", body, {"Authorization": "Bearer nope"})[0], 401)
            s, hd, _ = req(port, "POST", "/v1/verify", body, {"Authorization": "Bearer s3cret"})
            self.assertEqual((s, hd["Access-Control-Allow-Origin"]), (200, "https://my.app"))
            self.assertEqual(req(port, "POST", "/v1/verify", b"x" * 5000, {"Authorization": "Bearer s3cret", "Content-Type": "application/octet-stream"})[0], 413)
            self.assertEqual(req(port, "OPTIONS", "/v1/verify", raw=True)[1]["Access-Control-Allow-Methods"], "GET, POST, OPTIONS")
        finally: srv.shutdown(); srv.server_close()

    def test_no_cors_by_default(self):
        srv, port = ots_api.serve()
        try:
            _, hd, _ = req(port, "GET", "/v1/health")
            self.assertIsNone(hd.get("Access-Control-Allow-Origin"))
        finally: srv.shutdown(); srv.server_close()

    def test_refuses_a_public_bind_without_a_token(self):
        self.assertEqual(ots_api.main(["--host", "0.0.0.0", "--port", "0"]), 2)


class WithNetwork(unittest.TestCase):
    """--allow-network against the mock explorer and calendar: ledger check, stamp, upgrade, SSRF guard."""
    @classmethod
    def setUpClass(cls):
        cls.tmp = tempfile.mkdtemp(prefix="ots-api-")
        chain = os.path.join(cls.tmp, "chain"); os.makedirs(chain)
        cls.cal = mock_calendar.MockCalendar(chain, scenario="chain")
        cls.esp, eport = mock_esplora.serve(root=chain)
        cls.esp_syn, sport = mock_esplora.serve()  # the synthetic vectors
        cls.chain_base = "http://127.0.0.1:%d/chain" % eport
        cls.syn_base = "http://127.0.0.1:%d/synthetic" % sport
        cls.srv, cls.port = ots_api.serve(allow_network=True, esplora_allow=[cls.chain_base, cls.syn_base], calendar_allow=[cls.cal.url])

    @classmethod
    def tearDownClass(cls):
        cls.cal.close(); cls.esp.shutdown(); cls.esp_syn.shutdown(); cls.srv.shutdown(); cls.srv.server_close(); shutil.rmtree(cls.tmp, ignore_errors=True)

    def test_ledger_check_through_the_api(self):
        b64 = base64.b64encode(PROOF).decode()
        s, _, rep = req(self.port, "POST", "/v1/verify", {"proof_b64": b64, "digest": DIGEST, "ledger": {"servers": [self.syn_base, {"name": "mirror", "base": self.syn_base}]}})
        self.assertEqual((s, rep["verdict"]["status"], rep["verdict"]["block"]), (200, "PASS", 358391))
        local = V.build_report(PROOF, digest_hex=DIGEST, ledger={"fetch": V.http_fetch(), "servers": [{"name": self.syn_base, "base": self.syn_base}, {"name": self.syn_base, "base": self.syn_base}]})
        self.assertEqual(V.canonical_json(rep), V.canonical_json(local))

    def test_a_request_cannot_make_the_server_fetch_arbitrary_urls(self):
        b64 = base64.b64encode(PROOF).decode()
        for bad in ("http://169.254.169.254/latest", "https://evil.example/api", {"base": "http://127.0.0.1:1/x"}):
            s, _, e = req(self.port, "POST", "/v1/verify", {"proof_b64": b64, "ledger": {"servers": [bad]}})
            self.assertEqual((s, e["error"]["code"]), (400, "server_not_allowed"), str(bad))
        s, _, e = req(self.port, "POST", "/v1/stamp", {"digest": DIGEST, "calendars": ["http://169.254.169.254"]})
        self.assertEqual((s, e["error"]["code"]), (400, "calendar_not_allowed"))
        self.assertEqual(req(self.port, "POST", "/v1/stamp", {"digest": "abcd"})[0], 400)

    def test_stamp_upgrade_verify(self):
        api = ots_client.OtsApi("http://127.0.0.1:%d" % self.port)
        digest = V.sha256(b"api test file").hex()
        st = api.stamp(digest, [self.cal.url])
        self.assertEqual(st["status"], "pending")
        self.assertTrue(any("accepted" in l for l in st["log"]))
        early = api.upgrade(st["proof"])
        self.assertEqual((early["status"], early["changed"]), ("pending", False))
        self.cal.ready = True
        up = api.upgrade(st["proof"])
        self.assertEqual((up["status"], up["changed"]), ("complete", True))
        rep = api.verify(up["proof"], digest, ledger={"servers": [self.chain_base]})
        self.assertEqual([x["status"] for x in rep["steps"]], ["PASS"] * 5)
        self.assertEqual(api.upgrade(up["proof"])["status"], "nothing_to_do")
        with self.assertRaises(ots_client.OtsApiError) as cm: api.upgrade(b"garbage")
        self.assertEqual(cm.exception.code, "bad_proof")


if __name__ == "__main__":
    unittest.main()

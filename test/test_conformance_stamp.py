"""Conformance for the write half: python/ots_stamp.py and the TypeScript stamp.ts must produce the same bytes.

Both talk to the same mock calendars over real HTTP, with the same nonce. Compared: the pending .ots from `stamp`,
the result of `upgrade` before and after the calendar confirms, the allow-list refusal, and the log lines; then the
proof the *TypeScript* side upgraded is verified end to end by verify_ots.py against the synthetic chain.
"""
import http.server, json, os, shutil, subprocess, sys, tempfile, threading, unittest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(ROOT, "python")); sys.path.insert(0, os.path.join(ROOT, "test"))
import verify_ots as V, ots_stamp as S, mock_calendar, mock_esplora

NODE = shutil.which("node")


class Stub:
    """A server that answers every request with a fixed status and body."""
    def __init__(self, status, body=b""):
        class H(http.server.BaseHTTPRequestHandler):
            def log_message(self, *a): pass
            def _go(self):
                n = int(self.headers.get("content-length", 0)); self.rfile.read(n)
                self.send_response(status); self.send_header("content-length", str(len(body))); self.end_headers(); self.wfile.write(body)
            do_GET = do_POST = _go
        self.server = http.server.ThreadingHTTPServer(("127.0.0.1", 0), H)
        threading.Thread(target=self.server.serve_forever, daemon=True).start()
        self.url = "http://127.0.0.1:%d" % self.server.server_address[1]
    def close(self): self.server.shutdown(); self.server.server_close()


def node_run(tmp, jobs, tag):
    jf, out = os.path.join(tmp, tag + ".jobs.json"), os.path.join(tmp, tag)
    json.dump(jobs, open(jf, "w"))
    r = subprocess.run([NODE, os.path.join(ROOT, "test", "js", "stamp-run.mjs"), jf, out], capture_output=True, text=True)
    if r.returncode: raise RuntimeError(r.stderr)
    return out


@unittest.skipUnless(NODE and os.path.isdir(os.path.join(ROOT, "node_modules", "esbuild")), "needs node and `npm install`")
class StampConformance(unittest.TestCase):
    def test_python_and_typescript_stamp_and_upgrade_identically(self):
        os.environ["no_proxy"] = os.environ["NO_PROXY"] = "127.0.0.1,localhost"
        tmp = tempfile.mkdtemp(prefix="ots-stampconf-")
        chain = os.path.join(tmp, "explorer"); os.makedirs(chain)
        cal_a, cal_b = mock_calendar.MockCalendar(chain, scenario="chain"), mock_calendar.MockCalendar(chain, scenario="chain", height=810000)
        down, junk = Stub(503), Stub(200, b"\xf0\xff\xff")
        esp, port = mock_esplora.serve(root=chain)
        call = S.http_call()
        try:
            d = lambda i: V.sha256(b"file %d" % i).hex()
            n = lambda i: V.sha256(b"nonce %d" % i)[:16].hex()
            scen = [
                ("one", d(1), n(1), [cal_a.url]),
                ("two", d(2), n(2), [cal_a.url, cal_b.url]),
                ("one-down", d(3), n(3), [down.url, cal_a.url]),
                ("one-junk", d(4), n(4), [junk.url, cal_b.url]),
                ("order", d(5), n(5), [cal_b.url, cal_a.url]),
                ("all-down", d(6), n(6), [down.url]),
            ]
            # --- stamp
            jobs = [{"name": s[0], "op": "stamp", "digest": s[1], "nonce": s[2], "calendars": s[3]} for s in scen]
            ts = node_run(tmp, jobs, "stamp-ts")
            made = {}
            for name, dg, nc, cals in scen:
                logs = []
                try: py = S.stamp_digest(bytes.fromhex(dg), cals, call, nonce=bytes.fromhex(nc), log=logs.append); err = None
                except RuntimeError as e: py, err = None, str(e)
                tso = json.load(open(os.path.join(ts, name + ".out.json")))
                self.assertEqual(err, tso["error"], name)
                self.assertEqual("\n".join(logs), open(os.path.join(ts, name + ".log")).read(), name + " log")
                if py is not None:
                    self.assertEqual(py, open(os.path.join(ts, name + ".ots"), "rb").read(), name + " bytes")
                    p = os.path.join(tmp, name + ".ots"); open(p, "wb").write(py); made[name] = p
            self.assertEqual(set(made), {"one", "two", "one-down", "one-junk", "order"})
            # --- upgrade, not confirmed yet / refused by the allow list / confirmed
            def compare(tag, allowed):
                jobs = [{"name": k, "op": "upgrade", "proof": p, "allowed": allowed} for k, p in made.items()]
                out = node_run(tmp, jobs, tag)
                res = {}
                for k, p in made.items():
                    logs = []
                    new, changed, status = S.upgrade_proof(open(p, "rb").read(), call, allowed, logs.append)
                    o = json.load(open(os.path.join(out, k + ".out.json")))
                    self.assertEqual((status, changed, None), (o["status"], o["changed"], o["error"]), k + " " + tag)
                    self.assertEqual("\n".join(logs), open(os.path.join(out, k + ".log")).read(), k + " " + tag + " log")
                    self.assertEqual(new, open(os.path.join(out, k + ".ots"), "rb").read(), k + " " + tag + " bytes")
                    res[k] = (new, os.path.join(out, k + ".ots"))
                return res
            r1 = compare("up-early", [cal_a.url, cal_b.url])
            self.assertTrue(all(v[0] == open(made[k], "rb").read() for k, v in r1.items()))
            compare("up-refused", [])
            cal_a.ready = cal_b.ready = True
            r2 = compare("up-ready", [cal_a.url, cal_b.url])
            self.assertTrue(all(v[0] != open(made[k], "rb").read() for k, v in r2.items()))
            # an upgraded proof upgrades to "nothing to do", in both
            again = os.path.join(tmp, "again.ots"); open(again, "wb").write(r2["two"][0])
            self.assertEqual(S.upgrade_proof(r2["two"][0], call, [cal_a.url])[2], "nothing_to_do")
            # --- the proof the TypeScript side produced verifies against the synthetic chain, with the data we stamped
            datum = os.path.join(tmp, "d.bin"); open(datum, "wb").write(b"file 2")
            self.assertEqual(V.sha256(b"file 2").hex(), d(2))
            rep = V.build_report(open(r2["two"][1], "rb").read(), file=V.FileInput.from_bytes(b"file 2"),
                                 ledger={"fetch": V.http_fetch(), "servers": [{"name": "mock", "base": "http://127.0.0.1:%d/chain" % port}]})
            self.assertEqual([s["status"] for s in rep["steps"]], ["PASS", "PASS", "PASS", "PASS", "PASS"], json.dumps(rep["steps"]))
            print("\nstamp conformance: %d stamp cases, %d x 3 upgrade phases, 0 diffs; TS-upgraded proof verified PASS on the synthetic chain" % (len(scen), len(made)))
        finally:
            for c in (cal_a, cal_b, down, junk): c.close()
            esp.shutdown(); shutil.rmtree(tmp, ignore_errors=True)


if __name__ == "__main__":
    unittest.main()

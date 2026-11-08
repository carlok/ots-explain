#!/usr/bin/env python3
"""A complete offline demo of the pipeline: file -> hash -> stamp -> (wait) -> upgrade -> verify -> link.

Everything is local: a mock OpenTimestamps calendar, a synthetic chain served by a mock Esplora. It shows the
mechanics, not the real Bitcoin chain. With --serve it keeps the mock Esplora running so you can paste its base URL
into the web page's "Esplora URL" box and see the same green verdict there.
    python3 tools/demo.py [--serve] [--link-base URL]
"""
import argparse, io, os, sys, tempfile, time
ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
for sub in ("python", "test"): sys.path.insert(0, os.path.join(ROOT, sub))
import verify_ots as V, ots_stamp as S, mock_calendar, mock_esplora

def main():
    ap = argparse.ArgumentParser(); ap.add_argument("--serve", action="store_true"); ap.add_argument("--link-base", default="https://example.org/ots/")
    a = ap.parse_args()
    d = tempfile.mkdtemp(prefix="ots-demo-"); chain = os.path.join(d, "explorer"); os.makedirs(chain)
    cal = mock_calendar.MockCalendar(chain); esp, port = mock_esplora.serve(root=chain)
    base = "http://127.0.0.1:%d/chain" % port
    doc = os.path.join(d, "report.txt")
    with open(doc, "w") as f: f.write("Quarterly report, final.\n")
    step = lambda s: print("\n=== " + s)
    step("1. stamp (sends one commitment to the mock calendar)")
    S.main(["stamp", doc, "--calendar", cal.url, "--yes"])
    step("2. verify right away: steps 1-3 pass, no Bitcoin attestation yet")
    V.main([doc, "--offline"])
    step("3. upgrade too early: the calendar says not yet")
    S.main(["upgrade", doc + ".ots", "--allow", cal.url])
    cal.ready = True
    step("4. ...a few hours later (the mock chain confirms) - upgrade again")
    S.main(["upgrade", doc + ".ots", "--allow", cal.url])
    step("5. verify against the (synthetic) chain, asking the mock explorer")
    rc = V.main([doc, "--steps", "--yes", "--esplora", base, "--link", args_link(a)])
    print("\nexit code", rc)
    print("\nfiles in", d)
    if a.serve:
        print("mock Esplora base URL for the web page:", base, "\nCtrl-C to stop")
        try:
            while True: time.sleep(3600)
        except KeyboardInterrupt: pass
    cal.close(); esp.shutdown()
    return rc

def args_link(a): return a.link_base

if __name__ == "__main__": sys.exit(main())

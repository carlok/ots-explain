"""A real stamp, made on 2026-11-08 by tools/e2e_real.sh against the three public calendars, and the same proof after
alice.btc.calendar.opentimestamps.org added the Bitcoin path (block 975064). The facts below were checked against
blockstream.info and mempool.space when the proof was upgraded; here they are pinned so a parser change cannot move them.
The conformance test also runs both proofs through the Python and TypeScript implementations (cases real-dummy-*)."""
import hashlib, os, sys, unittest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(ROOT, "python"))
import verify_ots as V

REAL = os.path.join(ROOT, "vectors", "real")
DIGEST = "fb415de6e7484a2f9d685c857bb6c80ea98019c25a91665372c48b09f62c2da3"
TXID = "49884ee7042b6f28220f315b646888a7ee5574a9f575868fabfafa9422d70105"


def read(name):
    with open(os.path.join(REAL, name), "rb") as f:
        return f.read()


class RealVector(unittest.TestCase):
    def test_the_file_is_the_one_that_was_stamped(self):
        self.assertEqual(hashlib.sha256(read("dummy-2026-11-08.bin")).hexdigest(), DIGEST)

    def test_pending_proof_names_the_three_calendars_and_no_block(self):
        text = V.render_text(V.build_report(read("dummy-2026-11-08.pending.ots"), digest_hex=DIGEST), False)
        for cal in ("alice.btc.calendar.opentimestamps.org", "bob.btc.calendar.opentimestamps.org", "finney.calendar.eternitywall.com"):
            self.assertIn("pending (https://" + cal + ")", text)
        self.assertNotIn("Bitcoin (block", text)

    def test_confirmed_proof_points_at_block_975064(self):
        rep = V.build_report(read("dummy-2026-11-08.confirmed.ots"), file=V.FileInput.from_bytes(read("dummy-2026-11-08.bin")))
        text = V.render_text(rep, False)
        self.assertIn("attestation 1: Bitcoin (block 975064)", text)
        self.assertIn("every operation was recomputed from your digest", text)
        self.assertIn("pending (https://bob.btc.calendar.opentimestamps.org)", text)  # the other two calendars had not answered yet
        self.assertIn("pending (https://finney.calendar.eternitywall.com)", text)
        self.assertNotEqual(rep["verdict"]["status"], "FAIL")  # offline: the ledger step is skipped, nothing failed

    def test_confirmed_proof_ends_in_the_known_transaction(self):
        p = V.parse_proof(read("dummy-2026-11-08.confirmed.ots"))
        self.assertEqual(p.digest.hex(), DIGEST)
        text = V.render_text(V.build_report(read("dummy-2026-11-08.confirmed.ots"), digest_hex=DIGEST), False)
        self.assertIn("/api/tx/" + TXID + "/hex", text)  # the transaction the proof's hops end in, as step 4 would ask for it

    def test_pending_proof_is_the_confirmed_one_minus_the_bitcoin_path(self):
        a, b = read("dummy-2026-11-08.pending.ots"), read("dummy-2026-11-08.confirmed.ots")
        self.assertLess(len(a), len(b))
        self.assertEqual(V.parse_proof(a).digest, V.parse_proof(b).digest)


if __name__ == "__main__":
    unittest.main()

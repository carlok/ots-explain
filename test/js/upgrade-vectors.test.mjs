// vectors/upgrade/index.json was produced by python/ots_stamp.py; the independently written TypeScript module must
// produce the same log lines, status and bytes. (Regenerate with tools/make_upgrade_vectors.py.)
import test from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { join } from "node:path";
import { core, readBin, VECTORS } from "./helper.mjs";

const cases = JSON.parse(readFileSync(join(VECTORS, "upgrade", "index.json"), "utf8"));
const fromHex = (h) => Uint8Array.from(Buffer.from(h, "hex"));
test("upgrade vectors: at least 7 cases", () => assert.ok(cases.length >= 7));
for (const c of cases) {
  test("upgrade vector: " + c.title, async () => {
    const call = async (url) => {
      for (const [u, a] of Object.entries(c.answers)) if (url.startsWith(u.replace(/\/+$/, "") + "/timestamp/")) return { status: a.status, body: fromHex(a.body_hex) };
      throw new Error("no route " + url);
    };
    const log = [];
    const r = await core.upgradeProof(readBin(c.proof, "proof.ots"), call, c.allowed, (l) => log.push(l));
    assert.deepEqual(log, c.expect.log);
    assert.equal(r.status, c.expect.status);
    assert.equal(r.changed, c.expect.changed);
    assert.equal(Buffer.from(r.bytes).toString("hex"), c.expect.proof_hex);
  });
}

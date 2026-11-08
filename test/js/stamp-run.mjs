// node test/js/stamp-run.mjs JOBS.json OUTDIR   (driven by test/test_conformance_stamp.py)
// job: {name, op:"stamp", digest, nonce, calendars}  or  {name, op:"upgrade", proof, allowed}
// writes <name>.ots (when bytes result), <name>.out.json ({status, changed, error}) and <name>.log.
import { readFileSync, writeFileSync, mkdirSync } from "node:fs";
import { join } from "node:path";

const core = await import("../../web/build-core.mjs").then(() => import("../../web/build/core.mjs"));
const [jobs, out] = process.argv.slice(2);
mkdirSync(out, { recursive: true });
const call = async (url, body) => {
  const r = await fetch(url, body ? { method: "POST", body, headers: { Accept: "application/vnd.opentimestamps.v1" } } : { headers: { Accept: "application/vnd.opentimestamps.v1" } });
  return { status: r.status, body: new Uint8Array(await r.arrayBuffer()) };
};
const fromHex = (h) => Uint8Array.from(Buffer.from(h, "hex"));
for (const j of JSON.parse(readFileSync(jobs, "utf8"))) {
  const log = [];
  const res = { status: null, changed: null, error: null };
  try {
    if (j.op === "stamp") {
      const b = await core.stampDigest(fromHex(j.digest), j.calendars, call, fromHex(j.nonce), (l) => log.push(l));
      writeFileSync(join(out, j.name + ".ots"), b);
    } else {
      const r = await core.upgradeProof(new Uint8Array(readFileSync(j.proof)), call, j.allowed, (l) => log.push(l));
      writeFileSync(join(out, j.name + ".ots"), r.bytes);
      res.status = r.status; res.changed = r.changed;
    }
  } catch (e) { res.error = e.message; }
  writeFileSync(join(out, j.name + ".out.json"), JSON.stringify(res));
  writeFileSync(join(out, j.name + ".log"), log.join("\n"));
}

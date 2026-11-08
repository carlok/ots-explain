// node test/js/conformance-run.mjs MANIFEST.json OUTDIR
// Runs the TypeScript implementation on every case of the manifest written by test/test_conformance.py and writes
//   <name>.json (canonical report), <name>.txt (text report), <name>.steps.txt (text report with every hop).
import { readFileSync, writeFileSync, mkdirSync } from "node:fs";
import { join, dirname } from "node:path";
import { tmpdir } from "node:os";
import { fileURLToPath } from "node:url";
import { build } from "esbuild";

const [manifest, out] = process.argv.slice(2);
if (!manifest || !out) { console.error("usage: conformance-run.mjs MANIFEST OUTDIR"); process.exit(2); }
const root = join(dirname(fileURLToPath(import.meta.url)), "..", "..");
const bundle = join(tmpdir(), `ots-text-${process.pid}.mjs`);
await build({ entryPoints: [join(root, "web/src/ui/text.ts")], bundle: true, format: "esm", platform: "node", outfile: bundle, logLevel: "error" });
const T = await import(bundle);
const core = await import("../../web/build-core.mjs").then(() => import("../../web/build/core.mjs"));
mkdirSync(out, { recursive: true });

const fetchText = async (url) => { const r = await fetch(url); return { status: r.status, body: await r.text() }; };
let n = 0;
for (const c of JSON.parse(readFileSync(manifest, "utf8"))) {
  const proof = new Uint8Array(readFileSync(c.proof));
  let file = null;
  if (c.file) { const d = new Uint8Array(readFileSync(c.file)); file = { size: d.length, digest: (alg) => core.hashBytes(alg, d) }; }
  const report = await core.buildReport({
    proof, file, digestHex: c.digest ?? null,
    ledger: c.servers ? { servers: c.servers, fetchText } : null,
  });
  writeFileSync(join(out, c.name + ".json"), core.canonicalJson(report) + "\n");
  writeFileSync(join(out, c.name + ".txt"), T.renderText(report, false));
  writeFileSync(join(out, c.name + ".steps.txt"), T.renderText(report, true));
  n++;
}
console.log(`ran ${n} cases`);

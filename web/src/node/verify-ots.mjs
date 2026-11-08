// node verify-ots.mjs [--digest HEX] [file] proof.ots   (prints the canonical JSON report; no ledger)
// Exit codes (SPEC section 8): 0 PASS, 1 FAIL, 3 SKIP, 2 usage or input error.
import { readFileSync } from "node:fs";
import { createHash } from "node:crypto";
import { buildReport, canonicalJson } from "../../build/core.mjs";

const args = process.argv.slice(2);
let digestHex;
const di = args.indexOf("--digest");
if (di >= 0) digestHex = args.splice(di, 2)[1];
if (args.length < 1 || args.length > 2 || (di >= 0 && (digestHex === undefined || args.length > 1))) {
  console.error("usage: verify-ots.mjs [--digest HEX] [file] proof.ots");
  process.exit(2);
}
try {
  const proof = new Uint8Array(readFileSync(args.at(-1)));
  const file = args.length === 2 ? readFileSync(args[0]) : null;
  const report = await buildReport({
    proof,
    digestHex,
    file: file && { size: file.length, digest: (alg) => createHash(alg).update(file).digest() },
  });
  console.log(canonicalJson(report));
  process.exitCode = { PASS: 0, FAIL: 1, SKIP: 3 }[report.verdict.status];
} catch (e) {
  console.error(String(e?.message ?? e));
  process.exit(2);
}

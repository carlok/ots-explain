// node test/js/dump-reports.mjs OUTDIR
// For every vector in vectors/index.json writes the canonical JSON report (ledger off):
//   <id>.file.json (only when data.bin exists), <id>.digest.json, <id>.none.json
// and, for vectors with a Bitcoin attestation, <id>.ledger.json using the file-backed fake fetch with two
// servers (blockstream.info and mempool.space, both at mock://synthetic).
// digest mode uses the proof's own digest; when the proof does not parse there is none, so the digest
// of 32 zero bytes is used (the report then has error != null whatever the digest).
// ledger mode uses the file when data.bin exists, else the proof's own digest.
import { mkdirSync, writeFileSync } from "node:fs";
import { join } from "node:path";
import { core, readBin, vectorIndex, hasFile } from "./helper.mjs";
import { fileFetch, MOCK2 } from "./fakefetch.mjs";

const out = process.argv[2];
if (!out) {
  console.error("usage: dump-reports.mjs OUTDIR");
  process.exit(2);
}
mkdirSync(out, { recursive: true });
const write = (name, report) => writeFileSync(join(out, name), core.canonicalJson(report) + "\n");
const fileOf = (bytes) => ({ size: bytes.length, digest: (alg) => core.hashBytes(alg, bytes) });

let n = 0;
for (const v of vectorIndex()) {
  const proof = readBin(v.id, "proof.ots");
  const parsed = core.parseProof(proof);
  const digestHex = parsed.ok ? core.hex(parsed.proof.digest) : "00".repeat(32);
  const data = hasFile(v.id, "data.bin") ? readBin(v.id, "data.bin") : null;
  if (data) write(`${v.id}.file.json`, await core.buildReport({ proof, file: fileOf(data) }));
  write(`${v.id}.digest.json`, await core.buildReport({ proof, digestHex }));
  write(`${v.id}.none.json`, await core.buildReport({ proof }));
  n += data ? 3 : 2;
  if (parsed.ok && parsed.proof.attestations.some((a) => a.kind === "bitcoin")) {
    const input = data ? { file: fileOf(data) } : { digestHex };
    write(`${v.id}.ledger.json`, await core.buildReport({ proof, ...input, ledger: { servers: MOCK2, fetchText: fileFetch() } }));
    n++;
  }
}
console.log(`wrote ${n} reports to ${out}`);

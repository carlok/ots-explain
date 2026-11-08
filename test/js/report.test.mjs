import { test } from "node:test";
import assert from "node:assert/strict";
import {
  core, H, cat, hdr, btc, pending, proofOf, readBin, readJson, vectorIndex, hasFile, validateSchema, REPORT_SCHEMA, STEPS_JSON,
} from "./helper.mjs";

const fileOf = (bytes, log) => ({
  size: bytes.length,
  digest: (alg) => {
    if (log) log.push(alg);
    return core.hashBytes(alg, bytes);
  },
});
const codes = (r) => r.steps.map((s) => `${s.status}:${s.code}`);

function assertValid(report, label = "") {
  const errs = validateSchema(REPORT_SCHEMA, report);
  assert.deepEqual(errs, [], label + " schema errors");
  // round trip through canonical JSON stays parseable and sorted
  const text = core.canonicalJson(report);
  assert.deepEqual(JSON.parse(text), JSON.parse(JSON.stringify(report)));
  assert.ok(!/\s(?=([^"]*"[^"]*")*[^"]*$)/.test(text), "no whitespace outside strings");
}

test("steps.json titles and codes agree with the implementation", async () => {
  const r = await core.buildReport({ proof: readBin("hello-world", "proof.ots") });
  assert.deepEqual(r.steps.map((s) => [s.id, s.title]), STEPS_JSON.steps.map((s) => [s.id, s.title]));
  for (const s of r.steps) assert.ok(STEPS_JSON.step_codes[s.id].includes(s.code), s.id + " " + s.code);
  // every parse error code is a listed structure code
  for (const code of ["bad_magic", "unsupported_version"]) assert.ok(STEPS_JSON.step_codes.structure.includes(code));
});

test("mode file, hello-world: steps and input", async () => {
  const data = readBin("hello-world", "data.bin");
  const log = [];
  const r = await core.buildReport({ proof: readBin("hello-world", "proof.ots"), file: fileOf(data, log) });
  assertValid(r);
  assert.deepEqual(log, ["sha256"]);
  assert.deepEqual(codes(r), ["PASS:ok", "PASS:ok", "PASS:ok", "SKIP:not_requested", "SKIP:incomplete"]);
  assert.deepEqual(r.input, { mode: "file", size: 13, digest: "03ba204e50d126e4674c005e04d82e84c21366780af1f43bd54a37816b6ab340", digest_alg: "sha256" });
  assert.equal(r.error, null);
  assert.equal(r.ledger, null);
  assert.deepEqual(r.verdict, { status: "SKIP", code: "incomplete", block: null, time: null, unverified: [] });
  assert.equal(r.proof.nodes, 39);
  assert.equal(r.proof.ops, 38);
  assert.equal(r.proof.max_depth, 38);
  assert.equal(r.proof.tree.length, 39);
  assert.deepEqual(r.proof.tree[0], { id: 0, parent: -1, op: null, arg: null, digest: r.proof.digest });
  assert.equal(r.proof.tree[1].op, "ripemd160");
  assert.equal(r.proof.tree[1].arg, null);
  assert.equal(r.proof.tree[2].op, "prepend");
  assert.equal(r.proof.attestations[0].kind, "bitcoin");
  assert.equal(r.proof.attestations[0].height, 358391);
  assert.equal(r.proof.attestations[0].uri, null);
  assert.equal(r.proof.attestations[0].tag, "0588960d73d71901");
  assert.equal(r.proof.attestations[0].payload, "f7ef15");
  assert.equal(r.proof.attestations[0].where_to_look.length, 6);
  assert.deepEqual(r.proof.attestations[0].where_to_look.slice(0, 3), [
    { kind: "block", server: "blockstream.info", url: "https://blockstream.info/block-height/358391" },
    { kind: "tx", server: "blockstream.info", url: "https://blockstream.info/tx/7e9f0f7d9daa2d9e51b2e22f4abe814c3f90539afa778a9bef88dc64627cb2ec" },
    { kind: "raw_hex", server: "blockstream.info", url: "https://blockstream.info/api/tx/7e9f0f7d9daa2d9e51b2e22f4abe814c3f90539afa778a9bef88dc64627cb2ec/hex" },
  ]);
  assert.deepEqual(r.proof.attestations[0].where_to_look.slice(3).map((w) => [w.kind, w.server]), [["block", "mempool.space"], ["tx", "mempool.space"], ["raw_hex", "mempool.space"]]);
  assert.equal(r.proof.attestations[0].where_to_look[3].url, "https://mempool.space/block/358391");
  assert.equal(r.proof.attestations[0].where_to_look[5].url, "https://mempool.space/api/tx/7e9f0f7d9daa2d9e51b2e22f4abe814c3f90539afa778a9bef88dc64627cb2ec/hex");
});

test("mode file, wrong file: mismatch, replay not tied, digest still reported", async () => {
  const r = await core.buildReport({ proof: readBin("hello-world", "proof.ots"), file: fileOf(new TextEncoder().encode("other")) });
  assertValid(r);
  assert.deepEqual(codes(r), ["FAIL:mismatch", "PASS:ok", "SKIP:not_tied", "SKIP:not_requested", "FAIL:failed"]);
  assert.equal(r.input.digest, core.hex(core.sha256(new TextEncoder().encode("other"))));
  assert.equal(r.input.size, 5);
  assert.equal(r.verdict.status, "FAIL");
  assert.equal(r.proof.digest, "03ba204e50d126e4674c005e04d82e84c21366780af1f43bd54a37816b6ab340");
});

test("mode file with a lazy digest callback: the SHA-1 vectors ask for sha1", async () => {
  for (const id of ["sha1-a", "sha1-b"]) {
    const log = [];
    const r = await core.buildReport({ proof: readBin(id, "proof.ots"), file: fileOf(readBin(id, "data.bin"), log) });
    assert.deepEqual(log, ["sha1"], id);
    assert.equal(r.input.digest_alg, "sha1");
    assert.equal(r.input.digest.length, 40);
    assert.equal(r.steps[0].code, "ok", id);
  }
  // an async digest callback is awaited
  const r = await core.buildReport({ proof: readBin("hello-world", "proof.ots"), file: { size: 13, digest: async () => core.sha256(readBin("hello-world", "data.bin")) } });
  assert.equal(r.steps[0].code, "ok");
});

test("mode file with a RIPEMD-160 header: alg_unsupported, no digest, callback never called", async () => {
  const log = [];
  const id = "ripemd160-readme";
  const r = await core.buildReport({ proof: readBin(id, "proof.ots"), file: fileOf(hasFile(id, "data.bin") ? readBin(id, "data.bin") : H("00"), log) });
  assertValid(r);
  assert.deepEqual(log, []);
  assert.equal(r.input.digest_alg, "ripemd160");
  assert.equal(r.input.digest, null);
  assert.equal(r.input.mode, "file");
  assert.ok(r.input.size !== null);
  assert.deepEqual(codes(r).slice(0, 3), ["SKIP:alg_unsupported", "PASS:ok", "SKIP:not_tied"]);
  assert.equal(r.verdict.status, "SKIP");
  // hash-only mode: the digest by hand works
  const d = await core.buildReport({ proof: readBin(id, "proof.ots"), digestHex: r.proof.digest.toUpperCase() });
  assert.deepEqual(codes(d).slice(0, 3), ["PASS:ok", "PASS:ok", "PASS:ok"]);
  assert.equal(d.input.digest, r.proof.digest);
});

test("mode digest: ok, mismatch, case folding, bad digests", async () => {
  const proof = readBin("hello-world", "proof.ots");
  const dig = "03ba204e50d126e4674c005e04d82e84c21366780af1f43bd54a37816b6ab340";
  let r = await core.buildReport({ proof, digestHex: dig.toUpperCase() });
  assertValid(r);
  assert.deepEqual(r.input, { mode: "digest", size: null, digest: dig, digest_alg: "sha256" });
  assert.deepEqual(codes(r).slice(0, 3), ["PASS:ok", "PASS:ok", "PASS:ok"]);
  r = await core.buildReport({ proof, digestHex: "00".repeat(32) });
  assert.deepEqual(codes(r).slice(0, 3), ["FAIL:mismatch", "PASS:ok", "SKIP:not_tied"]);
  assert.equal(r.input.digest, "00".repeat(32));
  for (const [bad, shown] of [["abc", null], ["zz", null], ["", null], [" " + dig, null], ["00".repeat(20), "00".repeat(20)], ["00".repeat(33), "00".repeat(33)], ["0A", "0a"]]) {
    r = await core.buildReport({ proof, digestHex: bad });
    assertValid(r, bad);
    assert.deepEqual(codes(r).slice(0, 3), ["FAIL:bad_digest", "PASS:ok", "SKIP:not_tied"], JSON.stringify(bad));
    assert.equal(r.input.digest, shown, JSON.stringify(bad));
    assert.equal(r.input.mode, "digest");
  }
  // a 20-byte digest is right for a SHA-1 proof
  r = await core.buildReport({ proof: readBin("sha1-a", "proof.ots"), digestHex: core.hex(core.sha1(readBin("sha1-a", "data.bin"))) });
  assert.equal(r.steps[0].code, "ok");
});

test("mode none", async () => {
  const r = await core.buildReport({ proof: readBin("hello-world", "proof.ots") });
  assertValid(r);
  assert.deepEqual(r.input, { mode: "none", size: null, digest: null, digest_alg: "sha256" });
  assert.deepEqual(codes(r), ["SKIP:no_input", "PASS:ok", "SKIP:not_tied", "SKIP:not_requested", "SKIP:incomplete"]);
  const same = await core.buildReport({ proof: readBin("hello-world", "proof.ots"), file: null, digestHex: null, ledger: null });
  assert.deepEqual(same, r);
});

test("unparsable proof: every mode", async () => {
  const bad = readBin("invalid-bad-major-version", "proof.ots");
  for (const [opts, input] of [
    [{ proof: bad }, { mode: "none", size: null, digest: null, digest_alg: null }],
    [{ proof: bad, digestHex: "AB" }, { mode: "digest", size: null, digest: "ab", digest_alg: null }],
    [{ proof: bad, digestHex: "xyz" }, { mode: "digest", size: null, digest: null, digest_alg: null }],
    [{ proof: bad, file: fileOf(H("010203")) }, { mode: "file", size: 3, digest: null, digest_alg: null }],
  ]) {
    let called = false;
    if (opts.file) { const f = opts.file.digest; opts.file.digest = (a) => { called = true; return f(a); }; }
    const r = await core.buildReport({ ...opts, ledger: { fetchText: async () => { throw new Error("no network expected"); } } });
    assertValid(r);
    assert.deepEqual(r.input, input);
    assert.equal(called, false);
    assert.deepEqual(r.error, { code: "unsupported_version" });
    assert.equal(r.proof, null);
    assert.equal(r.ledger, null);
    assert.deepEqual(codes(r), ["SKIP:no_proof", "FAIL:unsupported_version", "SKIP:no_proof", "SKIP:no_proof", "FAIL:failed"]);
    assert.deepEqual(r.verdict, { status: "FAIL", code: "failed", block: null, time: null, unverified: [] });
  }
  const r = await core.buildReport({ proof: null });
  assert.deepEqual(r.error, { code: "bad_magic" });
  const empty = await core.buildReport({ proof: new Uint8Array(0) });
  assert.deepEqual(empty, r);
});

test("unverified attestations are listed in index order, whatever the verdict", async () => {
  const r = await core.buildReport({ proof: readBin("different-blockchains", "proof.ots") });
  assertValid(r);
  const kinds = r.proof.attestations.map((a) => a.kind);
  const want = kinds.flatMap((k, i) => (k === "bitcoin" ? [] : [i]));
  assert.ok(want.length >= 3);
  assert.deepEqual(r.verdict.unverified, want);
  assert.deepEqual(r.proof.attestations.filter((a) => a.kind === "pending").every((a) => a.uri.startsWith("https://") && a.height === null && a.phases === null && a.where_to_look.length === 0), true);
  const eth = await core.buildReport({ proof: readBin("eth", "proof.ots"), file: fileOf(readBin("eth", "data.bin")) });
  assert.deepEqual(eth.verdict.unverified, [0, 1]);
  assert.equal(eth.proof.attestations[1].kind, "ethereum");
  assert.equal(eth.proof.attestations[1].height, 3283690);
  // no bitcoin attestation: ledger requested -> no_bitcoin
  const nb = await core.buildReport({ proof: readBin("eth", "proof.ots"), ledger: { fetchText: async () => { throw new Error("x"); } } });
  assert.equal(nb.steps[3].code, "no_bitcoin");
  assert.equal(nb.ledger, null);
  assert.deepEqual(codes(nb).slice(3), ["SKIP:no_bitcoin", "SKIP:incomplete"]);
});

test("every vector, every mode: report validates against the schema", async () => {
  for (const v of vectorIndex()) {
    const proof = readBin(v.id, "proof.ots");
    const parsed = core.parseProof(proof);
    const reports = [await core.buildReport({ proof })];
    if (hasFile(v.id, "data.bin")) reports.push(await core.buildReport({ proof, file: fileOf(readBin(v.id, "data.bin")) }));
    if (parsed.ok) reports.push(await core.buildReport({ proof, digestHex: core.hex(parsed.proof.digest) }));
    for (const r of reports) assertValid(r, `${v.id}/${r.input.mode}`);
  }
});

test("data.bin vectors verify offline (file mode step 1/2/3 PASS), bad-stamp too", async () => {
  for (const v of vectorIndex()) {
    if (!hasFile(v.id, "data.bin")) continue;
    const parsed = core.parseProof(readBin(v.id, "proof.ots"));
    if (parsed.proof.hashOp === "ripemd160") continue;
    const r = await core.buildReport({ proof: readBin(v.id, "proof.ots"), file: fileOf(readBin(v.id, "data.bin")) });
    assert.deepEqual(codes(r).slice(0, 3), ["PASS:ok", "PASS:ok", "PASS:ok"], v.id);
  }
});

test("canonical JSON of a report is deterministic and ASCII", async () => {
  const proof = readBin("two-calendars", "proof.ots");
  const a = core.canonicalJson(await core.buildReport({ proof }));
  const b = core.canonicalJson(await core.buildReport({ proof }));
  assert.equal(a, b);
  assert.ok(/^[\x20-\x7e]*$/.test(a));
  assert.ok(a.startsWith('{"error":null,"input":{'));
  assert.ok(a.endsWith("}"));
});

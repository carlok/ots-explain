import { test } from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { join } from "node:path";
import { core, H, cat, hdr, append, prepend, btc, pending, readBin, hasFile, validateSchema, REPORT_SCHEMA, VECTORS } from "./helper.mjs";
import { fileFetch, MOCK2 } from "./fakefetch.mjs";
import { Explorer, mineHeader, hashOf, router, makeProof } from "./explorer.mjs";

const fileOf = (bytes) => ({ size: bytes.length, digest: (alg) => core.hashBytes(alg, bytes) });
const checks = (srv) => srv.checks.map((c) => `${c.id}:${c.status}:${c.code}`);
const OK = ["block_hash:PASS:ok", "header:PASS:ok", "merkle_root:PASS:ok", "txids:PASS:ok", "raw_tx:PASS:ok", "output:PASS:ok"];
const hello = () => ({ proof: readBin("hello-world", "proof.ots"), file: fileOf(readBin("hello-world", "data.bin")) });
const HW_TXID = "7e9f0f7d9daa2d9e51b2e22f4abe814c3f90539afa778a9bef88dc64627cb2ec";
const HW_HASH = "65a379c0fd0e551ed48289653e82aa8aaebb8d72901cca05c09b6f211afd9948";

async function run(opts, servers = MOCK2, fetchText = fileFetch()) {
  const r = await core.buildReport({ ...opts, ledger: { servers, fetchText } });
  assert.deepEqual(validateSchema(REPORT_SCHEMA, r), []);
  return r;
}

test("all pass on hello-world with two servers", async () => {
  const log = [];
  const r = await run(hello(), MOCK2, fileFetch({ log }));
  assert.deepEqual(r.steps.map((s) => `${s.status}:${s.code}`), ["PASS:ok", "PASS:ok", "PASS:ok", "PASS:ok", "PASS:proved"]);
  assert.equal(r.verdict.status, "PASS");
  assert.equal(r.verdict.block, 358391);
  const header = readFileSync(join(VECTORS, "explorer", "synthetic", "block", HW_HASH, "header"), "utf8");
  const time = Buffer.from(header, "hex").readUInt32LE(68);
  assert.equal(r.verdict.time, time);
  assert.equal(r.ledger.attestations.length, 1);
  const a = r.ledger.attestations[0];
  assert.equal(a.attestation, 0);
  assert.equal(a.agree, true);
  assert.deepEqual(a.servers.map((s) => s.server), ["blockstream.info", "mempool.space"]);
  for (const s of a.servers) {
    assert.equal(s.status, "PASS");
    assert.equal(s.block_hash, HW_HASH);
    assert.equal(s.header, header);
    assert.equal(s.time, time);
    assert.deepEqual(checks(s), OK);
  }
  assert.deepEqual(r.ledger.servers, MOCK2);
  // requests: per server, in order, exactly the four plan URLs with the placeholders filled in
  assert.deepEqual(log, [
    "mock://synthetic/block-height/358391", `mock://synthetic/block/${HW_HASH}/header`, `mock://synthetic/block/${HW_HASH}/txids`, `mock://synthetic/tx/${HW_TXID}/hex`,
    "mock://synthetic/block-height/358391", `mock://synthetic/block/${HW_HASH}/header`, `mock://synthetic/block/${HW_HASH}/txids`, `mock://synthetic/tx/${HW_TXID}/hex`,
  ]);
  assert.deepEqual(r.ledger.plan.map((p) => [p.attestation, p.server, p.url]), [
    [0, "blockstream.info", "mock://synthetic/block-height/358391"],
    [0, "blockstream.info", "mock://synthetic/block/{block_hash}/header"],
    [0, "blockstream.info", "mock://synthetic/block/{block_hash}/txids"],
    [0, "blockstream.info", `mock://synthetic/tx/${HW_TXID}/hex`],
    [0, "mempool.space", "mock://synthetic/block-height/358391"],
    [0, "mempool.space", "mock://synthetic/block/{block_hash}/header"],
    [0, "mempool.space", "mock://synthetic/block/{block_hash}/txids"],
    [0, "mempool.space", `mock://synthetic/tx/${HW_TXID}/hex`],
  ]);
});

test("all pass with a single server (agree is null) and with the default server list", async () => {
  const single = await run(hello(), [MOCK2[0]]);
  assert.equal(single.ledger.attestations[0].agree, null);
  assert.equal(single.verdict.status, "PASS");
  // default servers: names and https bases, mapped by an injected router
  const urls = [];
  const def = await core.buildReport({
    ...hello(),
    ledger: {
      fetchText: (url) => {
        urls.push(url);
        return fileFetch()(url.replace("https://blockstream.info/api", "mock://synthetic").replace("https://mempool.space/api", "mock://synthetic"));
      },
    },
  });
  assert.deepEqual(def.ledger.servers, [{ name: "blockstream.info", base: "https://blockstream.info/api" }, { name: "mempool.space", base: "https://mempool.space/api" }]);
  assert.equal(def.verdict.status, "PASS");
  assert.equal(urls[0], "https://blockstream.info/api/block-height/358391");
  assert.equal(urls[4], "https://mempool.space/api/block-height/358391");
  // an empty list means the defaults
  const empty = await core.buildReport({ ...hello(), ledger: { servers: [], fetchText: async () => ({ status: 500, body: "" }) } });
  assert.equal(empty.ledger.servers.length, 2);
  // user-supplied servers are named as given, trailing slashes dropped from the base
  const custom = await run(hello(), [{ name: "https://my.esplora/api", base: "mock://synthetic/" }]);
  assert.deepEqual(custom.ledger.servers, [{ name: "https://my.esplora/api", base: "mock://synthetic" }]);
  assert.equal(custom.ledger.attestations[0].servers[0].server, "https://my.esplora/api");
  assert.equal(custom.verdict.status, "PASS");
});

test("ledgerPlan before any request", () => {
  const p = core.parseProof(readBin("hello-world", "proof.ots")).proof;
  const plan = core.ledgerPlan(p);
  assert.equal(plan.length, 8);
  assert.deepEqual(plan.slice(0, 4).map((x) => x.url), [
    "https://blockstream.info/api/block-height/358391",
    "https://blockstream.info/api/block/{block_hash}/header",
    "https://blockstream.info/api/block/{block_hash}/txids",
    `https://blockstream.info/api/tx/${HW_TXID}/hex`,
  ]);
  assert.equal(plan[4].server, "mempool.space");
  assert.deepEqual(core.ledgerPlan(core.parseProof(readBin("two-calendars", "proof.ots")).proof), []);
  assert.deepEqual(core.normalizeServers(null), core.DEFAULT_SERVERS.map((s) => ({ ...s })));
});

test("bad-stamp: merkle_root FAIL, the rest not_run, verdict FAIL", async () => {
  const r = await run({ proof: readBin("bad-stamp", "proof.ots"), file: fileOf(readBin("bad-stamp", "data.bin")) });
  assert.equal(r.steps[3].status, "FAIL");
  assert.equal(r.steps[3].code, "check_failed");
  assert.equal(r.verdict.status, "FAIL");
  assert.equal(r.verdict.block, null);
  assert.equal(r.verdict.time, null);
  for (const s of r.ledger.attestations[0].servers) {
    assert.equal(s.status, "FAIL");
    assert.deepEqual(checks(s), [
      "block_hash:PASS:ok", "header:PASS:ok", "merkle_root:FAIL:mismatch",
      "txids:SKIP:not_run", "raw_tx:SKIP:not_run", "output:SKIP:not_run",
    ]);
    assert.ok(s.header && s.time && s.block_hash); // known as soon as received
  }
});

test("lying second server: agree=false and ledger FAIL (disagree takes precedence)", async () => {
  const fetchText = router({ "mock://synthetic-lying": fileFetch(), "mock://synthetic/": fileFetch() });
  const servers = [{ name: "honest", base: "mock://synthetic" }, { name: "liar", base: "mock://synthetic-lying" }];
  const r = await run(hello(), servers, fetchText);
  const a = r.ledger.attestations[0];
  assert.equal(a.agree, false);
  assert.equal(a.servers[0].status, "PASS");
  assert.equal(a.servers[1].status, "FAIL");
  assert.deepEqual(checks(a.servers[1]).slice(0, 3), ["block_hash:PASS:ok", "header:PASS:ok", "merkle_root:FAIL:mismatch"]);
  assert.deepEqual(r.steps[3], { id: "ledger", title: "The ledger", status: "FAIL", code: "disagree" });
  assert.equal(r.verdict.status, "FAIL");
});

test("disagree without any failing check: headers differ but both match the proof", async () => {
  const p = makeProof();
  const proof = cat(hdr({ digest: p.digest }), prepend(p.pre), append(p.post), "0808", btc(5));
  const root = core.parseProof(proof).proof.nodes.at(-1).msg;
  const e1 = new Explorer(), e2 = new Explorer();
  e1.addBlock({ height: 5, header: mineHeader({ merkleRoot: root, time: 1500000000 }), txids: [p.txid], txs: { [p.txid]: core.hex(p.tx) } });
  e2.addBlock({ height: 5, header: mineHeader({ merkleRoot: root, time: 1500000111 }), txids: [p.txid], txs: { [p.txid]: core.hex(p.tx) } });
  const f = router({ "mem://a": e1.fetcher("a"), "mem://b": e2.fetcher("b") });
  const r = await run({ proof, digestHex: core.hex(p.digest) }, [{ name: "a", base: "mem://a" }, { name: "b", base: "mem://b" }], f);
  const a = r.ledger.attestations[0];
  assert.deepEqual(a.servers.map((s) => s.status), ["PASS", "PASS"]);
  assert.equal(a.agree, false);
  assert.deepEqual(r.steps[3], { id: "ledger", title: "The ledger", status: "FAIL", code: "disagree" });
});

test("agree: null with one header, true with equal, false with two differing among three", () => {
  const sr = (header) => ({ header });
  assert.equal(core.agreeOf([sr(null), sr("aa")]), null);
  assert.equal(core.agreeOf([sr(null), sr(null)]), null);
  assert.equal(core.agreeOf([sr("aa"), sr("aa"), sr(null)]), true);
  assert.equal(core.agreeOf([sr("aa"), sr("aa"), sr("bb")]), false);
});

test("404 is not_found FAIL; network errors and other statuses are unreachable SKIP", async () => {
  let n = 0;
  const base404 = fileFetch();
  let r = await run(hello(), MOCK2, async (u) => (u.includes("block-height") && ++n === 2 ? { status: 404, body: "Block not found" } : base404(u)));
  let a = r.ledger.attestations[0];
  assert.deepEqual(checks(a.servers[1]), ["block_hash:FAIL:not_found", "header:SKIP:not_run", "merkle_root:SKIP:not_run", "txids:SKIP:not_run", "raw_tx:SKIP:not_run", "output:SKIP:not_run"]);
  assert.equal(a.servers[1].status, "FAIL");
  assert.equal(a.servers[1].block_hash, null);
  assert.equal(a.agree, null);
  assert.equal(r.steps[3].code, "check_failed");
  assert.equal(r.verdict.status, "FAIL");

  // fetch throws: unreachable SKIP, ledger incomplete, verdict SKIP
  r = await run(hello(), MOCK2, async () => { throw new Error("offline"); });
  assert.deepEqual(r.steps[3], { id: "ledger", title: "The ledger", status: "SKIP", code: "incomplete" });
  assert.equal(r.verdict.status, "SKIP");
  assert.equal(r.verdict.code, "incomplete");
  assert.deepEqual(checks(r.ledger.attestations[0].servers[0])[0], "block_hash:SKIP:unreachable");
  assert.equal(r.ledger.attestations[0].servers[0].status, "SKIP");
  assert.equal(r.ledger.attestations[0].agree, null);
  // rejected promise (not a sync throw) and a non-object result
  r = await run(hello(), MOCK2, () => Promise.reject(new Error("x")));
  assert.equal(r.steps[3].code, "incomplete");
  r = await run(hello(), MOCK2, async () => undefined);
  assert.equal(r.steps[3].code, "incomplete");
  // any status but 200 / 404 is unreachable, at every stage
  for (const [fragment, id, idx] of [["block-height", "block_hash", 0], ["/header", "header", 1], ["/txids", "txids", 3], ["/hex", "raw_tx", 4]]) {
    for (const status of [500, 503, 429, 301, 403, 204]) {
      const base = fileFetch();
      r = await run(hello(), [MOCK2[0]], async (u) => (u.includes(fragment) ? { status, body: "x" } : base(u)));
      const c = r.ledger.attestations[0].servers[0].checks[idx];
      assert.deepEqual([c.id, c.status, c.code], [id, "SKIP", "unreachable"], `${fragment} ${status}`);
      assert.equal(r.verdict.status, "SKIP");
    }
    const base = fileFetch();
    r = await run(hello(), [MOCK2[0]], async (u) => (u.includes(fragment) ? { status: 404, body: "" } : base(u)));
    const c = r.ledger.attestations[0].servers[0].checks[idx];
    assert.deepEqual([c.id, c.status, c.code], [id, "FAIL", "not_found"]);
  }
});

test("malformed bodies are bad_response (block hash, header, txids, raw tx)", async () => {
  const bodyFor = (fragment, body) => {
    const base = fileFetch();
    return async (u) => (u.includes(fragment) ? { status: 200, body } : base(u));
  };
  const cases = [
    ["block-height", "xyz", 0], ["block-height", "ab".repeat(31), 0], ["block-height", "ab".repeat(33), 0], ["block-height", "", 0], ["block-height", "zz".repeat(32), 0],
    ["/header", "ab".repeat(79), 1], ["/header", "ab".repeat(81), 1], ["/header", "zz".repeat(80), 1], ["/header", "", 1],
    ["/txids", "not json", 3], ["/txids", '{"a":1}', 3], ["/txids", "[1,2]", 3], ["/txids", '["a", 2]', 3], ["/txids", "", 3], ["/txids", "null", 3],
    ["/hex", "zz", 4], ["/hex", "abc", 4], ["/hex", "", 4], ["/hex", "00", 4 /* mismatch */],
  ];
  for (const [fragment, body, idx] of cases) {
    const r = await run(hello(), [MOCK2[0]], bodyFor(fragment, body));
    const c = r.ledger.attestations[0].servers[0].checks[idx];
    const want = fragment === "/hex" && body === "00" ? "mismatch" : "bad_response";
    assert.deepEqual([c.status, c.code], ["FAIL", want], `${fragment} ${JSON.stringify(body)}`);
    assert.equal(r.verdict.status, "FAIL");
  }
  // a fetch result without a string body counts as an empty body
  const nb = fileFetch();
  const r0 = await run(hello(), [MOCK2[0]], async (u) => (u.includes("block-height") ? { status: 200, body: undefined } : nb(u)));
  assert.equal(r0.ledger.attestations[0].servers[0].checks[0].code, "bad_response");
  // surrounding whitespace is trimmed on the hash, header and tx bodies
  const base = fileFetch();
  const ws = async (u) => {
    const r = await base(u);
    return r.status === 200 && !u.includes("/txids") ? { status: 200, body: "\n  " + r.body + " \r\n" } : r;
  };
  const r = await run(hello(), [MOCK2[0]], ws);
  assert.equal(r.verdict.status, "PASS");
  // upper-case hex is accepted and normalised
  const up = async (u) => {
    const r = await base(u);
    return r.status === 200 && !u.includes("/txids") ? { status: 200, body: r.body.toUpperCase() } : r;
  };
  const r2 = await run(hello(), [MOCK2[0]], up);
  assert.equal(r2.verdict.status, "PASS");
  assert.equal(r2.ledger.attestations[0].servers[0].block_hash, HW_HASH);
});

test("header checks: bad_hash, bad_pow (target and nBits), header known even when a later check fails", async () => {
  const hdrHex = readFileSync(join(VECTORS, "explorer", "synthetic", "block", HW_HASH, "header"), "utf8");
  const real = H(hdrHex);
  const base = fileFetch();
  // a header that does not hash to the announced hash
  const other = Uint8Array.from(real);
  other[79] ^= 1;
  let r = await run(hello(), [MOCK2[0]], async (u) => (u.includes("/header") ? { status: 200, body: core.hex(other) } : base(u)));
  let s = r.ledger.attestations[0].servers[0];
  assert.deepEqual(checks(s).slice(0, 3), ["block_hash:PASS:ok", "header:FAIL:bad_hash", "merkle_root:SKIP:not_run"]);
  assert.equal(s.header, core.hex(other));
  assert.equal(s.time, null);
  assert.equal(s.block_hash, HW_HASH);
  // a consistent header (hash matches) whose work is insufficient for its nBits
  for (const bits of [0x1d00ffff, 0x20800001 /* sign bit */, 0x1d000000 /* zero mantissa */, 0xff7fffff /* overflow */]) {
    const weak = Uint8Array.from(real);
    new DataView(weak.buffer).setUint32(72, bits, true);
    const h = hashOf(weak);
    r = await run(hello(), [MOCK2[0]], async (u) => {
      if (u.includes("block-height")) return { status: 200, body: h };
      if (u.includes("/header")) return { status: 200, body: core.hex(weak) };
      return base(u);
    });
    s = r.ledger.attestations[0].servers[0];
    assert.deepEqual(checks(s).slice(0, 2), ["block_hash:PASS:ok", "header:FAIL:bad_pow"], bits.toString(16));
    assert.equal(s.header, core.hex(weak));
    assert.equal(s.time, null);
  }
});

test("txids and raw transaction checks", async () => {
  const base = fileFetch();
  // not in the block
  let r = await run(hello(), [MOCK2[0]], async (u) => (u.includes("/txids") ? { status: 200, body: JSON.stringify(["00".repeat(32)]) } : base(u)));
  assert.deepEqual(checks(r.ledger.attestations[0].servers[0]).slice(3), ["txids:FAIL:not_in_block", "raw_tx:SKIP:not_run", "output:SKIP:not_run"]);
  // an empty array
  r = await run(hello(), [MOCK2[0]], async (u) => (u.includes("/txids") ? { status: 200, body: "[]" } : base(u)));
  assert.equal(r.ledger.attestations[0].servers[0].checks[3].code, "not_in_block");
  // a different but well-formed transaction
  const goodTx = readFileSync(join(VECTORS, "explorer", "synthetic", "tx", HW_TXID, "hex"), "utf8");
  const altered = goodTx.slice(0, 20) + (goodTx[20] === "0" ? "1" : "0") + goodTx.slice(21);
  r = await run(hello(), [MOCK2[0]], async (u) => (u.includes("/hex") ? { status: 200, body: altered } : base(u)));
  assert.deepEqual(checks(r.ledger.attestations[0].servers[0]).slice(4), ["raw_tx:FAIL:mismatch", "output:SKIP:not_run"]);
  // a segwit-wrapped transaction with witness data passes once the witness is removed (gdp2q25 fixture)
  const gdp = { proof: readBin("gdp2q25", "proof.ots") };
  r = await run({ ...gdp, digestHex: core.hex(core.parseProof(gdp.proof).proof.digest) });
  assert.deepEqual(r.steps.map((s) => s.code), ["ok", "ok", "ok", "ok", "proved"]);
  assert.equal(r.verdict.block, 912095);
  // malformed witness data is a bad response
  const segTx = readFileSync(join(VECTORS, "explorer", "synthetic", "tx", "fcf172401ca9d89013f13f5bbf0fc7577cb8a3588bf5cbc3b458ff36635fec00", "hex"), "utf8").trim();
  r = await run({ ...gdp, digestHex: core.hex(core.parseProof(gdp.proof).proof.digest) }, [MOCK2[0]], async (u) => (u.includes("/hex") ? { status: 200, body: segTx.slice(0, -2) } : base(u)));
  assert.equal(r.ledger.attestations[0].servers[0].checks[4].code, "bad_response");
});

test("every Bitcoin vector passes the synthetic ledger with the file or the proof digest", async () => {
  const seen = [];
  for (const id of ["hello-world", "empty", "different-blockchains", "bitcoin-pdf", "sha1-a", "sha1-b", "osdsp", "gdp2q25"]) {
    const proof = readBin(id, "proof.ots");
    const parsed = core.parseProof(proof).proof;
    const opts = hasFile(id, "data.bin") ? { proof, file: fileOf(readBin(id, "data.bin")) } : { proof, digestHex: core.hex(parsed.digest) };
    const r = await run(opts);
    assert.deepEqual(r.steps.map((s) => s.status), ["PASS", "PASS", "PASS", "PASS", "PASS"], id);
    assert.equal(r.verdict.block, parsed.attestations.find((a) => a.kind === "bitcoin").height);
    assert.ok(r.verdict.time > 0);
    seen.push(id);
  }
  assert.equal(seen.length, 8);
});

// ---- scenarios with in-memory servers ----

test("phases == null: block checks run, then no_transaction (and not_run after a failure)", async () => {
  // a Bitcoin attestation with no transaction on its path
  const digest = new Uint8Array(32).fill(0x22);
  const proof = cat(hdr({ digest }), "08", btc(9));
  const parsed = core.parseProof(proof).proof;
  const root = parsed.nodes.at(-1).msg;
  const ex = new Explorer();
  ex.addBlock({ height: 9, header: mineHeader({ merkleRoot: root }) });
  const S = [{ name: "m", base: "mem://m" }];
  let r = await run({ proof, digestHex: core.hex(digest) }, S, ex.fetcher("m"));
  const s = r.ledger.attestations[0].servers[0];
  assert.deepEqual(checks(s), ["block_hash:PASS:ok", "header:PASS:ok", "merkle_root:PASS:ok", "txids:SKIP:no_transaction", "raw_tx:SKIP:no_transaction", "output:SKIP:no_transaction"]);
  assert.equal(s.status, "SKIP");
  assert.deepEqual(r.steps[3], { id: "ledger", title: "The ledger", status: "SKIP", code: "incomplete" });
  assert.equal(r.verdict.status, "SKIP");
  assert.deepEqual(r.proof.attestations[0].where_to_look, []);
  // the plan carries only the two requests that can happen
  assert.deepEqual(r.ledger.plan.map((x) => x.url), ["mem://m/block-height/9", "mem://m/block/{block_hash}/header"]);
  // when merkle_root fails, the rest are not_run
  const ex2 = new Explorer();
  ex2.addBlock({ height: 9, header: mineHeader({ merkleRoot: new Uint8Array(32).fill(3) }) });
  r = await run({ proof, digestHex: core.hex(digest) }, S, ex2.fetcher("m"));
  assert.deepEqual(checks(r.ledger.attestations[0].servers[0]).slice(2), ["merkle_root:FAIL:mismatch", "txids:SKIP:not_run", "raw_tx:SKIP:not_run", "output:SKIP:not_run"]);
  assert.equal(r.steps[3].code, "check_failed");
});

test("output check: no_output FAIL when no output script contains the commitment", async () => {
  const p = makeProof({ inInput: true });
  const proof = cat(hdr({ digest: p.digest }), prepend(p.pre), append(p.post), "0808", btc(4));
  const root = core.parseProof(proof).proof.nodes.at(-1).msg;
  const ex = new Explorer();
  ex.addBlock({ height: 4, header: mineHeader({ merkleRoot: root }), txids: [p.txid], txs: { [p.txid]: core.hex(p.tx) } });
  const r = await run({ proof, digestHex: core.hex(p.digest) }, [{ name: "m", base: "mem://m" }], ex.fetcher("m"));
  assert.equal(r.proof.attestations[0].phases.output, null);
  assert.deepEqual(checks(r.ledger.attestations[0].servers[0]).slice(3), ["txids:PASS:ok", "raw_tx:PASS:ok", "output:FAIL:no_output"]);
  assert.equal(r.steps[3].code, "check_failed");
  assert.equal(r.verdict.status, "FAIL");
});

test("two Bitcoin attestations: verdict names the lowest height and its own time", async () => {
  const p = makeProof();
  const x = new Uint8Array(32).fill(0x77);
  // after the txid hash: attestation at height 20 directly; branch with append+sha256 and height 10
  const proof = cat(hdr({ digest: p.digest }), prepend(p.pre), append(p.post), "08", "08", "ff", btc(20), append(x), "08", btc(10));
  const parsed = core.parseProof(proof).proof;
  assert.deepEqual(parsed.attestations.map((a) => a.height), [20, 10]);
  const ex = new Explorer();
  const h20 = mineHeader({ merkleRoot: parsed.nodes[parsed.attestations[0].node].msg, time: 1600000020 });
  const h10 = mineHeader({ merkleRoot: parsed.nodes[parsed.attestations[1].node].msg, time: 1600000010 });
  ex.addBlock({ height: 20, header: h20, txids: [p.txid], txs: { [p.txid]: core.hex(p.tx) } });
  ex.addBlock({ height: 10, header: h10, txids: [p.txid], txs: { [p.txid]: core.hex(p.tx) } });
  const r = await run({ proof, digestHex: core.hex(p.digest) }, [{ name: "m", base: "mem://m" }], ex.fetcher("m"));
  assert.deepEqual(r.ledger.attestations.map((a) => a.attestation), [0, 1]);
  assert.deepEqual(r.ledger.plan.map((x) => x.attestation), [0, 0, 0, 0, 1, 1, 1, 1]);
  assert.equal(r.steps[3].status, "PASS");
  assert.equal(r.steps[0].status, "PASS");
  assert.equal(r.verdict.status, "PASS");
  assert.equal(r.verdict.block, 10);
  assert.equal(r.verdict.time, 1600000010);
  // one of the two failing makes the ledger FAIL
  ex.delete("block-height/20");
  const r2 = await run({ proof, digestHex: core.hex(p.digest) }, [{ name: "m", base: "mem://m" }], ex.fetcher("m"));
  assert.equal(r2.steps[3].code, "check_failed");
  assert.equal(r2.verdict.status, "FAIL");
  // a pending attestation next to a verified Bitcoin one does not block PASS
  const withPending = cat(hdr({ digest: p.digest }), prepend(p.pre), append(p.post), "08", "08", "ff", btc(20), pending("https://c.example"));
  const wp = core.parseProof(withPending).proof;
  const ex3 = new Explorer();
  ex3.addBlock({ height: 20, header: mineHeader({ merkleRoot: wp.nodes[wp.attestations[0].node].msg, time: 1600000020 }), txids: [p.txid], txs: { [p.txid]: core.hex(p.tx) } });
  const r3 = await run({ proof: withPending, digestHex: core.hex(p.digest) }, [{ name: "m", base: "mem://m" }], ex3.fetcher("m"));
  assert.equal(r3.verdict.status, "PASS");
  assert.deepEqual(r3.verdict.unverified, [1]);
});

test("no ledger object unless requested and a Bitcoin attestation exists", async () => {
  const proof = readBin("hello-world", "proof.ots");
  const never = async () => { throw new Error("must not be called"); };
  const r = await core.buildReport({ proof, ledger: null });
  assert.equal(r.ledger, null);
  assert.equal(r.steps[3].code, "not_requested");
  const l = await core.runLedger(core.parseProof(readBin("two-calendars", "proof.ots")).proof, null, never);
  assert.equal(l, null);
});

test("ledgerOutcome precedence: disagree, then check_failed, then incomplete, then ok", () => {
  const mk = (agree, statuses) => ({ servers: [], plan: [], attestations: [{ attestation: 0, agree, servers: [{ checks: statuses.map((status) => ({ status })) }] }] });
  assert.deepEqual(core.ledgerOutcome(mk(false, ["FAIL"])), { status: "FAIL", code: "disagree" });
  assert.deepEqual(core.ledgerOutcome(mk(false, ["PASS"])), { status: "FAIL", code: "disagree" });
  assert.deepEqual(core.ledgerOutcome(mk(null, ["FAIL", "SKIP"])), { status: "FAIL", code: "check_failed" });
  assert.deepEqual(core.ledgerOutcome(mk(true, ["PASS", "SKIP"])), { status: "SKIP", code: "incomplete" });
  assert.deepEqual(core.ledgerOutcome(mk(true, ["PASS"])), { status: "PASS", code: "ok" });
});

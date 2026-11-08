import { test } from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { join } from "node:path";
import {
  core, H, cat, hdr, append, prepend, btc, pending, proofOf, varuint, VECTORS, readBin, readJson, vectorIndex,
} from "./helper.mjs";

// ---- handcrafted transactions ----
const cs = (n) => {
  if (n < 0xfd) return Uint8Array.of(n);
  if (n <= 0xffff) return Uint8Array.of(0xfd, n & 255, n >> 8);
  return Uint8Array.of(0xfe, n & 255, (n >> 8) & 255, (n >> 16) & 255, (n >>> 24) & 255);
};
const input = (script = new Uint8Array(0)) => cat(new Uint8Array(32).fill(9), "00000000", cs(script.length), script, "ffffffff");
const output = (script, value = "0000000000000000") => cat(value, cs(script.length), script);
const tx = ({ ins = [input()], outs = [output(H("6a01ff"))] } = {}) =>
  cat("01000000", cs(ins.length), ...ins, cs(outs.length), ...outs, "00000000");
const segwit = (ins, outs, wit) => cat("01000000", "0001", cs(ins.length), ...ins, cs(outs.length), ...outs, ...wit, "00000000");

test("readCompactSize: all four forms and truncations", () => {
  assert.deepEqual(core.readCompactSize(H("05"), 0), { value: 5, next: 1 });
  assert.deepEqual(core.readCompactSize(H("fc"), 0), { value: 252, next: 1 });
  assert.deepEqual(core.readCompactSize(H("fdfd00"), 0), { value: 253, next: 3 });
  assert.deepEqual(core.readCompactSize(H("fdffff"), 0), { value: 65535, next: 3 });
  assert.deepEqual(core.readCompactSize(H("fe00000100"), 0), { value: 65536, next: 5 });
  assert.deepEqual(core.readCompactSize(H("ff0100000000000000"), 0), { value: 1, next: 9 });
  assert.equal(core.readCompactSize(H("ff0000000001000000"), 0), null); // beyond 2^32
  assert.equal(core.readCompactSize(H(""), 0), null);
  assert.equal(core.readCompactSize(H("fd00"), 0), null);
  assert.equal(core.readCompactSize(H("fe000000"), 0), null);
  assert.equal(core.readCompactSize(H("ff00000000"), 0), null);
  assert.deepEqual(core.readCompactSize(H("aa05"), 1), { value: 5, next: 2 });
});

test("parseLegacyTx: accepts well-formed, rejects each malformation", () => {
  const good = tx();
  const p = core.parseLegacyTx(good);
  assert.equal(p.inputs, 1);
  assert.equal(p.outputs.length, 1);
  assert.equal(core.hex(p.outputs[0].script), "6a01ff");
  // multiple inputs/outputs and long scripts needing fd varints
  const big = tx({ ins: [input(new Uint8Array(300)), input(H("51"))], outs: [output(new Uint8Array(260)), output(H("51"), "0100000000000000")] });
  const pb = core.parseLegacyTx(big);
  assert.equal(pb.inputs, 2);
  assert.deepEqual(pb.outputs.map((o) => o.script.length), [260, 1]);
  // truncations
  for (let n = 0; n < good.length; n++) assert.equal(core.parseLegacyTx(good.subarray(0, n)), null, "cut " + n);
  // trailing byte
  assert.equal(core.parseLegacyTx(cat(good, "00")), null);
  // zero inputs / zero outputs
  assert.equal(core.parseLegacyTx(cat("01000000", "00", "01", output(H("51")), "00000000")), null);
  assert.equal(core.parseLegacyTx(cat("01000000", cs(1), input(), "00", "00000000")), null);
  // script length pointing past the end
  assert.equal(core.parseLegacyTx(cat("01000000", "01", new Uint8Array(32), "00000000", "fe00ffff00", "00")), null);
  assert.equal(core.parseLegacyTx(cat("01000000", "01", new Uint8Array(32), "00000000", "00", "ffffffff", "01", "0000000000000000", "ff0000000001000000")), null);
  // segwit form is not a legacy tx
  assert.equal(core.parseLegacyTx(segwit([input()], [output(H("51"))], [H("0100")])), null);
  assert.equal(core.parseLegacyTx(H("")), null);
  assert.equal(core.parseLegacyTx(H("01000000")), null);
});

test("stripWitness", () => {
  const ins = [input(), input(H("aa"))];
  const outs = [output(H("6a01ff")), output(H("51"))];
  const legacy = cat("01000000", "02", ...ins, "02", ...outs, "00000000");
  const wit = [H("02" + "02abcd" + "01ee"), H("00")];
  const sw = segwit(ins, outs, wit);
  assert.deepEqual(core.stripWitness(sw), legacy);
  assert.equal(core.stripWitness(legacy), legacy); // untouched when there is no marker
  const short = H("0100000000");
  assert.equal(core.stripWitness(short), short); // too short to carry a marker: returned as is
  // every strict prefix of a witness-form transaction is rejected
  for (let n = 6; n < sw.length; n++) assert.equal(core.stripWitness(sw.subarray(0, n)), null, "cut " + n);
  // malformed witness forms are rejected
  assert.equal(core.stripWitness(sw.subarray(0, sw.length - 1)), null);
  assert.equal(core.stripWitness(cat(sw, "00")), null);
  assert.equal(core.stripWitness(H("010000000001")), null);
  assert.equal(core.stripWitness(cat("01000000", "0001", "01", new Uint8Array(10))), null);
  assert.equal(core.stripWitness(cat("01000000", "0001", "01", new Uint8Array(32), "00000000", "00", "ffffffff", "01", "00")), null);
  assert.equal(core.stripWitness(cat("01000000", "0001", "01", new Uint8Array(32), "00000000", "00", "ffffffff", "01", "0000000000000000", "05")), null);
  // witness item longer than the data
  assert.equal(core.stripWitness(cat("01000000", "0001", "01", input(), "01", output(H("51")), "01", "fd0001", "00000000")), null);
  assert.equal(core.stripWitness(cat("01000000", "0001", "01", input(), "01", output(H("51")), "01", "00000000")) === null, true);
  assert.equal(core.stripWitness(cat("01000000", "0001", "ff0000000001000000")), null);
  assert.equal(core.stripWitness(cat("01000000", "0001", "01", new Uint8Array(40), "ff0000000001000000")), null);
  // a witness count that is not terminated
  assert.equal(core.stripWitness(cat("01000000", "0001", "01", input(), "01", output(H("51")))), null);
  assert.equal(core.stripWitness(cat("01000000", "0001", "01", input(), "01", output(H("51")), "fd")), null);
});

test("stripWitness on the gdp2q25 synthetic segwit tx equals the proof's transaction", () => {
  const proof = readBin("gdp2q25", "proof.ots");
  const parsed = core.parseProof(proof).proof;
  const att = parsed.attestations.find((a) => a.kind === "bitcoin");
  const ph = core.computePhases(parsed, att).phases;
  assert.equal(ph.txid, "fcf172401ca9d89013f13f5bbf0fc7577cb8a3588bf5cbc3b458ff36635fec00");
  const raw = H(readFileSync(join(VECTORS, "explorer", "synthetic", "tx", ph.txid, "hex"), "utf8").trim());
  assert.deepEqual([...raw.subarray(4, 6)], [0, 1], "fixture should be segwit-wrapped");
  const stripped = core.stripWitness(raw);
  const mt = parsed.nodes[ph.path[ph.transaction_index]].msg;
  assert.deepEqual(stripped, mt);
  assert.equal(core.hex(core.reversed(core.sha256d(stripped))), ph.txid);
});

test("classifyScript and findCommitmentOutput", () => {
  const h20 = new Uint8Array(20).fill(3);
  assert.equal(core.classifyScript(H("6a20" + "00".repeat(32))), "op_return");
  assert.equal(core.classifyScript(H("6a")), "op_return");
  assert.equal(core.classifyScript(cat("a914", h20, "87")), "p2sh");
  assert.equal(core.classifyScript(cat("76a914", h20, "88ac")), "p2pkh");
  assert.equal(core.classifyScript(cat("a914", h20, "88")), "other");
  assert.equal(core.classifyScript(cat("76a914", h20, "88ad")), "other");
  assert.equal(core.classifyScript(cat("76a914", h20, "88")), "other");
  assert.equal(core.classifyScript(H("")), "other");
  assert.equal(core.classifyScript(H("5120" + "11".repeat(32))), "other");
  // first matching output wins, search is by substring
  const commit = new Uint8Array(20).fill(0x42);
  const t = core.parseLegacyTx(tx({ outs: [output(H("51")), output(cat("76a914", commit, "88ac")), output(cat("6a14", commit))] }));
  const found = core.findCommitmentOutput(t, commit);
  assert.equal(found.index, 1);
  assert.equal(found.kind, "p2pkh");
  assert.equal(core.findCommitmentOutput(t, new Uint8Array(20).fill(1)), null);
});

test("nBits: compact target, bad forms, proof of work on the genesis block", () => {
  assert.equal(core.bitsToTarget(0x1d00ffff), 0xffffn << (8n * (0x1dn - 3n)));
  assert.equal(core.bitsToTarget(0x207fffff), 0x7fffffn << (8n * 0x1dn));
  assert.equal(core.bitsToTarget(0x03123456), 0x123456n);
  assert.equal(core.bitsToTarget(0x02123456), 0x1234n);
  assert.equal(core.bitsToTarget(0x01123456), 0x12n);
  assert.equal(core.bitsToTarget(0x04123456), 0x12345600n);
  assert.equal(core.bitsToTarget(0x01fedcba), null); // sign bit set
  assert.equal(core.bitsToTarget(0x1d000000), null); // zero mantissa
  assert.equal(core.bitsToTarget(0x23000001), null); // exponent too large
  assert.equal(core.bitsToTarget(0x22000100), null);
  assert.equal(core.bitsToTarget(0x21010000), null);
  assert.notEqual(core.bitsToTarget(0x20000001), null);
  const genesis = H("0100000000000000000000000000000000000000000000000000000000000000000000003ba3edfd7a7b12b27ac72c3e67768f617fc81bc3888a51323a9fb8aa4b1e5e4a29ab5f49ffff001d1dac2b7c");
  assert.equal(genesis.length, 80);
  assert.equal(core.hex(core.blockHashOf(genesis)), "000000000019d6689c085ae165831e934ff763ae46a2a6c172b3f1b60a8ce26f");
  assert.equal(core.meetsPow(genesis), true);
  const h = core.parseHeader(genesis);
  assert.equal(h.time, 1231006505);
  assert.equal(h.bits, 0x1d00ffff);
  assert.equal(core.hex(h.merkleRoot), "3ba3edfd7a7b12b27ac72c3e67768f617fc81bc3888a51323a9fb8aa4b1e5e4a");
  const tampered = Uint8Array.from(genesis);
  tampered[79] ^= 0xff;
  assert.equal(core.meetsPow(tampered), false);
  const badBits = Uint8Array.from(genesis);
  badBits[75] = 0x80; // sign bit
  assert.equal(core.meetsPow(badBits), false);
});

// ---- phases ----

test("phases: hello-world (c=1, t=3, known txid)", () => {
  const parsed = core.parseProof(readBin("hello-world", "proof.ots")).proof;
  const a = parsed.attestations[0];
  const r = core.computePhases(parsed, a);
  assert.equal(r.phases_code, null);
  const p = r.phases;
  assert.equal(p.commitment_index, 1);
  assert.equal(p.transaction_index, 3);
  assert.equal(p.txid_index, 5);
  assert.equal(p.root_index, 38);
  assert.equal(p.txid, "7e9f0f7d9daa2d9e51b2e22f4abe814c3f90539afa778a9bef88dc64627cb2ec");
  assert.equal(p.commitment, "1df8859e60bc679503d16dcb870e6ce91a57e9df");
  assert.equal(p.path.length, 39);
  assert.equal(p.path[0], 0);
  assert.equal(p.path.at(-1), a.node);
  assert.equal(p.output.kind, "p2pkh");
  assert.equal(p.output.index, 1);
  assert.equal(p.output.script, "76a9141df8859e60bc679503d16dcb870e6ce91a57e9df88ac");
  // merkle root of the block, internal order
  assert.equal(core.hex(core.reversed(parsed.nodes[a.node].msg)), "8a1b66ecb7cbd07d8139a7e7d7f2c41aab1f5009b8364aaf61d03ad245e47e00");
});

test("phases: every Bitcoin vector gives phases whose txid is the one `ots info` prints", () => {
  let n = 0;
  for (const v of vectorIndex()) {
    const parsed = core.parseProof(readBin(v.id, "proof.ots"));
    if (!parsed.ok) continue;
    const info = readFileSync(join(VECTORS, v.id, "reference.info.txt"), "utf8");
    const txm = /Transaction id (\w{64})/.exec(info);
    for (const a of parsed.proof.attestations) {
      const r = core.computePhases(parsed.proof, a);
      if (a.kind !== "bitcoin") {
        assert.equal(r.phases, null);
        assert.equal(r.phases_code, null);
        continue;
      }
      n++;
      assert.ok(r.phases, v.id);
      assert.equal(r.phases.txid, txm[1], v.id);
      const m = /Bitcoin block merkle root (\w{64})/.exec(info);
      assert.equal(core.hex(core.reversed(parsed.proof.nodes[a.node].msg)), m[1], v.id + " merkle root");
      assert.ok(r.phases.commitment_index < r.phases.transaction_index);
      assert.ok(r.phases.txid_index === r.phases.transaction_index + 2);
      assert.ok(r.phases.output, v.id + " has an output with the commitment");
    }
  }
  assert.ok(n >= 8);
});

test("phases: gdp2q25 has c = 0 (digest placed straight into the transaction)", () => {
  const parsed = core.parseProof(readBin("gdp2q25", "proof.ots")).proof;
  const a = parsed.attestations.find((x) => x.kind === "bitcoin");
  const p = core.computePhases(parsed, a).phases;
  assert.equal(p.commitment_index, 0);
  assert.equal(p.transaction_index, 2);
  assert.equal(p.commitment, core.hex(parsed.digest));
  assert.equal(p.output.kind, "op_return");
  assert.equal(p.output.index, 0);
});

test("phases: handcrafted transaction, p2sh output, merkle path ops after the txid", () => {
  const D = new Uint8Array(32).fill(0x11);
  const script = cat("6a20", D);
  const full = tx({ outs: [output(H("51")), output(script)] });
  const at = core.indexOfBytes(full, D);
  const pre = full.subarray(0, at), post = full.subarray(at + 32);
  const proof = cat(hdr({ digest: D }), prepend(pre), append(post), H("08"), H("08"), append(new Uint8Array(32).fill(5)), H("08"), btc(77));
  const parsed = core.parseProof(proof);
  assert.ok(parsed.ok);
  const p = core.computePhases(parsed.proof, parsed.proof.attestations[0]).phases;
  assert.equal(p.commitment_index, 0);
  assert.equal(p.transaction_index, 2);
  assert.equal(p.txid_index, 4);
  assert.equal(p.root_index, 6);
  assert.equal(p.output.index, 1);
  assert.equal(p.output.kind, "op_return");
  assert.equal(p.txid, core.hex(core.reversed(core.sha256d(full))));
  // not Bitcoin: no phases
  const ltc = core.parseProof(cat(hdr({ digest: D }), prepend(pre), append(post), H("08"), H("08"), core.concat(H("00" + "06869a0d73d71b45"), varuint(1), varuint(1))));
  assert.equal(core.computePhases(ltc.proof, ltc.proof.attestations[0]).phases, null);
});

test("phases: null when no transaction, when c == t, and when the txid hash is missing", () => {
  const D = new Uint8Array(32).fill(0x11);
  const code = (proofBytes) => {
    const p = core.parseProof(proofBytes).proof;
    const r = core.computePhases(p, p.attestations.find((a) => a.kind === "bitcoin"));
    return [r.phases, r.phases_code];
  };
  // no tx at all
  assert.deepEqual(code(proofOf(H("08"), H("08"), btc(1))), [null, "no_transaction"]);
  // the attestation hangs on the root: no op index >= 1 exists
  assert.deepEqual(code(proofOf(btc(1))), [null, "no_transaction"]);
  const full = tx({ outs: [output(cat("6a20", D))] });
  // txid hash missing: only one sha256 after the tx
  const at2 = core.indexOfBytes(full, D);
  const pre = full.subarray(0, at2), post = full.subarray(at2 + 32);
  assert.deepEqual(code(cat(hdr({ digest: D }), prepend(pre), append(post), H("08"), btc(1))), [null, "no_txid_hash"]);
  assert.deepEqual(code(cat(hdr({ digest: D }), prepend(pre), append(post), btc(1))), [null, "no_txid_hash"]);
  assert.deepEqual(code(cat(hdr({ digest: D }), prepend(pre), append(post), H("08"), H("02"), btc(1))), [null, "no_txid_hash"]);
  assert.deepEqual(code(cat(hdr({ digest: D }), prepend(pre), append(post), H("02"), H("08"), btc(1))), [null, "no_txid_hash"]);
});

test("phases: c == t gives null (the tx was produced by a hash op, not by append/prepend)", () => {
  // A SHA-1 file digest (20 bytes) is hashed by 'sha1'... we need a message that IS a legacy tx after a non-append/prepend op.
  // hexlify/reverse/sha ops cannot produce a parseable tx from short data, but 'reverse' can: reverse(tx_reversed) = tx.
  const D = new Uint8Array(32).fill(0x11);
  const full = tx({ outs: [output(cat("6a20", D))] });
  const rev = core.reversed(full);
  // digest -> prepend(revPrefix) -> append(revSuffix) gives rev(tx) when we choose pre/post around D
  const at = core.indexOfBytes(rev, D);
  const pre = rev.subarray(0, at), post = rev.subarray(at + 32);
  const proof = cat(hdr({ digest: D }), prepend(pre), append(post), H("f2"), H("08"), H("08"), btc(3));
  const parsed = core.parseProof(proof).proof;
  const r = core.computePhases(parsed, parsed.attestations[0]);
  assert.equal(r.phases, null);
  assert.equal(r.phases_code, "no_transaction");
});

test("phases: output is null when no output script contains the commitment", () => {
  const D = new Uint8Array(32).fill(0x11);
  // the digest sits in an input script, not in an output
  const full = tx({ ins: [input(cat("51", D))], outs: [output(H("51"))] });
  const at = core.indexOfBytes(full, D);
  const proof = cat(hdr({ digest: D }), prepend(full.subarray(0, at)), append(full.subarray(at + 32)), H("08"), H("08"), btc(3));
  const parsed = core.parseProof(proof).proof;
  const p = core.computePhases(parsed, parsed.attestations[0]).phases;
  assert.equal(p.output, null);
  assert.equal(p.commitment_index, 0);
});

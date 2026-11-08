import { test } from "node:test";
import assert from "node:assert/strict";
import {
  core, H, cat, hdr, append, prepend, att, btc, pending, proofOf, parseCode, varuint, varbytes,
  BTC, LTC, ETH, PENDING, MAGIC_HEX, readBin, readJson, vectorIndex, hasFile,
} from "./helper.mjs";

const Z = new Uint8Array(0);
const unary = (n, op = "08") => H(op.repeat(n));

test("MAGIC constant matches the spec", () => {
  assert.equal(core.hex(core.MAGIC), MAGIC_HEX);
  assert.equal(core.MAGIC.length, 31);
});

test("minimal valid proofs for all three header algorithms", () => {
  for (const [op, len, name] of [[0x08, 32, "sha256"], [0x02, 20, "sha1"], [0x03, 20, "ripemd160"]]) {
    const r = core.parseProof(cat(hdr({ op, digest: new Uint8Array(len).fill(1) }), btc(5)));
    assert.ok(r.ok, name);
    assert.equal(r.proof.hashOp, name);
    assert.equal(r.proof.nodes.length, 1);
    assert.equal(r.proof.maxDepth, 0);
    assert.equal(r.proof.attestations[0].height, 5);
  }
});

test("bad_magic: empty, short, and altered magic", () => {
  assert.equal(parseCode(Z), "bad_magic");
  assert.equal(parseCode(H(MAGIC_HEX).subarray(0, 30)), "bad_magic");
  const bad = proofOf(btc(1));
  bad[0] = 1;
  assert.equal(parseCode(bad), "bad_magic");
  const bad2 = proofOf(btc(1));
  bad2[30] ^= 1;
  assert.equal(parseCode(bad2), "bad_magic");
});

test("unsupported_version", () => {
  assert.equal(parseCode(cat(hdr({ version: 2 }), btc(1))), "unsupported_version");
  assert.equal(parseCode(cat(hdr({ version: 0 }), btc(1))), "unsupported_version");
  assert.equal(parseCode(cat(hdr({ version: 255 }), btc(1))), "unsupported_version");
});

test("unknown_file_hash_op (keccak is not a legal file hash op)", () => {
  for (const op of [0x67, 0x00, 0x01, 0xf0, 0xf2, 0xff]) {
    assert.equal(parseCode(cat(hdr({ op }), btc(1))), "unknown_file_hash_op", "op " + op);
  }
});

test("truncated: every place the file can end early", () => {
  const full = proofOf(append(H("aabb")), pending("https://a.example"));
  for (let n = 31; n < full.length; n++) {
    const code = parseCode(full.subarray(0, n));
    assert.ok(code === "truncated", `cut at ${n} gave ${code}`);
  }
  assert.equal(parseCode(full), "ok");
  // digest shorter than the algorithm needs
  assert.equal(parseCode(cat(MAGIC_HEX, "0108", new Uint8Array(31))), "truncated");
  // arg shorter than declared
  assert.equal(parseCode(proofOf(cat("f0", varuint(10), H("0102")))), "truncated");
  // attestation payload shorter than declared
  assert.equal(parseCode(proofOf(cat("00", BTC, varuint(5), H("01")))), "truncated");
  // attestation tag cut
  assert.equal(parseCode(proofOf(cat("00", "0588"))), "truncated");
  // 0xff marker with nothing after it
  assert.equal(parseCode(proofOf(H("ff"))), "truncated");
});

test("trailing_garbage", () => {
  assert.equal(parseCode(cat(proofOf(btc(1)), "00")), "trailing_garbage");
  assert.equal(parseCode(cat(proofOf(btc(1)), "ffff")), "trailing_garbage");
});

test("unknown_op", () => {
  assert.equal(parseCode(proofOf(H("42"))), "unknown_op");
  assert.equal(parseCode(proofOf(H("01"))), "unknown_op");
  assert.equal(parseCode(proofOf(H("ffff"))), "unknown_op"); // 0xff entry marker followed by 0xff
  assert.equal(parseCode(proofOf(H("ff42"))), "unknown_op");
});

test("repeated_op: same op and arg twice in one node", () => {
  assert.equal(parseCode(proofOf(H("ff"), append(H("aa")), btc(1), append(H("aa")), btc(2))), "repeated_op");
  assert.equal(parseCode(proofOf(H("ff"), prepend(H("aa")), btc(1), prepend(H("aa")), btc(2))), "repeated_op");
  // unary
  assert.equal(parseCode(proofOf(H("ff"), H("08"), btc(1), H("08"), btc(2))), "repeated_op");
  // different arg, or different op with the same arg, or a different unary op: fine
  assert.equal(parseCode(proofOf(H("ff"), append(H("aa")), btc(1), H("ff"), append(H("ab")), btc(1), H("ff"), prepend(H("aa")), btc(1), H("08"), btc(1))), "ok");
  // same op in different nodes: fine
  assert.equal(parseCode(proofOf(H("ff"), H("08"), H("08"), btc(1), H("02"), btc(2))), "ok");
});

test("arg_length: 0 and 4097; 1 and 4096 accepted", () => {
  assert.equal(parseCode(proofOf(cat("f0", varuint(0)), btc(1))), "arg_length");
  assert.equal(parseCode(proofOf(cat("f1", varuint(0)), btc(1))), "arg_length");
  assert.equal(parseCode(proofOf(cat("f0", varuint(4097), new Uint8Array(4097)), btc(1))), "arg_length");
  assert.equal(parseCode(proofOf(cat("f0", varuint(4096), new Uint8Array(4096)), btc(1))), "result_too_long");
  assert.equal(parseCode(proofOf(append(H("01")), btc(1))), "ok");
  // arg_length is decided from the length, before the bytes are needed
  assert.equal(parseCode(proofOf(cat("f0", varuint(5000)))), "arg_length");
  // a huge 63-bit length is still arg_length, not an overflow
  assert.equal(parseCode(proofOf(cat("f0", varuint(2n ** 62n)))), "arg_length");
});

test("result_too_long: 4096 accepted, 4097 rejected", () => {
  const ok = proofOf(append(new Uint8Array(4064)), btc(1)); // 32 + 4064 = 4096
  assert.equal(parseCode(ok), "ok");
  const bad = proofOf(append(new Uint8Array(4065)), btc(1));
  assert.equal(parseCode(bad), "result_too_long");
  // prepend too
  assert.equal(parseCode(proofOf(prepend(new Uint8Array(4065)), btc(1))), "result_too_long");
});

test("msg_too_long: hexlify input over 2048 bytes (the other ops can never see more than 4096)", () => {
  const mk = (extra) => proofOf(append(new Uint8Array(extra)), H("f3"), btc(1));
  assert.equal(parseCode(mk(2048 - 32)), "ok"); // 2048 -> 4096 hex bytes
  assert.equal(parseCode(mk(2049 - 32)), "msg_too_long");
  // sha256 of a 4096-byte message is fine
  assert.equal(parseCode(proofOf(append(new Uint8Array(4064)), H("08"), btc(1))), "ok");
});

test("empty_message cannot be reached from a non-empty digest; reverse/hexlify work", () => {
  const r = core.parseProof(proofOf(H("f2"), H("f3"), btc(1)));
  assert.ok(r.ok);
  assert.equal(r.proof.nodes[1].op, "reverse");
  assert.equal(core.hex(r.proof.nodes[1].msg), core.hex(new Uint8Array(32).fill(7)));
  assert.equal(r.proof.nodes[2].msg.length, 64);
  assert.equal(String.fromCharCode(...r.proof.nodes[2].msg), "07".repeat(32));
  const rev = core.parseProof(cat(hdr({ digest: H("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f") }), H("f2"), btc(1)));
  assert.equal(core.hex(rev.proof.nodes[1].msg), "1f1e1d1c1b1a191817161514131211100f0e0d0c0b0a09080706050403020100");
});

test("varuint: 9 bytes allowed, 10th is varuint_too_long", () => {
  // eight continuation bytes + a final one = 9 bytes, value 0 with padding: legal
  assert.equal(parseCode(proofOf(cat("f0", H("8080808080808080" + "00")), btc(1))), "arg_length"); // value 0 -> arg_length (min 1)
  // a 9-byte encoding of 1
  assert.equal(parseCode(proofOf(cat("f0", H("8180808080808080" + "00"), H("aa")), btc(1))), "ok");
  // nine continuation bytes: the reader gives up
  assert.equal(parseCode(proofOf(cat("f0", H("80".repeat(9)), H("00")))), "varuint_too_long");
  assert.equal(parseCode(proofOf(cat("f0", H("ff".repeat(12))))), "varuint_too_long");
  // in an attestation length at file level
  assert.equal(parseCode(proofOf(cat("00", BTC, H("80".repeat(9))))), "varuint_too_long");
  // truncated inside a varuint is truncated
  assert.equal(parseCode(proofOf(cat("f0", H("8080")))), "truncated");
  // max 63-bit value as attestation payload length: payload_too_long
  assert.equal(parseCode(proofOf(cat("00", BTC, H("ffffffffffffffff7f")))), "payload_too_long");
});

test("payload limits: 8192 accepted for unknown, 8193 payload_too_long", () => {
  const unk = "0102030405060708";
  assert.equal(parseCode(proofOf(att(unk, new Uint8Array(8192)))), "ok");
  assert.equal(parseCode(proofOf(cat("00", unk, varuint(8193), new Uint8Array(8193)))), "payload_too_long");
  assert.equal(parseCode(proofOf(cat("00", unk, varuint(8193)))), "payload_too_long"); // decided before reading
  const r = core.parseProof(proofOf(att(unk, H("deadbeef"))));
  assert.equal(r.proof.attestations[0].kind, "unknown");
  assert.equal(core.hex(r.proof.attestations[0].tag), unk);
  assert.equal(core.hex(r.proof.attestations[0].payload), "deadbeef");
  assert.equal(r.proof.attestations[0].height, null);
  assert.equal(r.proof.attestations[0].uri, null);
});

test("bad_attestation_payload", () => {
  assert.equal(parseCode(proofOf(att(BTC, Z))), "bad_attestation_payload"); // no height
  assert.equal(parseCode(proofOf(att(BTC, H("0100")))), "bad_attestation_payload"); // trailing byte
  assert.equal(parseCode(proofOf(att(BTC, H("80")))), "bad_attestation_payload"); // truncated varuint inside the payload
  assert.equal(parseCode(proofOf(att(ETH, H("ff".repeat(9))))), "bad_attestation_payload"); // oversized varuint inside the payload
  assert.equal(parseCode(proofOf(att(PENDING, Z))), "bad_attestation_payload");
  assert.equal(parseCode(proofOf(att(PENDING, H("05616263")))), "bad_attestation_payload"); // uri shorter than declared
  assert.equal(parseCode(proofOf(att(PENDING, H("0161" + "00")))), "bad_attestation_payload"); // trailing
});

test("height: litecoin/ethereum parsed like bitcoin; max 2^32-1; over is height_too_large", () => {
  for (const tag of [BTC, LTC, ETH]) {
    const r = core.parseProof(proofOf(att(tag, varuint(4294967295))));
    assert.equal(r.proof.attestations[0].height, 4294967295);
    assert.equal(parseCode(proofOf(att(tag, varuint(4294967296)))), "height_too_large");
    assert.equal(parseCode(proofOf(att(tag, varuint(2n ** 63n - 1n)))), "height_too_large");
  }
  const kinds = [BTC, LTC, ETH].map((t) => core.parseProof(proofOf(att(t, varuint(0)))).proof.attestations[0].kind);
  assert.deepEqual(kinds, ["bitcoin", "litecoin", "ethereum"]);
});

test("bad_uri: characters and length", () => {
  const uri = (s) => proofOf(att(PENDING, varbytes(new TextEncoder().encode(s))));
  assert.equal(parseCode(uri("https://a.b-c_d.example/x:80")), "ok");
  assert.equal(parseCode(uri("")), "ok");
  assert.equal(parseCode(uri("a b")), "bad_uri");
  assert.equal(parseCode(uri("a?b")), "bad_uri");
  assert.equal(parseCode(uri("a#b")), "bad_uri");
  assert.equal(parseCode(uri("a%20b")), "bad_uri");
  assert.equal(parseCode(uri("é")), "bad_uri");
  assert.equal(parseCode(uri("a".repeat(1000))), "ok");
  assert.equal(parseCode(uri("a".repeat(1001))), "bad_uri");
  assert.equal(parseCode(proofOf(att(PENDING, cat(varuint(1001))))), "bad_uri"); // length alone decides
  const r = core.parseProof(uri("https://x.example"));
  assert.equal(r.proof.attestations[0].uri, "https://x.example");
  assert.equal(r.proof.attestations[0].kind, "pending");
});

test("recursion_limit: 255 ops accepted, 256 rejected", () => {
  const ok = core.parseProof(proofOf(unary(255), btc(1)));
  assert.ok(ok.ok);
  assert.equal(ok.proof.maxDepth, 255);
  assert.equal(ok.proof.nodes.length, 256);
  assert.equal(parseCode(proofOf(unary(256), btc(1))), "recursion_limit");
  // the attestation on the node at depth 256 is never read, so even garbage there is recursion_limit
  assert.equal(parseCode(proofOf(unary(256))), "recursion_limit");
  assert.equal(parseCode(proofOf(unary(256), H("42"))), "recursion_limit");
  // with branches: the deep branch decides
  assert.equal(parseCode(proofOf(H("ff"), unary(256, "02"), btc(1), H("08"), btc(2))), "recursion_limit");
  assert.equal(parseCode(proofOf(H("ff"), unary(255, "02"), btc(1), H("08"), btc(2))), "ok");
});

test("error order: tag, then varuint/varbytes limits, then op application, then recursion", () => {
  // result_too_long beats recursion_limit on the same op (result computed before descending)
  assert.equal(parseCode(proofOf(unary(255), append(new Uint8Array(4096)))), "result_too_long");
  // repeated_op is detected after the arg is read, before the op is applied
  assert.equal(parseCode(proofOf(H("ff"), append(new Uint8Array(4064)), btc(1), append(new Uint8Array(4064)), btc(1))), "repeated_op");
  // arg_length comes before unknown ops that follow it
  assert.equal(parseCode(proofOf(cat("f0", varuint(0), "42"))), "arg_length");
  // left to right: the first problem wins over a later one
  assert.equal(parseCode(proofOf(cat(btc(1), "00"))), "trailing_garbage");
});

test("tree, ids, attestations: numbering is depth-first in file order", () => {
  // root --append aa--> n1 --sha256--> n2 [btc 1], n1 --prepend bb--> n3 [pending]; root --sha256--> n4 [btc 2]
  const body = cat("ff", append(H("aa")), "ff", "08", btc(1), prepend(H("bb")), pending("https://c.example"), "08", btc(2));
  const r = core.parseProof(proofOf(body));
  assert.ok(r.ok);
  const p = r.proof;
  assert.deepEqual(p.nodes.map((n) => [n.id, n.parent, n.op, n.depth]), [
    [0, -1, null, 0], [1, 0, "append", 1], [2, 1, "sha256", 2], [3, 1, "prepend", 2], [4, 0, "sha256", 1],
  ]);
  assert.deepEqual(p.attestations.map((a) => [a.index, a.node, a.kind]), [[0, 2, "bitcoin"], [1, 3, "pending"], [2, 4, "bitcoin"]]);
  assert.equal(p.maxDepth, 2);
  assert.equal(p.size, r.proof.size);
  // duplicated attestations are neither merged nor sorted
  const dup = core.parseProof(proofOf(H("ff"), btc(9), btc(9)));
  assert.equal(dup.proof.attestations.length, 2);
  const unsorted = core.parseProof(proofOf(H("ff"), btc(9), btc(1)));
  assert.deepEqual(unsorted.proof.attestations.map((a) => a.height), [9, 1]);
});

test("ParseError", () => {
  const e = new core.ParseError("truncated");
  assert.equal(e.code, "truncated");
  assert.equal(e.name, "ParseError");
});

// ---- the real vectors ----

const edgeKey = (e) => JSON.stringify(e);

for (const v of vectorIndex()) {
  test(`vector ${v.id}: parse matches the reference tree`, () => {
    const proof = readBin(v.id, "proof.ots");
    const ref = readJson(v.id, "reference.tree.json");
    const r = core.parseProof(proof);
    if (!ref.valid) {
      const want = { "invalid-bad-major-version": "unsupported_version", "invalid-exceeds-max-msg-length": "result_too_long", "invalid-file-digest-type": "unknown_file_hash_op" }[v.id];
      assert.ok(want, "unexpected invalid vector " + v.id);
      assert.equal(r.ok, false);
      assert.equal(r.code, want);
      return;
    }
    assert.ok(r.ok, v.id + " should parse: " + (r.code ?? ""));
    const p = r.proof;
    assert.equal(p.size, proof.length);
    assert.equal(p.hashOp, ref.file_hash_op);
    assert.equal(core.hex(p.digest), ref.digest);
    const mine = new Set();
    for (const n of p.nodes) {
      if (n.parent < 0) continue;
      mine.add(edgeKey([core.hex(p.nodes[n.parent].msg), n.op, n.arg === null ? null : core.hex(n.arg), core.hex(n.msg)]));
    }
    const theirs = new Set(ref.edges.map(edgeKey));
    assert.deepEqual([...mine].sort(), [...theirs].sort());
    const myAtt = new Set(p.attestations.map((a) => edgeKey([
      core.hex(p.nodes[a.node].msg), a.kind,
      a.kind === "pending" ? a.uri : a.kind === "unknown" ? core.hex(a.tag) + ":" + core.hex(a.payload) : a.height,
    ])));
    const refAtt = new Set(ref.attestations.map(edgeKey));
    assert.deepEqual([...myAtt].sort(), [...refAtt].sort());
    // nodes/ops counts are consistent
    assert.equal(p.nodes.length - 1, p.nodes.filter((n) => n.parent >= 0).length);
    // if the file is there, its sha256/sha1 digest is the proof's digest
    if (hasFile(v.id, "data.bin") && p.hashOp !== "ripemd160") {
      const d = core.hashBytes(p.hashOp, readBin(v.id, "data.bin"));
      assert.equal(core.hex(d), ref.digest, "data.bin digest");
    }
  });
}

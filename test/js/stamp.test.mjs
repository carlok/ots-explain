import { test } from "node:test";
import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { spawn } from "node:child_process";
import { join } from "node:path";
import { core, H, cat, hdr, append, prepend, att, btc, pending, varuint, varbytes, BTC, PENDING, MAGIC_HEX, ROOT, readBin, hasFile, vectorIndex } from "./helper.mjs";

const sha = (b) => new Uint8Array(createHash("sha256").update(b).digest());
const hexOf = (b) => Buffer.from(b).toString("hex");
const D = sha(Buffer.from("hello"));
const N = Uint8Array.from({ length: 16 }, (_, i) => i);
const M1 = cat(D, N);
const C = sha(M1);
const PREFIX = cat(MAGIC_HEX, "0108", D, "f010", N, "08"); // header + append n + sha256, then the tip's timestamp

// ---- builders for bare timestamps
// a node: every entry but the last is PREFIXED with ff (SPEC 3: { 0xff entry } entry)
const ts = (...entries) => cat(...entries.flatMap((e, i) => (i < entries.length - 1 ? ["ff", e] : [e])));
const edge = (opHex, arg, child) => cat(opHex, arg ? varbytes(arg) : new Uint8Array(0), child);
const unknownAtt = (tagHex, payload) => att(tagHex, payload);
const ok = (bytes, status = 200) => async () => ({ status, body: bytes });

/** A fake calendar network: routes by URL prefix; records every request. */
function net(routes) {
  const calls = [];
  const call = async (url, body) => {
    calls.push({ url, body });
    for (const [prefix, h] of Object.entries(routes)) {
      if (url.startsWith(prefix)) {
        const r = await h(url, body);
        return r;
      }
    }
    throw new Error("no route for " + url);
  };
  return { call, calls };
}
const quiet = () => {
  const lines = [];
  const log = (l) => lines.push(l);
  return { lines, log };
};

test("DEFAULT_CALENDARS and KNOWN_CALENDARS (SPEC 12.1)", () => {
  assert.deepEqual(core.DEFAULT_CALENDARS, [
    "https://alice.btc.calendar.opentimestamps.org",
    "https://bob.btc.calendar.opentimestamps.org",
    "https://finney.calendar.eternitywall.com",
  ]);
  assert.deepEqual(core.KNOWN_CALENDARS, [
    ...core.DEFAULT_CALENDARS,
    "https://btc.calendar.catallaxy.com",
    "https://ots.btc.catallaxy.com",
  ]);
});

test("commitmentFor: SHA-256(digest || nonce), checked with node:crypto", () => {
  assert.equal(hexOf(core.commitmentFor(D, N)), hexOf(C));
  // a vector written down: sha256("hello") = 2cf24dba..., nonce 000102..0f
  assert.equal(hexOf(D), "2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824");
  assert.equal(
    hexOf(core.commitmentFor(D, N)),
    hexOf(createHash("sha256").update(Buffer.from("2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824000102030405060708090a0b0c0d0e0f", "hex")).digest()),
  );
  assert.equal(core.commitmentFor(D, N).length, 32);
});

test("stamp: one calendar, exact byte layout, only c is sent, POST", async () => {
  const { call, calls } = net({ "https://a.example": ok(pending("https://a.example")) });
  const { lines, log } = quiet();
  const out = await core.stampDigest(D, ["https://a.example"], call, N, log);
  assert.equal(hexOf(out), hexOf(cat(PREFIX, pending("https://a.example"))));
  assert.equal(calls.length, 1);
  assert.equal(calls[0].url, "https://a.example/digest");
  assert.equal(hexOf(calls[0].body), hexOf(C));
  assert.deepEqual(lines, ["calendar https://a.example accepted the commitment"]);
  // and the reader of the core agrees on the shape
  const r = core.parseProof(out);
  assert.ok(r.ok);
  assert.equal(r.proof.hashOp, "sha256");
  assert.equal(hexOf(r.proof.digest), hexOf(D));
  assert.deepEqual(r.proof.nodes.map((n) => hexOf(n.msg)), [hexOf(D), hexOf(M1), hexOf(C)]);
  assert.deepEqual(r.proof.nodes.map((n) => n.op), [null, "append", "sha256"]);
});

test("stamp: URL join strips trailing slashes, the log keeps the calendar as given", async () => {
  const { call, calls } = net({ "https://a.example": ok(pending("https://a.example")) });
  const { lines, log } = quiet();
  await core.stampDigest(D, ["https://a.example///"], call, N, log);
  assert.equal(calls[0].url, "https://a.example/digest");
  assert.equal(lines[0], "calendar https://a.example/// accepted the commitment");
});

test("stamp: calendars are asked in the given order, in sequence", async () => {
  const order = [];
  const call = async (url) => {
    order.push(url + ":start");
    await new Promise((r) => setTimeout(r, url.includes("slow") ? 20 : 1));
    order.push(url + ":end");
    return { status: 200, body: pending("https://x.example") };
  };
  await core.stampDigest(D, ["https://slow.example", "https://fast.example"], call, N, () => {});
  assert.deepEqual(order, [
    "https://slow.example/digest:start", "https://slow.example/digest:end",
    "https://fast.example/digest:start", "https://fast.example/digest:end",
  ]);
});

test("stamp: two calendars, attestations sorted by URI bytes whatever the call order", async () => {
  const { call } = net({
    "https://z.example": ok(pending("https://zeta.example")),
    "https://b.example": ok(pending("https://alpha.example")),
  });
  const out = await core.stampDigest(D, ["https://z.example", "https://b.example"], call, N, () => {});
  assert.equal(hexOf(out), hexOf(cat(PREFIX, "ff", pending("https://alpha.example"), pending("https://zeta.example"))));
});

test("serialization sort orders: attestations by tag, numeric height, then payload; edges by op byte then argument", async () => {
  const frag = ts(
    // deliberately in the worst order; the parser accepts any order
    edge("f1", H("05"), btc(1)),
    edge("f0", H("0202"), btc(2)),
    edge("f0", H("02"), btc(3)),
    edge("08", null, btc(4)),
    edge("f0", H("01"), btc(5)),
    pending("https://p.example"),
    btc(300), // varuint ac 02: sorts BEFORE c8 01 bytewise, after it numerically
    btc(200),
    att("ffffffffffffffff", H("aa")),
    att("0000000000000001", H("bb")),
    att("0000000000000001", H("ba")),
  );
  const { call } = net({ "https://a.example": ok(frag) });
  const out = await core.stampDigest(D, ["https://a.example"], call, N, () => {});
  const expected = cat(
    PREFIX,
    ts(
      att("0000000000000001", H("ba")),
      att("0000000000000001", H("bb")),
      btc(200),
      btc(300),
      pending("https://p.example"),
      att("ffffffffffffffff", H("aa")),
      edge("08", null, btc(4)),
      edge("f0", H("01"), btc(5)),
      edge("f0", H("02"), btc(3)),
      edge("f0", H("0202"), btc(2)),
      edge("f1", H("05"), btc(1)),
    ),
  );
  assert.equal(hexOf(out), hexOf(expected));
});

test("serialization: attestations with equal tag and height compare by payload; pending by URI", async () => {
  // two bitcoin attestations at the same height written with different varuint spellings; both kept, sorted by payload bytes
  const frag = ts(att(BTC, H("8500")), att(BTC, H("05")));
  const { call } = net({ "https://a.example": ok(frag) });
  const out = await core.stampDigest(D, ["https://a.example"], call, N, () => {});
  assert.equal(hexOf(out), hexOf(cat(PREFIX, ts(att(BTC, H("05")), att(BTC, H("8500"))))));
});

test("merge: identical edges from two calendars become one edge, children merged; identical attestations once", async () => {
  const x = H("aabb");
  const f1 = ts(edge("f0", x, pending("https://one.example")), edge("08", null, pending("https://one.example")));
  const f2 = ts(
    edge("f0", x, pending("https://two.example")),
    edge("f0", H("cc"), pending("https://two.example")),
    edge("08", null, pending("https://one.example")), // same child attestation as in f1
    pending("https://top.example"),
  );
  const f3 = f1; // a third calendar says exactly what the first said
  const { call } = net({ "https://1.example": ok(f1), "https://2.example": ok(f2), "https://3.example": ok(f3) });
  const { lines, log } = quiet();
  const out = await core.stampDigest(D, ["https://1.example", "https://2.example", "https://3.example"], call, N, log);
  const expected = cat(
    PREFIX,
    ts(
      pending("https://top.example"),
      edge("08", null, pending("https://one.example")),
      edge("f0", x, ts(pending("https://one.example"), pending("https://two.example"))),
      edge("f0", H("cc"), pending("https://two.example")),
    ),
  );
  assert.equal(hexOf(out), hexOf(expected));
  assert.equal(lines.length, 3);
  assert.ok(core.parseProof(out).ok, "no repeated_op");
});

test("merge: two calendars using the same nonce and path do not produce repeated_op", async () => {
  const f = ts(edge("f0", H("0102030405060708"), edge("08", null, pending("https://one.example"))));
  const g = ts(edge("f0", H("0102030405060708"), edge("08", null, pending("https://two.example"))));
  const { call } = net({ "https://1.example": ok(f), "https://2.example": ok(g) });
  const out = await core.stampDigest(D, ["https://1.example", "https://2.example"], call, N, () => {});
  const r = core.parseProof(out);
  assert.ok(r.ok);
  assert.equal(r.proof.attestations.length, 2);
  assert.equal(r.proof.nodes.length, 3 + 2 + 0); // root, m1, tip, f0, sha256 (one shared chain)
});

// ---- fragment limits

function fragOfSize(n) {
  // two unknown attestations: payload 8192 (the maximum) and the rest, total n bytes
  const a = att("1111111111111111", new Uint8Array(8192));
  const rest = n - a.length - 1 /* ff */ - 1 - 8 - 2;
  const b = att("2222222222222222", new Uint8Array(rest));
  const out = ts(a, b);
  assert.equal(out.length, n);
  return out;
}

test("fragment limit: exactly 10000 bytes is accepted, 10001 is payload_too_long", async () => {
  {
    const { call } = net({ "https://a.example": ok(fragOfSize(10000)) });
    const { lines, log } = quiet();
    const out = await core.stampDigest(D, ["https://a.example"], call, N, log);
    assert.deepEqual(lines, ["calendar https://a.example accepted the commitment"]);
    assert.ok(core.parseProof(out).ok);
  }
  {
    const { call } = net({ "https://a.example": ok(fragOfSize(10001)), "https://b.example": ok(pending("https://b.example")) });
    const { lines, log } = quiet();
    await core.stampDigest(D, ["https://a.example", "https://b.example"], call, N, log);
    assert.deepEqual(lines, [
      "calendar https://a.example failed: payload_too_long",
      "calendar https://b.example accepted the commitment",
    ]);
  }
  {
    const { call } = net({ "https://a.example": ok(new Uint8Array(1_000_000)) });
    const { lines, log } = quiet();
    await assert.rejects(core.stampDigest(D, ["https://a.example"], call, N, log), { message: "no calendar accepted the commitment" });
    assert.deepEqual(lines, ["calendar https://a.example failed: payload_too_long"]);
  }
});

test("fragment parse errors become the failure reason (section 4 codes)", async () => {
  const cases = [
    ["empty body", new Uint8Array(0), "truncated"],
    ["cut in the middle of an attestation", pending("https://a.example").subarray(0, 12), "truncated"],
    ["trailing bytes", cat(pending("https://a.example"), "00"), "trailing_garbage"],
    ["unknown op byte", H("42"), "unknown_op"],
    ["bad uri", att(PENDING, varbytes(new TextEncoder().encode("bad uri"))), "bad_uri"],
    ["append with empty arg", cat("f000", btc(1)), "arg_length"],
    ["same op twice at one node", ts(edge("08", null, btc(1)), edge("08", null, btc(2))), "repeated_op"],
    ["height too large", att(BTC, cat(varuint(2n ** 32n))), "height_too_large"],
    ["payload over 8192", att("1111111111111111", new Uint8Array(8193)), "payload_too_long"],
    ["recursion", cat(H("08".repeat(256)), btc(1)), "recursion_limit"],
  ];
  for (const [name, body, code] of cases) {
    const { call } = net({ "https://a.example": ok(body) });
    const { lines, log } = quiet();
    await assert.rejects(core.stampDigest(D, ["https://a.example"], call, N, log), { message: "no calendar accepted the commitment" }, name);
    assert.deepEqual(lines, [`calendar https://a.example failed: ${code}`], name);
  }
  // 255 ops are fine
  const { call } = net({ "https://a.example": ok(cat(H("08".repeat(255)), btc(1))) });
  const { lines, log } = quiet();
  await core.stampDigest(D, ["https://a.example"], call, N, log);
  // the fragment alone is within the limit; the final file is 257 ops deep, which stampDigest does not re-check (see QUESTIONS-stamp.md)
  assert.deepEqual(lines, ["calendar https://a.example accepted the commitment"]);
});

test("failure paths: HTTP status, call raising (Error and non-Error), mixed with a good calendar", async () => {
  const { call, calls } = net({
    "https://s500.example": ok(new Uint8Array(0), 500),
    "https://s404.example": ok(pending("https://x.example"), 404),
    "https://s204.example": ok(pending("https://x.example"), 204),
    "https://down.example": async () => { throw new Error("connection refused"); },
    "https://str.example": async () => { throw "plain string"; },
    "https://good.example": ok(pending("https://good.example")),
  });
  const { lines, log } = quiet();
  const out = await core.stampDigest(
    D,
    ["https://s500.example", "https://s404.example", "https://s204.example", "https://down.example", "https://str.example", "https://good.example"],
    call, N, log,
  );
  assert.deepEqual(lines, [
    "calendar https://s500.example failed: HTTP 500",
    "calendar https://s404.example failed: HTTP 404",
    "calendar https://s204.example failed: HTTP 204",
    "calendar https://down.example failed: connection refused",
    "calendar https://str.example failed: plain string",
    "calendar https://good.example accepted the commitment",
  ]);
  assert.equal(calls.length, 6, "a failure does not stop the others");
  assert.equal(hexOf(out), hexOf(cat(PREFIX, pending("https://good.example"))));
});

test("no calendar accepted: throws the spec message; empty calendar list too", async () => {
  const { call } = net({ "https://a.example": ok(new Uint8Array(0), 503) });
  const { lines, log } = quiet();
  await assert.rejects(core.stampDigest(D, ["https://a.example"], call, N, log), (e) => e instanceof Error && e.message === "no calendar accepted the commitment");
  assert.deepEqual(lines, ["calendar https://a.example failed: HTTP 503"]);
  await assert.rejects(core.stampDigest(D, [], call, N, () => {}), { message: "no calendar accepted the commitment" });
});

test("stamp: the answer's HTTP status is checked before its length", async () => {
  const { call } = net({ "https://a.example": ok(new Uint8Array(20000), 502) });
  const { lines, log } = quiet();
  await assert.rejects(core.stampDigest(D, ["https://a.example"], call, N, log));
  assert.deepEqual(lines, ["calendar https://a.example failed: HTTP 502"]);
});

// ---- upgrade

const U1 = "https://alice.btc.calendar.opentimestamps.org";
const U2 = "https://bob.btc.calendar.opentimestamps.org";
const NA = H("a1".repeat(16));
const NB = H("b2".repeat(16));
const CA = sha(cat(D, NA));
const CB = sha(cat(D, NB));
const one = (uri, nonce = NA) => cat(hdr({ digest: D }), append(nonce), "08", pending(uri));
const two = cat(hdr({ digest: D }), ts(edge("f0", NA, edge("08", null, pending(U1))), edge("f0", NB, edge("08", null, pending(U2)))));

test("upgrade: complete -- pending replaced by the Bitcoin attestation, GET to uri/timestamp/<hex>", async () => {
  const proof = one(U1);
  const { call, calls } = net({ [U1]: ok(btc(800000)) });
  const { lines, log } = quiet();
  const r = await core.upgradeProof(proof, call, [U1], log);
  assert.equal(r.status, "complete");
  assert.equal(r.changed, true);
  assert.equal(hexOf(r.bytes), hexOf(cat(hdr({ digest: D }), append(NA), "08", btc(800000))));
  assert.deepEqual(calls, [{ url: `${U1}/timestamp/${hexOf(CA)}`, body: undefined }]);
  assert.deepEqual(lines, []);
});

test("upgrade: a full path from the calendar is grafted under the node; the other pending attestation stays", async () => {
  const frag = cat("f1", varbytes(H("0a0b")), "08", btc(123));
  const { call, calls } = net({ [U1]: ok(frag), [U2]: ok(new Uint8Array(0), 404) });
  const { lines, log } = quiet();
  const r = await core.upgradeProof(two, call, [U1, U2], log);
  assert.equal(r.status, "complete");
  assert.equal(r.changed, true);
  const expected = cat(hdr({ digest: D }), ts(
    edge("f0", NA, edge("08", null, edge("f1", H("0a0b"), edge("08", null, btc(123))))),
    edge("f0", NB, edge("08", null, pending(U2))),
  ));
  assert.equal(hexOf(r.bytes), hexOf(expected));
  assert.deepEqual(calls.map((c) => c.url), [`${U1}/timestamp/${hexOf(CA)}`, `${U2}/timestamp/${hexOf(CB)}`]);
  assert.deepEqual(lines, [`${U2}: not confirmed yet`]);
});

test("upgrade: pending attestations are visited in tree (creation) order, not sorted order", async () => {
  const reversed = cat(hdr({ digest: D }), ts(edge("f0", NB, edge("08", null, pending(U2))), edge("f0", NA, edge("08", null, pending(U1)))));
  const { call, calls } = net({ [U1]: ok(new Uint8Array(0), 404), [U2]: ok(new Uint8Array(0), 404) });
  const r = await core.upgradeProof(reversed, call, [U1, U2], () => {});
  assert.equal(r.status, "pending");
  assert.deepEqual(calls.map((c) => c.url), [`${U2}/timestamp/${hexOf(CB)}`, `${U1}/timestamp/${hexOf(CA)}`]);
});

test("upgrade outcomes and their exact log lines", async () => {
  const proof = one(U1);
  const cases = [
    ["404", ok(new Uint8Array(0), 404), `${U1}: not confirmed yet`],
    ["500", ok(new Uint8Array(0), 500), `${U1}: HTTP 500`],
    ["204", ok(new Uint8Array(0), 204), `${U1}: HTTP 204`],
    ["unreachable", async () => { throw new Error("timed out"); }, `${U1} unreachable: timed out`],
    ["unreadable (truncated)", ok(new Uint8Array(0)), `${U1} sent an unreadable answer: truncated`],
    ["unreadable (garbage)", ok(cat(btc(1), "00")), `${U1} sent an unreadable answer: trailing_garbage`],
    ["unreadable (unknown op)", ok(H("42")), `${U1} sent an unreadable answer: unknown_op`],
    ["no bitcoin yet", ok(pending(U1)), `${U1}: answer has no Bitcoin attestation yet`],
    ["only litecoin", ok(att("06869a0d73d71b45", varuint(5))), `${U1}: answer has no Bitcoin attestation yet`],
  ];
  for (const [name, h, line] of cases) {
    const { call } = net({ [U1]: h });
    const { lines, log } = quiet();
    const r = await core.upgradeProof(proof, call, [U1], log);
    assert.equal(r.status, "pending", name);
    assert.equal(r.changed, false, name);
    assert.equal(r.bytes, proof, name + ": the input is returned unchanged (same bytes)");
    assert.deepEqual(lines, [line], name);
  }
});

test("upgrade: a 'no Bitcoin' answer is judged only after it parsed; a Bitcoin attestation deep in the answer counts", async () => {
  const deep = ts(pending(U1), edge("08", null, edge("f0", H("01"), btc(9))));
  const { call } = net({ [U1]: ok(deep) });
  const r = await core.upgradeProof(one(U1), call, [U1], () => {});
  assert.equal(r.status, "complete");
  // the pending attestation of that same URI came back in the answer; it is merged in after the old one was removed
  assert.equal(hexOf(r.bytes), hexOf(cat(hdr({ digest: D }), append(NA), "08", deep)));
});

test("upgrade: allow-list refusal, comparison ignores trailing slashes on both sides", async () => {
  const proof = one(U1);
  {
    const { call, calls } = net({});
    const { lines, log } = quiet();
    const r = await core.upgradeProof(proof, call, [U2], log);
    assert.equal(r.status, "pending");
    assert.equal(r.changed, false);
    assert.equal(calls.length, 0, "nothing is sent");
    assert.deepEqual(lines, [`not asking ${U1}: not on the allowed list (use --allow)`]);
  }
  {
    const { call, calls } = net({ [U1]: ok(btc(5)) });
    const r = await core.upgradeProof(proof, call, [U1 + "//"], () => {});
    assert.equal(r.status, "complete");
    assert.equal(calls[0].url, `${U1}/timestamp/${hexOf(CA)}`);
  }
  {
    const slash = one(U1 + "/");
    const { call, calls } = net({ [U1]: ok(btc(5)) });
    const r = await core.upgradeProof(slash, call, [U1], () => {});
    assert.equal(r.status, "complete");
    assert.equal(calls[0].url, `${U1}/timestamp/${hexOf(CA)}`, "join strips the trailing slash");
  }
  {
    // an empty allow-list refuses everything; a prefix of an allowed URL is not the URL
    const { call, calls } = net({});
    const { lines, log } = quiet();
    await core.upgradeProof(proof, call, [], log);
    await core.upgradeProof(proof, call, [U1.slice(0, -1)], log);
    assert.equal(calls.length, 0);
    assert.equal(lines.length, 2);
  }
  {
    // known and custom calendars: a mixed proof asks the allowed one only
    const { call, calls } = net({ [U2]: ok(btc(7)) });
    const { lines, log } = quiet();
    const r = await core.upgradeProof(two, call, [U2], log);
    assert.equal(r.status, "complete");
    assert.deepEqual(calls.map((c) => c.url), [`${U2}/timestamp/${hexOf(CB)}`]);
    assert.deepEqual(lines, [`not asking ${U1}: not on the allowed list (use --allow)`]);
  }
});

test("upgrade: a node message of any length is sent (SPEC 12.7: no 32-byte rule)", async () => {
  // SHA-1 header: the pending attestation hangs on the 20-byte root
  const root = new Uint8Array(20).fill(9);
  const sha1Proof = cat(hdr({ op: 0x02, digest: root }), pending(U1));
  const { call, calls } = net({});
  const { lines, log } = quiet();
  const r = await core.upgradeProof(sha1Proof, call, [U1], log);
  assert.equal(r.status, "pending");
  assert.deepEqual(calls.map((c) => c.url), [`${U1}/timestamp/${hexOf(root)}`]);
  // the allow-list still comes first
  const { call: c2, calls: calls2 } = net({});
  const { lines: l2, log: log2 } = quiet();
  await core.upgradeProof(sha1Proof, c2, [], log2);
  assert.equal(calls2.length, 0);
  assert.deepEqual(l2, [`not asking ${U1}: not on the allowed list (use --allow)`]);
});

test("upgrade: nothing_to_do when a Bitcoin attestation exists and no pending one", async () => {
  const proof = readBin("hello-world", "proof.ots");
  const { call, calls } = net({});
  const { lines, log } = quiet();
  const r = await core.upgradeProof(proof, call, [], log);
  assert.deepEqual({ s: r.status, c: r.changed }, { s: "nothing_to_do", c: false });
  assert.equal(r.bytes, proof);
  assert.equal(calls.length, 0);
  assert.deepEqual(lines, []);
});

test("upgrade: a proof with both kinds is worked on; duplicate Bitcoin attestations merge once", async () => {
  const proof = cat(hdr({ digest: D }), ts(btc(1), pending(U1)));
  // the node is the 32-byte root
  const { call } = net({ [U1]: ok(ts(btc(1), btc(2))) });
  const r = await core.upgradeProof(proof, call, [U1], () => {});
  assert.equal(r.status, "complete");
  assert.equal(hexOf(r.bytes), hexOf(cat(hdr({ digest: D }), ts(btc(1), btc(2)))));
});

test("upgrade: neither Bitcoin nor pending attestation -> pending, unchanged, no call", async () => {
  const proof = cat(hdr({ digest: D }), att("1111111111111111", H("00")));
  const { call, calls } = net({});
  const r = await core.upgradeProof(proof, call, [U1], () => {});
  assert.deepEqual({ s: r.status, c: r.changed }, { s: "pending", c: false });
  assert.equal(r.bytes, proof);
  assert.equal(calls.length, 0);
});

test("upgrade: output is canonical (sorted), and the header operation and digest are kept", async () => {
  // a SHA-1 proof (20-byte root) with a pending attestation on a 32-byte node, edges written out of order
  const d1 = new Uint8Array(20).fill(5);
  const m = sha(cat(d1, NA));
  const proof = cat(hdr({ op: 0x02, digest: d1 }), ts(edge("f1", H("01"), btc(3)), edge("f0", NA, edge("08", null, pending(U1)))));
  const { call, calls } = net({ [U1]: ok(btc(42)) });
  const r = await core.upgradeProof(proof, call, [U1], () => {});
  assert.equal(calls[0].url, `${U1}/timestamp/${hexOf(m)}`);
  assert.equal(hexOf(r.bytes), hexOf(cat(hdr({ op: 0x02, digest: d1 }), ts(edge("f0", NA, edge("08", null, btc(42))), edge("f1", H("01"), btc(3))))));
});

test("upgrade: a parse failure of the input is raised with its code", async () => {
  const { call } = net({});
  for (const [bytes, code] of [[new Uint8Array(0), "bad_magic"], [cat(hdr(), "00"), "truncated"], [cat(hdr(), btc(1), "00"), "trailing_garbage"]]) {
    await assert.rejects(core.upgradeProof(bytes, call, [], () => {}), (e) => e.message === code && e.code === code);
  }
});

test("upgrade: a result that no longer parses (too deep) is raised, nothing returned", async () => {
  const deepProof = cat(hdr({ digest: D }), H("08".repeat(250)), pending(U1));
  assert.ok(core.parseProof(deepProof).ok);
  const { call } = net({ [U1]: ok(cat(H("08".repeat(10)), btc(1))) });
  await assert.rejects(core.upgradeProof(deepProof, call, [U1], () => {}), { message: "recursion_limit" });
});

test("upgrade asks for the pending attestations of official proofs: their nodes hold 44 bytes (SPEC 12.7)", async () => {
  const proof = readBin("two-calendars", "proof.ots");
  const { call, calls } = net({});
  const { lines, log } = quiet();
  const r = await core.upgradeProof(proof, call, core.KNOWN_CALENDARS, log);
  assert.equal(r.status, "pending");
  assert.equal(calls.length, 2);
  for (const c of calls) assert.match(c.url, /\/timestamp\/[0-9a-f]{88}$/);
  assert.deepEqual(lines.length, 2);
});

test("upgrade re-serializes official trees canonically: same nodes, same attestations plus the new ones", async () => {
  let checked = 0;
  for (const v of vectorIndex()) {
    if (!hasFile(v.id, "proof.ots")) continue;
    const proof = readBin(v.id, "proof.ots");
    const before = core.parseProof(proof);
    if (!before.ok || before.proof.hashOp !== "sha256") continue;
    if (before.proof.attestations.some((a) => a.kind === "pending")) continue; // those are asked too now (test above)
    // hang a pending attestation on the root, in front of the existing entries
    const body = proof.subarray(31 + 2 + 32);
    const mixed = cat(proof.subarray(0, 65), "ff", pending(U1), body);
    assert.ok(core.parseProof(mixed).ok, v.id);
    const call = async () => ({ status: 200, body: ts(btc(1), btc(2)) });
    const r = await core.upgradeProof(mixed, call, [U1], () => {});
    assert.equal(r.status, "complete", v.id);
    const after = core.parseProof(r.bytes);
    assert.ok(after.ok, v.id);
    const sig = (n) => `${n.parent}|${n.op}|${n.arg ? hexOf(n.arg) : ""}|${hexOf(n.msg)}`;
    assert.deepEqual(after.proof.nodes.map(sig), before.proof.nodes.map(sig), v.id);
    const att1 = (a) => `${a.node}|${a.kind}|${a.height}|${a.uri}|${hexOf(a.payload)}`;
    const want = before.proof.attestations.map(att1).concat(`0|bitcoin|1|null|01`, `0|bitcoin|2|null|02`).sort();
    // an official proof already has its root attestations first; a Bitcoin attestation at the root is merged, not duplicated
    const got = after.proof.attestations.map(att1).sort();
    assert.deepEqual([...new Set(got)], [...new Set(want)], v.id);
    checked++;
  }
  assert.ok(checked >= 5, "enough sha256 vectors were exercised: " + checked);
});

test("stamp then upgrade round trip with fake calendars; second upgrade has nothing to do", async () => {
  const cal = "https://c.example";
  const pend = cat(H("f0"), varbytes(H("0102030405060708")), "08", pending(cal));
  const stamped = await core.stampDigest(D, [cal], net({ [cal]: ok(pend) }).call, N, () => {});
  const asked = [];
  const call = async (url) => { asked.push(url); return { status: 200, body: btc(700001) }; };
  const m = sha(cat(C, H("0102030405060708")));
  const up = await core.upgradeProof(stamped, call, [cal], () => {});
  assert.equal(up.status, "complete");
  assert.equal(asked[0], `${cal}/timestamp/${hexOf(sha(cat(C, H("0102030405060708"))))}`);
  assert.equal(hexOf(m), hexOf(sha(cat(C, H("0102030405060708")))));
  const r = core.parseProof(up.bytes);
  assert.ok(r.ok);
  assert.deepEqual(r.proof.attestations.map((a) => [a.kind, a.height]), [["bitcoin", 700001]]);
  const again = await core.upgradeProof(up.bytes, call, [cal], () => {});
  assert.equal(again.status, "nothing_to_do");
  assert.equal(asked.length, 1);
});

test("stamp: preconditions on digest and nonce size", async () => {
  const { call } = net({ "https://a.example": ok(pending("https://a.example")) });
  await assert.rejects(core.stampDigest(D.subarray(0, 31), ["https://a.example"], call, N, () => {}), /32 bytes/);
  await assert.rejects(core.stampDigest(D, ["https://a.example"], call, N.subarray(0, 15), () => {}), /16 bytes/);
});

// ---- end to end against the mock calendar (python3 test/mock_calendar.py)

test("end to end with test/mock_calendar.py: stamp, 404 while pending, upgrade after /__ready", async (t) => {
  const env = { ...process.env, no_proxy: "127.0.0.1,localhost", NO_PROXY: "127.0.0.1,localhost" };
  const child = spawn("python3", ["-I", join(ROOT, "test", "mock_calendar.py")], { env, stdio: ["ignore", "pipe", "ignore"] });
  t.after(() => child.kill());
  const info = await new Promise((resolve, reject) => {
    let buf = "";
    child.on("error", reject);
    child.on("exit", () => reject(new Error("mock calendar exited")));
    child.stdout.on("data", (d) => {
      buf += d;
      const i = buf.indexOf("\n");
      if (i >= 0) resolve(JSON.parse(buf.slice(0, i)));
    });
    setTimeout(() => reject(new Error("mock calendar did not start")), 15000);
  }).catch((e) => { t.skip(String(e.message)); return null; });
  if (!info) return;
  const call = async (url, body) => {
    const r = await fetch(url, body ? { method: "POST", body, headers: { Accept: "application/vnd.opentimestamps.v1" } } : { headers: { Accept: "application/vnd.opentimestamps.v1" } });
    return { status: r.status, body: new Uint8Array(await r.arrayBuffer()) };
  };
  const cal = info.calendar;
  const { lines, log } = quiet();
  const stamped = await core.stampDigest(D, [cal], call, N, log);
  assert.deepEqual(lines, [`calendar ${cal} accepted the commitment`]);
  const p = core.parseProof(stamped);
  assert.ok(p.ok);
  assert.equal(p.proof.attestations.length, 1);
  assert.equal(p.proof.attestations[0].kind, "pending");
  assert.equal(p.proof.attestations[0].uri, cal);
  assert.equal(hexOf(p.proof.nodes[0].msg), hexOf(D));
  assert.equal(p.proof.nodes[1].op, "append");
  assert.equal(hexOf(p.proof.nodes[1].arg), hexOf(N));

  const l1 = quiet();
  const r1 = await core.upgradeProof(stamped, call, [cal], l1.log);
  assert.equal(r1.status, "pending");
  assert.equal(r1.changed, false);
  assert.deepEqual(l1.lines, [`${cal}: not confirmed yet`]);

  const l0 = quiet();
  const refused = await core.upgradeProof(stamped, call, [core.DEFAULT_CALENDARS[0]], l0.log);
  assert.equal(refused.status, "pending");
  assert.deepEqual(l0.lines, [`not asking ${cal}: not on the allowed list (use --allow)`]);

  assert.equal((await call(cal + "/__ready", new Uint8Array(0))).status, 200);
  const l2 = quiet();
  const r2 = await core.upgradeProof(stamped, call, [cal], l2.log);
  assert.equal(r2.status, "complete");
  assert.equal(r2.changed, true);
  assert.deepEqual(l2.lines, []);
  const q = core.parseProof(r2.bytes);
  assert.ok(q.ok);
  assert.ok(q.proof.attestations.some((a) => a.kind === "bitcoin"));
  assert.ok(!q.proof.attestations.some((a) => a.kind === "pending"));
  assert.ok(q.proof.nodes.length > 8, "the transaction and merkle path were grafted on");
  // the upgraded proof is canonical: upgrading again does nothing, and re-serializing is stable
  assert.equal((await core.upgradeProof(r2.bytes, call, [cal], () => {})).status, "nothing_to_do");
});

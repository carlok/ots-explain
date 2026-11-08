import { test } from "node:test";
import assert from "node:assert/strict";
import { core, H, readBin } from "./helper.mjs";

test("canonical JSON: key order, whitespace, ints, nesting", () => {
  assert.equal(core.canonicalJson({ b: 1, a: [true, false, null, { z: 0, y: -5 }], aa: "x", A: 2 }), '{"A":2,"a":[true,false,null,{"y":-5,"z":0}],"aa":"x","b":1}');
  assert.equal(core.canonicalJson([]), "[]");
  assert.equal(core.canonicalJson({}), "{}");
  assert.equal(core.canonicalJson(0), "0");
  assert.equal(core.canonicalJson(4294967295), "4294967295");
  assert.equal(core.canonicalJson(null), "null");
});

test("canonical JSON: sorted by code point (not UTF-16 unit)", () => {
  // U+FF5E (BMP, one unit 0xFF5E) sorts before U+1F600 (surrogates 0xD83D..) by units, but after by code point? 0xFF5E < 0x1F600 in both; use U+E000 vs U+10000
  const o = { "\u{10000}": 1, "": 2, a: 3 };
  assert.equal(core.canonicalJson(o), '{"a":3,"":2,"\u{10000}":1}');
  assert.equal(core.canonicalJson({ ab: 1, a: 2 }), '{"a":2,"ab":1}');
  assert.equal(core.canonicalJson({ b: 1, ab: 2 }), '{"ab":2,"b":1}');
});

test("canonical JSON: string escapes", () => {
  assert.equal(core.canonicalJson('a"b\\c\nd\re\tf'), '"a\\"b\\\\c\\nd\\re\\tf"');
  assert.equal(core.canonicalJson("\u0000\u0001\b\f\u001f"), '"\\u0000\\u0001\\u0008\\u000c\\u001f"');
  assert.equal(core.canonicalJson("/\u007f"), '"/\u007f"'); // DEL and slash are not escaped
  assert.equal(core.canonicalJson("é"), '"é"'); // no \u escaping of non-ASCII (never occurs in reports)
  assert.deepEqual(core.canonicalBytes("é"), new TextEncoder().encode('"é"'));
});

test("canonical JSON: rejects floats, NaN, undefined, functions", () => {
  assert.throws(() => core.canonicalJson(1.5));
  assert.throws(() => core.canonicalJson(NaN));
  assert.throws(() => core.canonicalJson(Infinity));
  assert.throws(() => core.canonicalJson(undefined));
  assert.throws(() => core.canonicalJson(() => 1));
  assert.throws(() => core.canonicalJson({ a: undefined }));
});

test("permalink: encode shapes", () => {
  const B = "https://example.org/explain/";
  assert.equal(core.encodePermalink(B), B);
  assert.equal(core.encodePermalink(B, {}), B);
  assert.equal(core.encodePermalink(B, { digestHex: "ABCD" }), B + "#h=abcd");
  assert.equal(core.encodePermalink(B, { ots: H("fbff") }), B + "#ots=-_8");
  assert.equal(core.encodePermalink(B, { digestHex: "00ff", ots: H("fbff") }), B + "#h=00ff&ots=-_8");
  assert.equal(core.encodePermalink(B, { proofUrl: "https://a.b/c d?x=1&y=é~._-" }), B + "?proof=https%3A%2F%2Fa.b%2Fc%20d%3Fx%3D1%26y%3D%C3%A9~._-");
  assert.equal(core.encodePermalink(B, { proofUrl: "https://a.b/p.ots", digestHex: "aa", ots: H("00") }), B + "?proof=https%3A%2F%2Fa.b%2Fp.ots#h=aa&ots=AA");
  assert.equal(core.encodePermalink(B, { proofUrl: "", digestHex: "", ots: null }), B);
});

test("permalink: decode, unknown keys, case-sensitive keys, garbage", () => {
  const B = "https://example.org/explain/";
  let d = core.decodePermalink(B + "?proof=https%3A%2F%2Fa.b%2Fp.ots&other=1#h=AABB&zzz=9&ots=AA");
  assert.deepEqual({ ...d, ots: [...d.ots] }, { base: B, proofUrl: "https://a.b/p.ots", digestHex: "aabb", ots: [0] });
  d = core.decodePermalink(B + "#H=aa&OTS=AA");
  assert.equal(d.digestHex, null);
  assert.equal(d.ots, null);
  d = core.decodePermalink(B);
  assert.deepEqual(d, { base: B, proofUrl: null, digestHex: null, ots: null });
  d = core.decodePermalink(B + "#h=zz&ots=@@@@");
  assert.equal(d.digestHex, null);
  assert.equal(d.ots, null);
  d = core.decodePermalink(B + "?proof=%ZZ");
  assert.equal(d.proofUrl, null);
  d = core.decodePermalink(B + "?proof=%C3");
  assert.equal(d.proofUrl, null);
  d = core.decodePermalink(B + "?proof=%C");
  assert.equal(d.proofUrl, null);
  d = core.decodePermalink(B + "?proof=é%20x&novalue&proof=second");
  assert.equal(d.proofUrl, "é x");
  d = core.decodePermalink(B + "#novalue&h=aa&h=bb");
  assert.equal(d.digestHex, "aa");
});

test("permalink: round trips, including the 3812-byte empty vector proof", () => {
  const proof = readBin("empty", "proof.ots");
  assert.equal(proof.length, 3812);
  const url = core.encodePermalink("https://example.org/", { digestHex: "e3b0c442", ots: proof, proofUrl: "https://x.example/a b.ots?z=1" });
  const d = core.decodePermalink(url);
  assert.deepEqual(d.ots, proof);
  assert.equal(d.digestHex, "e3b0c442");
  assert.equal(d.proofUrl, "https://x.example/a b.ots?z=1");
  assert.equal(d.base, "https://example.org/");
  assert.ok(core.parseProof(d.ots).ok);
  // every length mod 3
  for (let n = 0; n < 12; n++) {
    const b = Uint8Array.from({ length: n }, (_, i) => (i * 37 + 11) & 255);
    const u = core.encodePermalink("x:", { ots: b });
    assert.deepEqual(core.decodePermalink(u).ots ?? new Uint8Array(0), b);
  }
  // every vector proof
  for (const id of ["hello-world", "bitcoin-pdf", "gdp2q25", "two-calendars"]) {
    const p = readBin(id, "proof.ots");
    assert.deepEqual(core.decodePermalink(core.encodePermalink("https://h/", { ots: p })).ots, p);
  }
});

import { test } from "node:test";
import assert from "node:assert/strict";
import { createHash, randomBytes } from "node:crypto";
import { core, readJson, H } from "./helper.mjs";

const vectors = readJson("hash-vectors.json");
const fn = { sha256: core.sha256, sha1: core.sha1, ripemd160: core.ripemd160, keccak256: core.keccak256 };

for (const [alg, list] of Object.entries(vectors)) {
  test(`${alg}: vectors/hash-vectors.json`, () => {
    for (const [inputHex, outHex] of list) {
      assert.equal(core.hex(fn[alg](H(inputHex))), outHex, `${alg}(${inputHex})`);
      assert.equal(core.hex(core.hashBytes(alg, H(inputHex))), outHex);
    }
  });
}

const LENGTHS = [0, 1, 54, 55, 56, 57, 63, 64, 65, 119, 120, 121, 127, 128, 129, 135, 136, 137, 271, 272, 1000, 4096];

function nodeHash(alg, data) {
  return createHash(alg).update(data).digest();
}

for (const alg of ["sha256", "sha1", "ripemd160"]) {
  test(`${alg}: block-boundary lengths agree with node:crypto`, () => {
    for (const n of LENGTHS) {
      const data = randomBytes(n);
      assert.equal(core.hex(fn[alg](data)), nodeHash(alg, data).toString("hex"), `${alg} len ${n}`);
    }
  });
}

test("sha256/sha1/ripemd160: all-zero and all-ff messages at boundaries", () => {
  for (const alg of ["sha256", "sha1", "ripemd160"]) {
    for (const n of [55, 56, 63, 64, 65, 119, 120]) {
      for (const fill of [0, 0xff]) {
        const d = new Uint8Array(n).fill(fill);
        assert.equal(core.hex(fn[alg](d)), nodeHash(alg, d).toString("hex"));
      }
    }
  }
});

test("known multi-block values", () => {
  const million = new Uint8Array(1_000_000).fill(0x61);
  assert.equal(core.hex(core.sha256(million)), "cdc76e5c9914fb9281a1c7e284d73e67f1809a48a497200e046d39ccc7112cd0");
  assert.equal(core.hex(core.sha1(million)), "34aa973cd4c4daa4f61eeb2bdbad27316534016f");
  assert.equal(core.hex(core.ripemd160(million)), "52783243c1697bdbe16d37f97f68f08325dc1528");
  const two = new TextEncoder().encode("abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq");
  assert.equal(core.hex(core.sha256(two)), "248d6a61d20638b8e5c026930c3e6039a33ce45964ff2167f6ecedd419db06c1");
});

test("keccak256 differs from NIST SHA3-256 (padding 0x01) and handles rate boundaries", () => {
  assert.equal(core.hex(core.keccak256(new Uint8Array(0))), "c5d2460186f7233c927e7db2dcc703c0e500b653ca82273b7bfad8045d85a470");
  assert.notEqual(core.hex(core.keccak256(new Uint8Array(0))), createHash("sha3-256").update("").digest("hex"));
  // the same permutation with NIST padding would give SHA3: cross-check by its known value for 'abc'
  assert.equal(core.hex(core.keccak256(H("616263"))), "4e03657aea45a94fc7d47ba826c8d667c0d1e6e33a64a036ec44f58fa12d6c45");
  // Keccak-256 of n bytes 0x5a, produced with pycryptodome (reference client's library), around the 136-byte rate
  const refs = {
    1: "7d54a4ab605dc825939ee59b4af5be4680f51892ef5944365e996fd93f70a2e5",
    55: "86de87e300025859fb02ad6d6f4bed3bbf580129345a5274ed7c6f3bf8276fb1",
    135: "03c527855334eb2e62b3b9b4d02ab76721707d3dde5fb218369640ee2edc7f3a",
    136: "ddc757d2caa82320e140f35833c18e8cc3b230b2b9a48def3d98461ffae81716",
    137: "37a14cb79c82d4b7d837a3f8ea134a324b138a5e4e3bb0814b75e52b17975b9c",
    200: "e0a0ddfeb4c428abbff0d8abe7bbea601185f9b9bafcf610c2acb0b6f6f3b61d",
    271: "6913adec7e366aaa82b47e65fa86e20416f3ca3bee8d3651b4b1e61a8e533ed1",
    272: "55f08c872f52ae47a17f2ed98203965fe6361a0a3036291c800eaec1fefe1a7e",
    273: "b207ec510b45402a9292f0d5abfe1ad018fe2aedcfbb7514e81333f8b33306e1",
    4096: "0549341144e711d1b8587d3dcf2672774c0352a89501b0e57b5ae13b1e7198f1",
  };
  for (const [n, want] of Object.entries(refs)) {
    assert.equal(core.hex(core.keccak256(new Uint8Array(Number(n)).fill(0x5a))), want, `keccak256 len ${n}`);
  }
});

test("streaming == one-shot with random chunking (sha256, sha1)", () => {
  for (const alg of ["sha256", "sha1"]) {
    for (const n of [0, 1, 55, 56, 64, 65, 1000, 70001]) {
      const data = randomBytes(n);
      const want = nodeHash(alg, data).toString("hex");
      for (let rep = 0; rep < 5; rep++) {
        const h = core.createStreamingHasher(alg);
        let i = 0;
        while (i < n) {
          const step = 1 + Math.floor(Math.random() * 200);
          h.update(data.subarray(i, i + step));
          i += step;
        }
        assert.equal(core.hex(h.digest()), want, `${alg} n=${n}`);
      }
    }
  }
});

test("hasher cannot be reused after digest", () => {
  const h = core.createStreamingHasher("sha256");
  h.update(H("00"));
  h.digest();
  assert.throws(() => h.digest(), /finalized/);
  assert.throws(() => h.update(H("00")), /finalized/);
});

test("hashBlob streams a Blob in 4 MiB chunks", async () => {
  const size = 9 * 1024 * 1024 + 123;
  const data = randomBytes(size);
  const calls = [];
  const blob = {
    size,
    slice(a, b) {
      calls.push([a, b]);
      return { arrayBuffer: async () => data.buffer.slice(data.byteOffset + a, data.byteOffset + b) };
    },
  };
  const progress = [];
  const got = await core.hashBlob(blob, "sha256", (d, t) => progress.push([d, t]));
  assert.equal(core.hex(got), nodeHash("sha256", data).toString("hex"));
  assert.equal(calls.length, 3);
  assert.deepEqual(calls[0], [0, 4194304]);
  assert.deepEqual(progress.at(-1), [size, size]);
  const sha1 = await core.hashBlob(blob, "sha1", undefined, 1_000_000);
  assert.equal(core.hex(sha1), nodeHash("sha1", data).toString("hex"));
  // a real Blob works too
  const real = new Blob([data.subarray(0, 5000)]);
  assert.equal(core.hex(await core.hashBlob(real, "sha256")), nodeHash("sha256", data.subarray(0, 5000)).toString("hex"));
  const f = core.fileFromBlob(real);
  assert.equal(f.size, 5000);
  assert.equal(core.hex(await f.digest("sha1")), nodeHash("sha1", data.subarray(0, 5000)).toString("hex"));
  const empty = core.fileFromBlob(new Blob([]));
  assert.equal(core.hex(await empty.digest("sha256")), "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855");
});

test("bytes helpers", () => {
  assert.equal(core.hex(H("00ff10")), "00ff10");
  assert.equal(core.fromHex("0G"), null);
  assert.equal(core.fromHex("abc"), null);
  assert.equal(core.fromHex(""), null);
  assert.deepEqual(core.fromHex("AbCd"), H("abcd"));
  assert.equal(core.isHex("zz"), false);
  assert.deepEqual(core.reversed(H("010203")), H("030201"));
  assert.equal(core.indexOfBytes(H("0102030405"), H("0304")), 2);
  assert.equal(core.indexOfBytes(H("0102"), H("")), -1);
  assert.equal(core.indexOfBytes(H("01"), H("0102")), -1);
  assert.equal(core.indexOfBytes(H("0102"), H("0103")), -1);
  assert.equal(core.equalBytes(H("01"), H("0102")), false);
  assert.deepEqual(core.asciiBytes("ab"), H("6162"));
  // base64url, RFC 4648 vectors (unpadded, url alphabet)
  for (const [raw, b64] of [["", ""], ["f", "Zg"], ["fo", "Zm8"], ["foo", "Zm9v"], ["foob", "Zm9vYg"], ["fooba", "Zm9vYmE"], ["foobar", "Zm9vYmFy"]]) {
    const bytes = new TextEncoder().encode(raw);
    assert.equal(core.base64urlEncode(bytes), b64);
    assert.deepEqual(core.base64urlDecode(b64), bytes);
  }
  assert.equal(core.base64urlEncode(H("fbff")), "-_8");
  assert.deepEqual(core.base64urlDecode("-_8"), H("fbff"));
  assert.equal(core.base64urlDecode("Zg=="), null);
  assert.equal(core.base64urlDecode("Z"), null);
  assert.equal(core.base64urlDecode("Zh"), null); // non-zero trailing bits
  assert.equal(core.base64urlDecode("Zm9="), null);
  assert.equal(core.base64urlDecode("Zm-"), null); // non-zero trailing bits (3 characters)
  assert.equal(core.base64urlDecode("a+b/"), null);
});

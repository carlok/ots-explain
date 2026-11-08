// web/src/core/bytes.ts
var HEX = "0123456789abcdef";
var HEX_TABLE = [];
for (let i = 0; i < 256; i++) HEX_TABLE.push(HEX[i >> 4] + HEX[i & 15]);
function hex(b) {
  let s = "";
  for (let i = 0; i < b.length; i++) s += HEX_TABLE[b[i]];
  return s;
}
function nibble(c) {
  if (c >= 48 && c <= 57) return c - 48;
  if (c >= 97 && c <= 102) return c - 87;
  if (c >= 65 && c <= 70) return c - 55;
  return -1;
}
function isHex(s) {
  if (s.length === 0 || s.length % 2 !== 0) return false;
  for (let i = 0; i < s.length; i++) if (nibble(s.charCodeAt(i)) < 0) return false;
  return true;
}
function fromHex(s) {
  if (!isHex(s)) return null;
  const out = new Uint8Array(s.length / 2);
  for (let i = 0; i < out.length; i++) {
    out[i] = nibble(s.charCodeAt(2 * i)) << 4 | nibble(s.charCodeAt(2 * i + 1));
  }
  return out;
}
function concat(...parts) {
  let n = 0;
  for (const p of parts) n += p.length;
  const out = new Uint8Array(n);
  let o = 0;
  for (const p of parts) {
    out.set(p, o);
    o += p.length;
  }
  return out;
}
function equalBytes(a, b) {
  if (a.length !== b.length) return false;
  for (let i = 0; i < a.length; i++) if (a[i] !== b[i]) return false;
  return true;
}
function indexOfBytes(hay, needle) {
  const n = needle.length;
  if (n === 0 || n > hay.length) return -1;
  outer: for (let i = 0; i + n <= hay.length; i++) {
    for (let j = 0; j < n; j++) if (hay[i + j] !== needle[j]) continue outer;
    return i;
  }
  return -1;
}
function reversed(b) {
  const out = new Uint8Array(b.length);
  for (let i = 0; i < b.length; i++) out[i] = b[b.length - 1 - i];
  return out;
}
function asciiBytes(s) {
  const out = new Uint8Array(s.length);
  for (let i = 0; i < s.length; i++) out[i] = s.charCodeAt(i) & 255;
  return out;
}
var B64URL = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
function base64urlEncode(b) {
  let s = "";
  let i = 0;
  for (; i + 2 < b.length; i += 3) {
    const v = b[i] << 16 | b[i + 1] << 8 | b[i + 2];
    s += B64URL[v >> 18] + B64URL[v >> 12 & 63] + B64URL[v >> 6 & 63] + B64URL[v & 63];
  }
  if (b.length - i === 1) {
    const v = b[i] << 16;
    s += B64URL[v >> 18] + B64URL[v >> 12 & 63];
  } else if (b.length - i === 2) {
    const v = b[i] << 16 | b[i + 1] << 8;
    s += B64URL[v >> 18] + B64URL[v >> 12 & 63] + B64URL[v >> 6 & 63];
  }
  return s;
}
function base64urlDecode(s) {
  if (s.length % 4 === 1) return null;
  const vals = [];
  for (let i2 = 0; i2 < s.length; i2++) {
    const k = B64URL.indexOf(s[i2]);
    if (k < 0) return null;
    vals.push(k);
  }
  const out = new Uint8Array(Math.floor(s.length * 6 / 8));
  let o = 0;
  let i = 0;
  for (; i + 3 < vals.length; i += 4) {
    const v = vals[i] << 18 | vals[i + 1] << 12 | vals[i + 2] << 6 | vals[i + 3];
    out[o++] = v >> 16;
    out[o++] = v >> 8 & 255;
    out[o++] = v & 255;
  }
  const rest = vals.length - i;
  if (rest === 2) {
    const v = vals[i] << 18 | vals[i + 1] << 12;
    if ((v & 65535) !== 0) return null;
    out[o++] = v >> 16;
  } else if (rest === 3) {
    const v = vals[i] << 18 | vals[i + 1] << 12 | vals[i + 2] << 6;
    if ((v & 255) !== 0) return null;
    out[o++] = v >> 16;
    out[o++] = v >> 8 & 255;
  }
  return out;
}

// web/src/core/hashes.ts
function rotl(x, n) {
  return x << n | x >>> 32 - n;
}
function rotr(x, n) {
  return x >>> n | x << 32 - n;
}
var BlockHasher = class {
  buf = new Uint8Array(64);
  bufLen = 0;
  total = 0;
  done = false;
  update(chunk) {
    if (this.done) throw new Error("hasher already finalized");
    let i = 0;
    const n = chunk.length;
    this.total += n;
    if (this.bufLen > 0) {
      const take = Math.min(64 - this.bufLen, n);
      this.buf.set(chunk.subarray(0, take), this.bufLen);
      this.bufLen += take;
      i = take;
      if (this.bufLen === 64) {
        this.compress(this.buf, 0);
        this.bufLen = 0;
      }
    }
    for (; i + 64 <= n; i += 64) this.compress(chunk, i);
    if (i < n) {
      this.buf.set(chunk.subarray(i), 0);
      this.bufLen = n - i;
    }
    return this;
  }
  digest() {
    if (this.done) throw new Error("hasher already finalized");
    this.done = true;
    const total = this.total;
    const padLen = this.bufLen < 56 ? 56 - this.bufLen : 120 - this.bufLen;
    const pad = new Uint8Array(padLen + 8);
    pad[0] = 128;
    const hi = Math.floor(total / 536870912);
    const lo = total * 8 >>> 0;
    const dv = new DataView(pad.buffer);
    if (this.bigEndian) {
      dv.setUint32(padLen, hi);
      dv.setUint32(padLen + 4, lo);
    } else {
      dv.setUint32(padLen, lo, true);
      dv.setUint32(padLen + 4, hi, true);
    }
    const saved = this.total;
    this.done = false;
    this.update(pad);
    this.total = saved;
    this.done = true;
    return this.output();
  }
};
var PRIMES = [];
for (let n = 2; PRIMES.length < 64; n++) {
  let p = true;
  for (let d = 2; d * d <= n; d++) if (n % d === 0) {
    p = false;
    break;
  }
  if (p) PRIMES.push(n);
}
var frac32 = (x) => Math.floor((x - Math.floor(x)) * 4294967296) >>> 0;
var SHA256_K = new Uint32Array(PRIMES.map((p) => frac32(Math.cbrt(p))));
var SHA256_H0 = new Uint32Array(PRIMES.slice(0, 8).map((p) => frac32(Math.sqrt(p))));
var Sha256Hasher = class extends BlockHasher {
  bigEndian = true;
  h = new Uint32Array(SHA256_H0);
  w = new Uint32Array(64);
  compress(b, o) {
    const w = this.w;
    for (let i = 0; i < 16; i++) {
      const j = o + 4 * i;
      w[i] = (b[j] << 24 | b[j + 1] << 16 | b[j + 2] << 8 | b[j + 3]) >>> 0;
    }
    for (let i = 16; i < 64; i++) {
      const x = w[i - 15];
      const y = w[i - 2];
      const s0 = rotr(x, 7) ^ rotr(x, 18) ^ x >>> 3;
      const s1 = rotr(y, 17) ^ rotr(y, 19) ^ y >>> 10;
      w[i] = w[i - 16] + s0 + w[i - 7] + s1 | 0;
    }
    const h = this.h;
    let a = h[0], bb = h[1], c = h[2], d = h[3], e = h[4], f = h[5], g = h[6], hh = h[7];
    for (let i = 0; i < 64; i++) {
      const S1 = rotr(e, 6) ^ rotr(e, 11) ^ rotr(e, 25);
      const ch = e & f ^ ~e & g;
      const t1 = hh + S1 + ch + SHA256_K[i] + w[i] | 0;
      const S0 = rotr(a, 2) ^ rotr(a, 13) ^ rotr(a, 22);
      const maj = a & bb ^ a & c ^ bb & c;
      const t2 = S0 + maj | 0;
      hh = g;
      g = f;
      f = e;
      e = d + t1 | 0;
      d = c;
      c = bb;
      bb = a;
      a = t1 + t2 | 0;
    }
    h[0] += a;
    h[1] += bb;
    h[2] += c;
    h[3] += d;
    h[4] += e;
    h[5] += f;
    h[6] += g;
    h[7] += hh;
  }
  output() {
    const out = new Uint8Array(32);
    const dv = new DataView(out.buffer);
    for (let i = 0; i < 8; i++) dv.setUint32(4 * i, this.h[i]);
    return out;
  }
};
var Sha1Hasher = class extends BlockHasher {
  bigEndian = true;
  h = new Uint32Array([1732584193, 4023233417, 2562383102, 271733878, 3285377520]);
  w = new Uint32Array(80);
  compress(b, o) {
    const w = this.w;
    for (let i = 0; i < 16; i++) {
      const j = o + 4 * i;
      w[i] = (b[j] << 24 | b[j + 1] << 16 | b[j + 2] << 8 | b[j + 3]) >>> 0;
    }
    for (let i = 16; i < 80; i++) w[i] = rotl(w[i - 3] ^ w[i - 8] ^ w[i - 14] ^ w[i - 16], 1);
    const h = this.h;
    let a = h[0], bb = h[1], c = h[2], d = h[3], e = h[4];
    for (let i = 0; i < 80; i++) {
      let f, k;
      if (i < 20) {
        f = bb & c | ~bb & d;
        k = 1518500249;
      } else if (i < 40) {
        f = bb ^ c ^ d;
        k = 1859775393;
      } else if (i < 60) {
        f = bb & c | bb & d | c & d;
        k = 2400959708;
      } else {
        f = bb ^ c ^ d;
        k = 3395469782;
      }
      const t = rotl(a, 5) + f + e + k + w[i] | 0;
      e = d;
      d = c;
      c = rotl(bb, 30);
      bb = a;
      a = t;
    }
    h[0] += a;
    h[1] += bb;
    h[2] += c;
    h[3] += d;
    h[4] += e;
  }
  output() {
    const out = new Uint8Array(20);
    const dv = new DataView(out.buffer);
    for (let i = 0; i < 5; i++) dv.setUint32(4 * i, this.h[i]);
    return out;
  }
};
var RMD_R1 = [
  0,
  1,
  2,
  3,
  4,
  5,
  6,
  7,
  8,
  9,
  10,
  11,
  12,
  13,
  14,
  15,
  7,
  4,
  13,
  1,
  10,
  6,
  15,
  3,
  12,
  0,
  9,
  5,
  2,
  14,
  11,
  8,
  3,
  10,
  14,
  4,
  9,
  15,
  8,
  1,
  2,
  7,
  0,
  6,
  13,
  11,
  5,
  12,
  1,
  9,
  11,
  10,
  0,
  8,
  12,
  4,
  13,
  3,
  7,
  15,
  14,
  5,
  6,
  2,
  4,
  0,
  5,
  9,
  7,
  12,
  2,
  10,
  14,
  1,
  3,
  8,
  11,
  6,
  15,
  13
];
var RMD_R2 = [
  5,
  14,
  7,
  0,
  9,
  2,
  11,
  4,
  13,
  6,
  15,
  8,
  1,
  10,
  3,
  12,
  6,
  11,
  3,
  7,
  0,
  13,
  5,
  10,
  14,
  15,
  8,
  12,
  4,
  9,
  1,
  2,
  15,
  5,
  1,
  3,
  7,
  14,
  6,
  9,
  11,
  8,
  12,
  2,
  10,
  0,
  4,
  13,
  8,
  6,
  4,
  1,
  3,
  11,
  15,
  0,
  5,
  12,
  2,
  13,
  9,
  7,
  10,
  14,
  12,
  15,
  10,
  4,
  1,
  5,
  8,
  7,
  6,
  2,
  13,
  14,
  0,
  3,
  9,
  11
];
var RMD_S1 = [
  11,
  14,
  15,
  12,
  5,
  8,
  7,
  9,
  11,
  13,
  14,
  15,
  6,
  7,
  9,
  8,
  7,
  6,
  8,
  13,
  11,
  9,
  7,
  15,
  7,
  12,
  15,
  9,
  11,
  7,
  13,
  12,
  11,
  13,
  6,
  7,
  14,
  9,
  13,
  15,
  14,
  8,
  13,
  6,
  5,
  12,
  7,
  5,
  11,
  12,
  14,
  15,
  14,
  15,
  9,
  8,
  9,
  14,
  5,
  6,
  8,
  6,
  5,
  12,
  9,
  15,
  5,
  11,
  6,
  8,
  13,
  12,
  5,
  12,
  13,
  14,
  11,
  8,
  5,
  6
];
var RMD_S2 = [
  8,
  9,
  9,
  11,
  13,
  15,
  15,
  5,
  7,
  7,
  8,
  11,
  14,
  14,
  12,
  6,
  9,
  13,
  15,
  7,
  12,
  8,
  9,
  11,
  7,
  7,
  12,
  7,
  6,
  15,
  13,
  11,
  9,
  7,
  15,
  11,
  8,
  6,
  6,
  14,
  12,
  13,
  5,
  14,
  13,
  13,
  7,
  5,
  15,
  5,
  8,
  11,
  14,
  14,
  6,
  14,
  6,
  9,
  12,
  9,
  12,
  5,
  15,
  8,
  8,
  5,
  12,
  9,
  12,
  5,
  14,
  6,
  8,
  13,
  6,
  5,
  15,
  13,
  11,
  11
];
var RMD_K1 = [0, 1518500249, 1859775393, 2400959708, 2840853838];
var RMD_K2 = [1352829926, 1548603684, 1836072691, 2053994217, 0];
function rmdF(j, x, y, z) {
  switch (j) {
    case 0:
      return x ^ y ^ z;
    case 1:
      return x & y | ~x & z;
    case 2:
      return (x | ~y) ^ z;
    case 3:
      return x & z | y & ~z;
    default:
      return x ^ (y | ~z);
  }
}
var Ripemd160Hasher = class extends BlockHasher {
  bigEndian = false;
  h = new Uint32Array([1732584193, 4023233417, 2562383102, 271733878, 3285377520]);
  x = new Uint32Array(16);
  compress(b, o) {
    const x = this.x;
    for (let i = 0; i < 16; i++) {
      const j = o + 4 * i;
      x[i] = (b[j + 3] << 24 | b[j + 2] << 16 | b[j + 1] << 8 | b[j]) >>> 0;
    }
    const h = this.h;
    let a1 = h[0], b1 = h[1], c1 = h[2], d1 = h[3], e1 = h[4];
    let a2 = a1, b2 = b1, c2 = c1, d2 = d1, e2 = e1;
    for (let j = 0; j < 80; j++) {
      const round = j >> 4;
      let t2 = rotl(a1 + rmdF(round, b1, c1, d1) + x[RMD_R1[j]] + RMD_K1[round] | 0, RMD_S1[j]) + e1 | 0;
      a1 = e1;
      e1 = d1;
      d1 = rotl(c1, 10);
      c1 = b1;
      b1 = t2;
      t2 = rotl(a2 + rmdF(4 - round, b2, c2, d2) + x[RMD_R2[j]] + RMD_K2[round] | 0, RMD_S2[j]) + e2 | 0;
      a2 = e2;
      e2 = d2;
      d2 = rotl(c2, 10);
      c2 = b2;
      b2 = t2;
    }
    const t = h[1] + c1 + d2 | 0;
    h[1] = h[2] + d1 + e2 | 0;
    h[2] = h[3] + e1 + a2 | 0;
    h[3] = h[4] + a1 + b2 | 0;
    h[4] = h[0] + b1 + c2 | 0;
    h[0] = t;
  }
  output() {
    const out = new Uint8Array(20);
    const dv = new DataView(out.buffer);
    for (let i = 0; i < 5; i++) dv.setUint32(4 * i, this.h[i], true);
    return out;
  }
};
var M64 = (1n << 64n) - 1n;
var KECCAK_RC = [];
var KECCAK_ROT = new Array(25).fill(0);
(() => {
  const lfsr = (t) => {
    if (t % 255 === 0) return 1;
    let r = 1;
    for (let i = 1; i <= t % 255; i++) {
      r <<= 1;
      if (r & 256) r ^= 369;
    }
    return r & 1;
  };
  for (let ir = 0; ir < 24; ir++) {
    let rc = 0n;
    for (let j = 0; j < 7; j++) if (lfsr(j + 7 * ir)) rc |= 1n << BigInt((1 << j) - 1);
    KECCAK_RC.push(rc);
  }
  let x = 1, y = 0;
  for (let t = 0; t < 24; t++) {
    KECCAK_ROT[x + 5 * y] = (t + 1) * (t + 2) / 2 % 64;
    const nx = y;
    y = (2 * x + 3 * y) % 5;
    x = nx;
  }
})();
var rol64 = (v, n) => n === 0 ? v : (v << BigInt(n) | v >> BigInt(64 - n)) & M64;
function keccakF(s) {
  const c = new Array(5);
  const b = new Array(25);
  for (let round = 0; round < 24; round++) {
    for (let x = 0; x < 5; x++) c[x] = s[x] ^ s[x + 5] ^ s[x + 10] ^ s[x + 15] ^ s[x + 20];
    for (let x = 0; x < 5; x++) {
      const d = c[(x + 4) % 5] ^ rol64(c[(x + 1) % 5], 1);
      for (let y = 0; y < 25; y += 5) s[x + y] ^= d;
    }
    for (let x = 0; x < 5; x++) {
      for (let y = 0; y < 5; y++) {
        b[y + 5 * ((2 * x + 3 * y) % 5)] = rol64(s[x + 5 * y], KECCAK_ROT[x + 5 * y]);
      }
    }
    for (let y = 0; y < 25; y += 5) {
      for (let x = 0; x < 5; x++) s[x + y] = b[x + y] ^ ~b[(x + 1) % 5 + y] & M64 & b[(x + 2) % 5 + y];
    }
    s[0] ^= KECCAK_RC[round];
  }
}
function keccak256(data) {
  const rate = 136;
  const padded = new Uint8Array(Math.floor(data.length / rate) * rate + rate);
  padded.set(data);
  padded[data.length] ^= 1;
  padded[padded.length - 1] ^= 128;
  const s = new Array(25).fill(0n);
  for (let off = 0; off < padded.length; off += rate) {
    for (let i = 0; i < rate / 8; i++) {
      let lane = 0n;
      for (let k = 7; k >= 0; k--) lane = lane << 8n | BigInt(padded[off + 8 * i + k]);
      s[i] ^= lane;
    }
    keccakF(s);
  }
  const out = new Uint8Array(32);
  for (let i = 0; i < 4; i++) {
    let lane = s[i];
    for (let k = 0; k < 8; k++) {
      out[8 * i + k] = Number(lane & 0xffn);
      lane >>= 8n;
    }
  }
  return out;
}
function sha256(data) {
  return new Sha256Hasher().update(data).digest();
}
function sha1(data) {
  return new Sha1Hasher().update(data).digest();
}
function ripemd160(data) {
  return new Ripemd160Hasher().update(data).digest();
}
function hashBytes(alg, data) {
  switch (alg) {
    case "sha256":
      return sha256(data);
    case "sha1":
      return sha1(data);
    case "ripemd160":
      return ripemd160(data);
    case "keccak256":
      return keccak256(data);
  }
}
function createStreamingHasher(alg) {
  return alg === "sha256" ? new Sha256Hasher() : new Sha1Hasher();
}
var FILE_CHUNK = 4 * 1024 * 1024;
async function hashBlob(blob, alg, onProgress, chunkSize = FILE_CHUNK) {
  const h = createStreamingHasher(alg);
  for (let i = 0; i < blob.size; i += chunkSize) {
    const buf = await blob.slice(i, Math.min(i + chunkSize, blob.size)).arrayBuffer();
    h.update(new Uint8Array(buf));
    if (onProgress) onProgress(Math.min(i + chunkSize, blob.size), blob.size);
  }
  return h.digest();
}

// web/src/core/tx.ts
function sha256d(b) {
  return sha256(sha256(b));
}
function readCompactSize(b, pos) {
  if (pos >= b.length) return null;
  const first = b[pos];
  if (first < 253) return { value: first, next: pos + 1 };
  const dv = new DataView(b.buffer, b.byteOffset, b.byteLength);
  if (first === 253) {
    if (pos + 3 > b.length) return null;
    return { value: dv.getUint16(pos + 1, true), next: pos + 3 };
  }
  if (first === 254) {
    if (pos + 5 > b.length) return null;
    return { value: dv.getUint32(pos + 1, true), next: pos + 5 };
  }
  if (pos + 9 > b.length) return null;
  const lo = dv.getUint32(pos + 1, true);
  const hi = dv.getUint32(pos + 5, true);
  if (hi !== 0) return null;
  return { value: lo, next: pos + 9 };
}
function parseLegacyTx(b) {
  let pos = 4;
  if (b.length < 4) return null;
  const nIn = readCompactSize(b, pos);
  if (nIn === null || nIn.value < 1) return null;
  pos = nIn.next;
  for (let i = 0; i < nIn.value; i++) {
    pos += 36;
    if (pos > b.length) return null;
    const sl = readCompactSize(b, pos);
    if (sl === null) return null;
    pos = sl.next + sl.value + 4;
    if (pos > b.length) return null;
  }
  const nOut = readCompactSize(b, pos);
  if (nOut === null || nOut.value < 1) return null;
  pos = nOut.next;
  const outputs = [];
  for (let i = 0; i < nOut.value; i++) {
    pos += 8;
    if (pos > b.length) return null;
    const sl = readCompactSize(b, pos);
    if (sl === null) return null;
    const start = sl.next;
    const end = start + sl.value;
    if (end > b.length) return null;
    outputs.push({ index: i, script: b.subarray(start, end) });
    pos = end;
  }
  if (pos + 4 !== b.length) return null;
  return { inputs: nIn.value, outputs };
}
function stripWitness(b) {
  if (!(b.length >= 6 && b[4] === 0 && b[5] === 1)) return b;
  let pos = 6;
  const nIn = readCompactSize(b, pos);
  if (nIn === null) return null;
  pos = nIn.next;
  for (let i = 0; i < nIn.value; i++) {
    pos += 36;
    if (pos > b.length) return null;
    const sl = readCompactSize(b, pos);
    if (sl === null) return null;
    pos = sl.next + sl.value + 4;
    if (pos > b.length) return null;
  }
  const nOut = readCompactSize(b, pos);
  if (nOut === null) return null;
  pos = nOut.next;
  for (let i = 0; i < nOut.value; i++) {
    pos += 8;
    if (pos > b.length) return null;
    const sl = readCompactSize(b, pos);
    if (sl === null) return null;
    pos = sl.next + sl.value;
    if (pos > b.length) return null;
  }
  const bodyEnd = pos;
  for (let i = 0; i < nIn.value; i++) {
    const items = readCompactSize(b, pos);
    if (items === null) return null;
    pos = items.next;
    for (let k = 0; k < items.value; k++) {
      const il = readCompactSize(b, pos);
      if (il === null) return null;
      pos = il.next + il.value;
      if (pos > b.length) return null;
    }
  }
  if (pos + 4 !== b.length) return null;
  return concat(b.subarray(0, 4), b.subarray(6, bodyEnd), b.subarray(pos));
}
function classifyScript(s) {
  if (s.length > 0 && s[0] === 106) return "op_return";
  if (s.length === 23 && s[0] === 169 && s[1] === 20 && s[22] === 135) return "p2sh";
  if (s.length === 25 && s[0] === 118 && s[1] === 169 && s[2] === 20 && s[23] === 136 && s[24] === 172) return "p2pkh";
  return "other";
}
function findCommitmentOutput(tx, commitment) {
  for (const o of tx.outputs) {
    if (indexOfBytes(o.script, commitment) >= 0) return { index: o.index, kind: classifyScript(o.script), script: o.script };
  }
  return null;
}
function parseHeader(h) {
  const dv = new DataView(h.buffer, h.byteOffset, h.byteLength);
  return { merkleRoot: h.subarray(36, 68), time: dv.getUint32(68, true), bits: dv.getUint32(72, true) };
}
function bitsToTarget(bits) {
  const exp = bits >>> 24;
  const mant = bits & 8388607;
  if (mant === 0) return null;
  if (bits & 8388608) return null;
  if (exp > 32 || mant > 255 && exp > 33 || mant > 65535 && exp > 34) return null;
  return exp <= 3 ? BigInt(mant >> 8 * (3 - exp)) : BigInt(mant) << BigInt(8 * (exp - 3));
}
function leToBigInt(b) {
  let v = 0n;
  for (let i = b.length - 1; i >= 0; i--) v = v << 8n | BigInt(b[i]);
  return v;
}
function blockHashOf(header) {
  return reversed(sha256d(header));
}
function meetsPow(header) {
  const target = bitsToTarget(parseHeader(header).bits);
  if (target === null) return false;
  return leToBigInt(sha256d(header)) <= target;
}

// web/src/core/parse.ts
var ParseError = class extends Error {
  constructor(code) {
    super(code);
    this.code = code;
    this.name = "ParseError";
  }
};
var MAGIC = new Uint8Array([
  0,
  79,
  112,
  101,
  110,
  84,
  105,
  109,
  101,
  115,
  116,
  97,
  109,
  112,
  115,
  0,
  0,
  80,
  114,
  111,
  111,
  102,
  0,
  191,
  137,
  226,
  232,
  132,
  232,
  146,
  148
]);
var LIMITS = {
  maxArg: 4096,
  maxResult: 4096,
  maxMsg: 4096,
  maxHexlifyMsg: 2048,
  maxPayload: 8192,
  maxUri: 1e3,
  maxVaruintBytes: 9,
  maxHeight: 4294967295n,
  recursion: 256
};
var TAGS = {
  "0588960d73d71901": "bitcoin",
  "06869a0d73d71b45": "litecoin",
  "30fe8087b5c7ead7": "ethereum",
  "83dfe30d2ef90c8e": "pending"
};
var HASH_OPS = { 2: "sha1", 3: "ripemd160", 8: "sha256" };
var HASH_LEN = { sha1: 20, ripemd160: 20, sha256: 32 };
var OP_BY_TAG = {
  240: "append",
  241: "prepend",
  8: "sha256",
  2: "sha1",
  3: "ripemd160",
  103: "keccak256",
  242: "reverse",
  243: "hexlify"
};
var Reader = class {
  constructor(b, onShort = "truncated", onLong = "varuint_too_long") {
    this.b = b;
    this.onShort = onShort;
    this.onLong = onLong;
  }
  pos = 0;
  get left() {
    return this.b.length - this.pos;
  }
  u8() {
    if (this.pos >= this.b.length) throw new ParseError(this.onShort);
    return this.b[this.pos++];
  }
  take(n) {
    if (n > this.left) throw new ParseError(this.onShort);
    const out = this.b.subarray(this.pos, this.pos + n);
    this.pos += n;
    return out;
  }
  /** LEB128, at most 9 bytes (63 bits). */
  varuint() {
    let value = 0n;
    let shift = 0n;
    for (let i = 0; i < LIMITS.maxVaruintBytes; i++) {
      const byte = this.u8();
      value |= BigInt(byte & 127) << shift;
      if ((byte & 128) === 0) return value;
      shift += 7n;
    }
    throw new ParseError(this.onLong);
  }
  /** varuint length, then bytes. `tooLong` is the code for length > max (or < min). */
  varbytes(max, min, tooLong) {
    const l = this.varuint();
    if (l > BigInt(max) || l < BigInt(min)) throw new ParseError(tooLong);
    return this.take(Number(l));
  }
};
function applyOp(op, arg, msg) {
  const maxMsg = op === "hexlify" ? LIMITS.maxHexlifyMsg : LIMITS.maxMsg;
  if (msg.length > maxMsg) throw new ParseError("msg_too_long");
  let r;
  switch (op) {
    case "append": {
      r = new Uint8Array(msg.length + arg.length);
      r.set(msg);
      r.set(arg, msg.length);
      break;
    }
    case "prepend": {
      r = new Uint8Array(msg.length + arg.length);
      r.set(arg);
      r.set(msg, arg.length);
      break;
    }
    case "sha256":
      r = sha256(msg);
      break;
    case "sha1":
      r = sha1(msg);
      break;
    case "ripemd160":
      r = ripemd160(msg);
      break;
    case "keccak256":
      r = keccak256(msg);
      break;
    case "reverse":
      if (msg.length === 0) throw new ParseError("empty_message");
      r = Uint8Array.from(msg).reverse();
      break;
    case "hexlify": {
      if (msg.length === 0) throw new ParseError("empty_message");
      const h = hex(msg);
      r = new Uint8Array(h.length);
      for (let i = 0; i < h.length; i++) r[i] = h.charCodeAt(i);
      break;
    }
  }
  if (r.length > LIMITS.maxResult) throw new ParseError("result_too_long");
  return r;
}
function parseAttestationPayload(kind, payload) {
  const r = new Reader(payload, "bad_attestation_payload", "bad_attestation_payload");
  let height = null;
  let uri = null;
  if (kind === "bitcoin" || kind === "litecoin" || kind === "ethereum") {
    const h = r.varuint();
    if (h > LIMITS.maxHeight) throw new ParseError("height_too_large");
    height = Number(h);
  } else if (kind === "pending") {
    const l = r.varuint();
    if (l > BigInt(LIMITS.maxUri)) throw new ParseError("bad_uri");
    const bytes = r.take(Number(l));
    let s = "";
    for (const c of bytes) {
      const ok = c >= 65 && c <= 90 || c >= 97 && c <= 122 || c >= 48 && c <= 57 || c === 45 || c === 46 || c === 95 || c === 47 || c === 58;
      if (!ok) throw new ParseError("bad_uri");
      s += String.fromCharCode(c);
    }
    uri = s;
  }
  if (kind !== "unknown" && r.left !== 0) throw new ParseError("bad_attestation_payload");
  return { height, uri };
}
function parseProof(bytes) {
  try {
    return { ok: true, proof: parseOrThrow(bytes) };
  } catch (e) {
    if (e instanceof ParseError) return { ok: false, code: e.code };
    throw e;
  }
}
function parseOrThrow(bytes) {
  const r = new Reader(bytes);
  const magic = bytes.subarray(0, MAGIC.length);
  if (!equalBytes(magic, MAGIC)) throw new ParseError("bad_magic");
  r.pos = MAGIC.length;
  if (r.u8() !== 1) throw new ParseError("unsupported_version");
  const hashOp = HASH_OPS[r.u8()];
  if (hashOp === void 0) throw new ParseError("unknown_file_hash_op");
  const digest = r.take(HASH_LEN[hashOp]);
  return parseTree(r, digest, hashOp, bytes.length);
}
function parseFragmentTree(msg, body) {
  if (msg.length < 1 || msg.length > LIMITS.maxMsg) throw new ParseError("arg_length");
  return parseTree(new Reader(body), msg, "sha256", body.length);
}
function parseTree(r, digest, hashOp, size) {
  const nodes = [{ id: 0, parent: -1, op: null, arg: null, msg: digest, depth: 0 }];
  const attestations = [];
  let maxDepth = 0;
  const readTimestamp = (nodeId, msg, limit, depth) => {
    if (limit === 0) throw new ParseError("recursion_limit");
    const seen = /* @__PURE__ */ new Set();
    const entry = (tag2) => {
      if (tag2 === 0) {
        const attTag = r.take(8);
        const payload = r.varbytes(LIMITS.maxPayload, 0, "payload_too_long");
        const kind = TAGS[hex(attTag)] ?? "unknown";
        const { height, uri } = parseAttestationPayload(kind, payload);
        attestations.push({ index: attestations.length, node: nodeId, kind, height, uri, tag: attTag, payload });
        return;
      }
      const op = OP_BY_TAG[tag2];
      if (op === void 0) throw new ParseError("unknown_op");
      let arg = null;
      if (op === "append" || op === "prepend") arg = r.varbytes(LIMITS.maxArg, 1, "arg_length");
      const key = tag2.toString(16) + ":" + (arg ? hex(arg) : "");
      if (seen.has(key)) throw new ParseError("repeated_op");
      seen.add(key);
      const result = applyOp(op, arg, msg);
      const child = { id: nodes.length, parent: nodeId, op, arg, msg: result, depth: depth + 1 };
      nodes.push(child);
      if (child.depth > maxDepth) maxDepth = child.depth;
      readTimestamp(child.id, result, limit - 1, depth + 1);
    };
    let tag = r.u8();
    while (tag === 255) {
      entry(r.u8());
      tag = r.u8();
    }
    entry(tag);
  };
  readTimestamp(0, digest, LIMITS.recursion, 0);
  if (r.left !== 0) throw new ParseError("trailing_garbage");
  return { size, version: 1, hashOp, digest, nodes, attestations, maxDepth };
}

// web/src/core/phases.ts
function pathTo(proof, node) {
  const path = [];
  for (let n = node; n !== -1; n = proof.nodes[n].parent) path.push(n);
  return path.reverse();
}
function computePhases(proof, att) {
  const none = (code) => ({ phases: null, phases_code: code });
  if (att.kind !== "bitcoin") return { phases: null, phases_code: null };
  const path = pathTo(proof, att.node);
  const K = path.length - 1;
  const msg = (i) => proof.nodes[path[i]].msg;
  const opAt = (i) => proof.nodes[path[i]].op;
  let t = -1;
  let tx = null;
  for (let i = 1; i <= K; i++) {
    tx = parseLegacyTx(msg(i));
    if (tx !== null) {
      t = i;
      break;
    }
  }
  if (tx === null) return none("no_transaction");
  let c = t;
  while (c > 0 && (opAt(c) === "append" || opAt(c) === "prepend")) c--;
  if (c === t) return none("no_transaction");
  if (!(t + 2 <= K && opAt(t + 1) === "sha256" && opAt(t + 2) === "sha256")) return none("no_txid_hash");
  const txid = hex(reversed(msg(t + 2)));
  const commitment = msg(c);
  const found = findCommitmentOutput(tx, commitment);
  return {
    phases: {
      path,
      commitment_index: c,
      transaction_index: t,
      txid_index: t + 2,
      root_index: K,
      commitment: hex(commitment),
      txid,
      output: found === null ? null : { index: found.index, kind: found.kind, script: hex(found.script) }
    },
    phases_code: null
  };
}

// web/src/core/ledger.ts
var DEFAULT_SERVERS = [
  { name: "blockstream.info", base: "https://blockstream.info/api" },
  { name: "mempool.space", base: "https://mempool.space/api" }
];
var CHECK_IDS = ["block_hash", "header", "merkle_root", "txids", "raw_tx", "output"];
function normalizeServers(servers) {
  const list = servers && servers.length > 0 ? servers : DEFAULT_SERVERS;
  return list.map((s) => ({ name: s.name, base: s.base.replace(/\/+$/, "") }));
}
function bitcoinTargets(proof) {
  const out = [];
  for (const att of proof.attestations) {
    if (att.kind !== "bitcoin") continue;
    const { phases } = computePhases(proof, att);
    out.push({
      att,
      phases,
      root: proof.nodes[att.node].msg,
      tx: phases === null ? null : proof.nodes[phases.path[phases.transaction_index]].msg
    });
  }
  return out;
}
function ledgerPlan(proof, servers) {
  const list = normalizeServers(servers);
  const plan = [];
  for (const t of bitcoinTargets(proof)) {
    for (const s of list) {
      const add = (path) => plan.push({ attestation: t.att.index, server: s.name, url: s.base + path });
      add("/block-height/" + t.att.height);
      add("/block/{block_hash}/header");
      if (t.phases !== null) {
        add("/block/{block_hash}/txids");
        add("/tx/" + t.phases.txid + "/hex");
      }
    }
  }
  return plan;
}
async function get(fetchText, url) {
  try {
    const res = await fetchText(url);
    if (res.status === 404) return { kind: "not_found" };
    if (res.status !== 200) return { kind: "unreachable" };
    return { kind: "ok", body: typeof res.body === "string" ? res.body : "" };
  } catch {
    return { kind: "unreachable" };
  }
}
var trim = (s) => s.replace(/^[ \t\r\n\f\v]+|[ \t\r\n\f\v]+$/g, "");
function combine(statuses) {
  if (statuses.includes("FAIL")) return "FAIL";
  if (statuses.includes("SKIP")) return "SKIP";
  return "PASS";
}
async function runServer(t, server, fetchText) {
  const res = { server: server.name, status: "PASS", block_hash: null, header: null, time: null, checks: [] };
  let halted = false;
  let header = null;
  const h = t.att.height;
  const record = (id, status, code) => {
    res.checks.push({ id, status, code });
    if (status !== "PASS") halted = true;
  };
  const gate = (id) => {
    if (halted) {
      res.checks.push({ id, status: "SKIP", code: "not_run" });
      return false;
    }
    return true;
  };
  const gateTx = (id) => {
    if (!gate(id)) return false;
    if (t.phases === null) {
      res.checks.push({ id, status: "SKIP", code: "no_transaction" });
      return false;
    }
    return true;
  };
  const httpFail = (id, g) => {
    if (g.kind === "not_found") record(id, "FAIL", "not_found");
    else if (g.kind === "unreachable") record(id, "SKIP", "unreachable");
    return g.kind !== "ok";
  };
  if (gate("block_hash")) {
    const g = await get(fetchText, `${server.base}/block-height/${h}`);
    if (!httpFail("block_hash", g) && g.kind === "ok") {
      const body = trim(g.body);
      if (body.length === 64 && isHex(body)) {
        res.block_hash = body.toLowerCase();
        record("block_hash", "PASS", "ok");
      } else record("block_hash", "FAIL", "bad_response");
    }
  }
  if (gate("header")) {
    const g = await get(fetchText, `${server.base}/block/${res.block_hash}/header`);
    if (!httpFail("header", g) && g.kind === "ok") {
      const body = trim(g.body);
      if (body.length !== 160 || !isHex(body)) record("header", "FAIL", "bad_response");
      else {
        res.header = body.toLowerCase();
        header = fromHex(res.header);
        if (hex(blockHashOf(header)) !== res.block_hash) record("header", "FAIL", "bad_hash");
        else if (!meetsPow(header)) record("header", "FAIL", "bad_pow");
        else {
          res.time = parseHeader(header).time;
          record("header", "PASS", "ok");
        }
      }
    }
  }
  if (gate("merkle_root")) {
    if (equalBytes(parseHeader(header).merkleRoot, t.root)) record("merkle_root", "PASS", "ok");
    else record("merkle_root", "FAIL", "mismatch");
  }
  if (gateTx("txids")) {
    const g = await get(fetchText, `${server.base}/block/${res.block_hash}/txids`);
    if (!httpFail("txids", g) && g.kind === "ok") {
      let list = null;
      try {
        list = JSON.parse(g.body);
      } catch {
        list = null;
      }
      if (!Array.isArray(list) || !list.every((x) => typeof x === "string")) record("txids", "FAIL", "bad_response");
      else if (!list.includes(t.phases.txid)) record("txids", "FAIL", "not_in_block");
      else record("txids", "PASS", "ok");
    }
  }
  if (gateTx("raw_tx")) {
    const g = await get(fetchText, `${server.base}/tx/${t.phases.txid}/hex`);
    if (!httpFail("raw_tx", g) && g.kind === "ok") {
      const raw = fromHex(trim(g.body));
      const stripped = raw === null ? null : stripWitness(raw);
      if (stripped === null) record("raw_tx", "FAIL", "bad_response");
      else if (!equalBytes(stripped, t.tx)) record("raw_tx", "FAIL", "mismatch");
      else record("raw_tx", "PASS", "ok");
    }
  }
  if (gateTx("output")) {
    if (t.phases.output !== null) record("output", "PASS", "ok");
    else record("output", "FAIL", "no_output");
  }
  res.status = combine(res.checks.map((c) => c.status));
  return res;
}
function agreeOf(servers) {
  const headers = servers.map((s) => s.header).filter((x) => x !== null);
  if (headers.length < 2) return null;
  return headers.every((x) => x === headers[0]);
}
async function runLedger(proof, servers, fetchText) {
  const targets = bitcoinTargets(proof);
  if (targets.length === 0) return null;
  const list = normalizeServers(servers);
  const attestations = [];
  for (const t of targets) {
    const results = [];
    for (const s of list) results.push(await runServer(t, s, fetchText));
    attestations.push({ attestation: t.att.index, agree: agreeOf(results), servers: results });
  }
  return { servers: list, plan: ledgerPlan(proof, list), attestations };
}
function ledgerOutcome(l) {
  if (l.attestations.some((a) => a.agree === false)) return { status: "FAIL", code: "disagree" };
  const all = l.attestations.flatMap((a) => a.servers.flatMap((s) => s.checks.map((c) => c.status)));
  if (all.includes("FAIL")) return { status: "FAIL", code: "check_failed" };
  if (all.includes("SKIP")) return { status: "SKIP", code: "incomplete" };
  return { status: "PASS", code: "ok" };
}

// web/src/core/report.ts
var REPORT_SPEC = "ots-explain-report/1";
var STEP_TITLES = {
  file_hash: "File to hash",
  structure: "Proof structure",
  hash_steps: "Hash steps",
  ledger: "The ledger",
  verdict: "Verdict"
};
function whereToLook(height, txid) {
  const out = [];
  const sites = [["blockstream.info", "https://blockstream.info"], ["mempool.space", "https://mempool.space"]];
  for (const [server, site] of sites) {
    out.push({ kind: "block", server, url: server === "blockstream.info" ? `${site}/block-height/${height}` : `${site}/block/${height}` });
    out.push({ kind: "tx", server, url: `${site}/tx/${txid}` });
    out.push({ kind: "raw_hex", server, url: `${site}/api/tx/${txid}/hex` });
  }
  return out;
}
function reportProof(p) {
  return {
    size: p.size,
    version: p.version,
    hash_op: p.hashOp,
    digest: hex(p.digest),
    nodes: p.nodes.length,
    ops: p.nodes.length - 1,
    max_depth: p.maxDepth,
    tree: p.nodes.map((n) => ({
      id: n.id,
      parent: n.parent,
      op: n.op,
      arg: n.arg === null ? null : hex(n.arg),
      digest: hex(n.msg)
    })),
    attestations: p.attestations.map((a) => {
      const phases = computePhases(p, a).phases;
      return {
        index: a.index,
        node: a.node,
        kind: a.kind,
        height: a.height,
        uri: a.uri,
        tag: hex(a.tag),
        payload: hex(a.payload),
        phases,
        where_to_look: phases === null || a.height === null ? [] : whereToLook(a.height, phases.txid)
      };
    })
  };
}
async function buildReport(opts) {
  const parsed = parseProof(opts.proof ?? new Uint8Array(0));
  const mode = opts.file ? "file" : opts.digestHex !== void 0 && opts.digestHex !== null ? "digest" : "none";
  let inSize = null;
  let inDigest = null;
  let s1;
  if (mode === "file") inSize = opts.file.size;
  if (mode === "digest" && isHex(opts.digestHex)) inDigest = opts.digestHex.toLowerCase();
  if (!parsed.ok) {
    s1 = { status: "SKIP", code: "no_proof" };
  } else if (mode === "none") {
    s1 = { status: "SKIP", code: "no_input" };
  } else if (mode === "file") {
    if (parsed.proof.hashOp === "ripemd160") s1 = { status: "SKIP", code: "alg_unsupported" };
    else {
      inDigest = hex(await opts.file.digest(parsed.proof.hashOp));
      s1 = inDigest === hex(parsed.proof.digest) ? { status: "PASS", code: "ok" } : { status: "FAIL", code: "mismatch" };
    }
  } else if (inDigest === null || inDigest.length !== parsed.proof.digest.length * 2) {
    s1 = { status: "FAIL", code: "bad_digest" };
  } else {
    s1 = inDigest === hex(parsed.proof.digest) ? { status: "PASS", code: "ok" } : { status: "FAIL", code: "mismatch" };
  }
  const s2 = parsed.ok ? { status: "PASS", code: "ok" } : { status: "FAIL", code: parsed.code };
  let s3;
  if (!parsed.ok) s3 = { status: "SKIP", code: "no_proof" };
  else if (s1.status === "PASS") s3 = { status: "PASS", code: "ok" };
  else s3 = { status: "SKIP", code: "not_tied" };
  let ledger = null;
  let s4;
  if (!parsed.ok) s4 = { status: "SKIP", code: "no_proof" };
  else if (!opts.ledger) s4 = { status: "SKIP", code: "not_requested" };
  else {
    ledger = await runLedger(parsed.proof, opts.ledger.servers, opts.ledger.fetchText);
    s4 = ledger === null ? { status: "SKIP", code: "no_bitcoin" } : ledgerOutcome(ledger);
  }
  const all = [s1, s2, s3, s4];
  const vstatus = all.some((s) => s.status === "FAIL") ? "FAIL" : all.some((s) => s.status === "SKIP") ? "SKIP" : "PASS";
  let block = null;
  let time = null;
  if (vstatus === "PASS" && parsed.ok && ledger !== null) {
    let best = null;
    for (const a of parsed.proof.attestations) {
      if (a.kind === "bitcoin" && a.height !== null && (best === null || a.height < best.height)) best = { height: a.height, attestation: a.index };
    }
    if (best !== null) {
      block = best.height;
      const al = ledger.attestations.find((x) => x.attestation === best.attestation);
      time = al?.servers.find((s) => s.time !== null)?.time ?? null;
    }
  }
  const unverified = parsed.ok ? parsed.proof.attestations.filter((a) => a.kind !== "bitcoin").map((a) => a.index) : [];
  const steps = [
    { id: "file_hash", title: STEP_TITLES.file_hash, ...s1 },
    { id: "structure", title: STEP_TITLES.structure, ...s2 },
    { id: "hash_steps", title: STEP_TITLES.hash_steps, ...s3 },
    { id: "ledger", title: STEP_TITLES.ledger, ...s4 },
    { id: "verdict", title: STEP_TITLES.verdict, status: vstatus, code: vstatus === "PASS" ? "proved" : vstatus === "FAIL" ? "failed" : "incomplete" }
  ];
  return {
    spec: REPORT_SPEC,
    input: { mode, size: inSize, digest: inDigest, digest_alg: parsed.ok ? parsed.proof.hashOp : null },
    error: parsed.ok ? null : { code: parsed.code },
    proof: parsed.ok ? reportProof(parsed.proof) : null,
    steps,
    ledger,
    verdict: {
      status: vstatus,
      code: vstatus === "PASS" ? "proved" : vstatus === "FAIL" ? "failed" : "incomplete",
      block,
      time,
      unverified
    }
  };
}

// web/src/core/canonical.ts
function cmpCodePoints(a, b) {
  const ia = a[Symbol.iterator]();
  const ib = b[Symbol.iterator]();
  for (; ; ) {
    const x = ia.next();
    const y = ib.next();
    if (x.done && y.done) return 0;
    if (x.done) return -1;
    if (y.done) return 1;
    const cx = x.value.codePointAt(0);
    const cy = y.value.codePointAt(0);
    if (cx !== cy) return cx < cy ? -1 : 1;
  }
}
function quote(s) {
  let out = '"';
  for (let i = 0; i < s.length; i++) {
    const c = s.charCodeAt(i);
    if (c === 34) out += '\\"';
    else if (c === 92) out += "\\\\";
    else if (c === 10) out += "\\n";
    else if (c === 13) out += "\\r";
    else if (c === 9) out += "\\t";
    else if (c < 32) out += "\\u00" + (c < 16 ? "0" : "") + c.toString(16);
    else out += s[i];
  }
  return out + '"';
}
function canonicalJson(v) {
  if (v === null) return "null";
  switch (typeof v) {
    case "boolean":
      return v ? "true" : "false";
    case "number":
      if (!Number.isSafeInteger(v)) throw new Error("canonical JSON allows integers only: " + String(v));
      return String(v);
    case "string":
      return quote(v);
    case "object": {
      if (Array.isArray(v)) return "[" + v.map(canonicalJson).join(",") + "]";
      const o = v;
      const keys = Object.keys(o).sort(cmpCodePoints);
      return "{" + keys.map((k) => quote(k) + ":" + canonicalJson(o[k])).join(",") + "}";
    }
    default:
      throw new Error("not representable in canonical JSON: " + typeof v);
  }
}
function canonicalBytes(v) {
  return new TextEncoder().encode(canonicalJson(v));
}

// web/src/core/permalink.ts
var UNRESERVED = /[A-Za-z0-9\-._~]/;
function percentEncode(s) {
  let out = "";
  for (const b of new TextEncoder().encode(s)) {
    const ch = String.fromCharCode(b);
    out += b < 128 && UNRESERVED.test(ch) ? ch : "%" + (b < 16 ? "0" : "") + b.toString(16).toUpperCase();
  }
  return out;
}
function percentDecode(s) {
  const bytes = [];
  for (let i = 0; i < s.length; i++) {
    const c = s[i];
    if (c === "%") {
      const v = fromHex(s.slice(i + 1, i + 3));
      if (v === null || s.length < i + 3) return null;
      bytes.push(v[0]);
      i += 2;
    } else {
      const code = s.charCodeAt(i);
      if (code > 127) {
        for (const b of new TextEncoder().encode(s[i])) bytes.push(b);
      } else bytes.push(code);
    }
  }
  try {
    return new TextDecoder("utf-8", { fatal: true }).decode(new Uint8Array(bytes));
  } catch {
    return null;
  }
}
function encodePermalink(base, parts = {}) {
  let url = base;
  if (parts.proofUrl) url += "?proof=" + percentEncode(parts.proofUrl);
  const frag = [];
  if (parts.digestHex) frag.push("h=" + parts.digestHex.toLowerCase());
  if (parts.ots) frag.push("ots=" + base64urlEncode(parts.ots));
  if (frag.length > 0) url += "#" + frag.join("&");
  return url;
}
function firstParams(s) {
  const m = /* @__PURE__ */ new Map();
  if (s === "") return m;
  for (const part of s.split("&")) {
    const eq = part.indexOf("=");
    if (eq < 0) continue;
    const k = part.slice(0, eq);
    if (!m.has(k)) m.set(k, part.slice(eq + 1));
  }
  return m;
}
function decodePermalink(url) {
  const hash = url.indexOf("#");
  const beforeHash = hash < 0 ? url : url.slice(0, hash);
  const fragment = hash < 0 ? "" : url.slice(hash + 1);
  const q = beforeHash.indexOf("?");
  const base = q < 0 ? beforeHash : beforeHash.slice(0, q);
  const query = q < 0 ? "" : beforeHash.slice(q + 1);
  const qp = firstParams(query);
  const fp = firstParams(fragment);
  const proofRaw = qp.get("proof");
  const hRaw = fp.get("h");
  const otsRaw = fp.get("ots");
  return {
    base,
    proofUrl: proofRaw === void 0 ? null : percentDecode(proofRaw),
    digestHex: hRaw !== void 0 && isHex(hRaw) ? hRaw.toLowerCase() : null,
    ots: otsRaw === void 0 ? null : base64urlDecode(otsRaw)
  };
}

// web/src/core/stamp.ts
var MAX_CALENDAR_RESPONSE = 1e4;
var DEFAULT_CALENDARS = [
  "https://alice.btc.calendar.opentimestamps.org",
  "https://bob.btc.calendar.opentimestamps.org",
  "https://finney.calendar.eternitywall.com"
];
var KNOWN_CALENDARS = [
  ...DEFAULT_CALENDARS,
  "https://btc.calendar.catallaxy.com",
  "https://ots.btc.catallaxy.com"
];
function stripSlashes(s) {
  let n = s.length;
  while (n > 0 && s.charCodeAt(n - 1) === 47) n--;
  return s.slice(0, n);
}
function join(base, path) {
  return stripSlashes(base) + "/" + path;
}
var Failure = class extends Error {
};
function messageOf(e) {
  return e instanceof Error ? e.message : String(e);
}
function commitmentFor(digest, nonce) {
  return sha256(concat(digest, nonce));
}
var OP_BYTE = {
  append: 240,
  prepend: 241,
  sha256: 8,
  sha1: 2,
  ripemd160: 3,
  keccak256: 103,
  reverse: 242,
  hexlify: 243
};
var HASH_OP_BYTE = { sha256: 8, sha1: 2, ripemd160: 3 };
function toTree(p) {
  const nodes = p.nodes.map((n) => ({ msg: n.msg, atts: [], edges: [] }));
  for (const n of p.nodes) {
    if (n.parent >= 0) nodes[n.parent].edges.push({ op: n.op, arg: n.arg ? n.arg.slice() : null, child: nodes[n.id] });
  }
  for (const a of p.attestations) {
    nodes[a.node].atts.push({
      kind: a.kind,
      height: a.height,
      uri: a.uri,
      tag: a.tag.slice(),
      payload: a.payload.slice()
    });
  }
  return nodes[0];
}
function parseFragment(msg, body) {
  if (body.length > MAX_CALENDAR_RESPONSE) throw new ParseError("payload_too_long");
  const proof = parseFragmentTree(msg, body);
  return { root: toTree(proof), proof };
}
function sameArg(a, b) {
  if (a === null || b === null) return a === b;
  return equalBytes(a, b);
}
function cloneNode(n) {
  return {
    msg: n.msg,
    atts: n.atts.map((a) => ({ ...a, tag: a.tag.slice(), payload: a.payload.slice() })),
    edges: n.edges.map((e) => ({ op: e.op, arg: e.arg ? e.arg.slice() : null, child: cloneNode(e.child) }))
  };
}
function merge(into, frag) {
  for (const a of frag.atts) {
    const dup = into.atts.some((b) => equalBytes(a.tag, b.tag) && equalBytes(a.payload, b.payload));
    if (!dup) into.atts.push({ ...a, tag: a.tag.slice(), payload: a.payload.slice() });
  }
  for (const e of frag.edges) {
    const same = into.edges.find((f) => f.op === e.op && sameArg(f.arg, e.arg));
    if (same) merge(same.child, e.child);
    else into.edges.push({ op: e.op, arg: e.arg ? e.arg.slice() : null, child: cloneNode(e.child) });
  }
}
function varuint(n) {
  const out = [];
  let v = n;
  do {
    let b = v % 128;
    v = Math.floor(v / 128);
    if (v > 0) b |= 128;
    out.push(b);
  } while (v > 0);
  return Uint8Array.from(out);
}
function varbytes(b) {
  return concat(varuint(b.length), b);
}
function cmpBytes(a, b) {
  const n = Math.min(a.length, b.length);
  for (let i = 0; i < n; i++) if (a[i] !== b[i]) return a[i] - b[i];
  return a.length - b.length;
}
function attSecondary(a) {
  if (a.uri !== null) return Uint8Array.from(a.uri, (c) => c.charCodeAt(0) & 255);
  return a.payload;
}
function cmpAtt(a, b) {
  return cmpBytes(a.tag, b.tag) || (a.height ?? 0) - (b.height ?? 0) || cmpBytes(attSecondary(a), attSecondary(b));
}
function cmpEdge(a, b) {
  return OP_BYTE[a.op] - OP_BYTE[b.op] || cmpBytes(a.arg ?? new Uint8Array(0), b.arg ?? new Uint8Array(0));
}
function writeNode(n, out) {
  if (n.atts.length + n.edges.length === 0) throw new Error("a timestamp node has no entries");
  const atts = n.atts.slice().sort(cmpAtt);
  const edges = n.edges.slice().sort(cmpEdge);
  let left = atts.length + edges.length;
  const lead = () => {
    if (--left > 0) out.push(Uint8Array.of(255));
  };
  for (const a of atts) {
    lead();
    out.push(Uint8Array.of(0), a.tag, varbytes(a.payload));
  }
  for (const e of edges) {
    lead();
    out.push(Uint8Array.of(OP_BYTE[e.op]));
    if (e.op === "append" || e.op === "prepend") out.push(varbytes(e.arg));
    writeNode(e.child, out);
  }
}
function serialize(hashOp, digest, root) {
  const out = [MAGIC, Uint8Array.of(1, HASH_OP_BYTE[hashOp]), digest];
  writeNode(root, out);
  return concat(...out);
}
async function stampDigest(digest, calendars, call, nonce, log) {
  if (digest.length !== 32) throw new Error("the digest must be 32 bytes");
  if (nonce.length !== 16) throw new Error("the nonce must be 16 bytes");
  const m1 = concat(digest, nonce);
  const c = sha256(m1);
  const tip = { msg: c, atts: [], edges: [] };
  const root = {
    msg: digest,
    atts: [],
    edges: [{ op: "append", arg: nonce.slice(), child: { msg: m1, atts: [], edges: [{ op: "sha256", arg: null, child: tip }] } }]
  };
  let accepted = 0;
  for (const cal of calendars) {
    let frag;
    try {
      let res;
      try {
        res = await call(join(cal, "digest"), c);
      } catch (e) {
        throw new Failure(messageOf(e));
      }
      if (res.status !== 200) throw new Failure(`HTTP ${res.status}`);
      if (res.body.length > MAX_CALENDAR_RESPONSE) throw new Failure("payload_too_long");
      try {
        frag = parseFragment(c, res.body).root;
      } catch (e) {
        if (e instanceof ParseError) throw new Failure(e.code);
        throw e;
      }
    } catch (e) {
      if (e instanceof Failure) {
        log(`calendar ${cal} failed: ${e.message}`);
        continue;
      }
      throw e;
    }
    merge(tip, frag);
    accepted++;
    log(`calendar ${cal} accepted the commitment`);
  }
  if (accepted === 0) throw new Error("no calendar accepted the commitment");
  return serialize("sha256", digest, root);
}
async function upgradeProof(proof, call, allowed, log) {
  const parsed = parseProof(proof);
  if (!parsed.ok) throw new ParseError(parsed.code);
  const p = parsed.proof;
  const hasBitcoin = p.attestations.some((a) => a.kind === "bitcoin");
  const hasPending = p.attestations.some((a) => a.kind === "pending");
  if (hasBitcoin && !hasPending) return { bytes: proof, changed: false, status: "nothing_to_do" };
  const root = toTree(p);
  const todo = [];
  const walk = (n) => {
    for (const a of n.atts) if (a.kind === "pending") todo.push({ node: n, uri: a.uri });
    for (const e of n.edges) walk(e.child);
  };
  walk(root);
  const allowedSet = new Set(allowed.map(stripSlashes));
  let changed = false;
  for (const { node, uri } of todo) {
    if (!allowedSet.has(stripSlashes(uri))) {
      log(`not asking ${uri}: not on the allowed list (use --allow)`);
      continue;
    }
    let res;
    try {
      res = await call(join(uri, "timestamp/" + hex(node.msg)));
    } catch (e) {
      log(`${uri} unreachable: ${messageOf(e)}`);
      continue;
    }
    if (res.status === 404) {
      log(`${uri}: not confirmed yet`);
      continue;
    }
    if (res.status !== 200) {
      log(`${uri}: HTTP ${res.status}`);
      continue;
    }
    let frag;
    try {
      frag = parseFragment(node.msg, res.body);
    } catch (e) {
      if (e instanceof ParseError) {
        log(`${uri} sent an unreadable answer: ${e.code}`);
        continue;
      }
      throw e;
    }
    if (!frag.proof.attestations.some((a) => a.kind === "bitcoin")) {
      log(`${uri}: answer has no Bitcoin attestation yet`);
      continue;
    }
    node.atts = node.atts.filter((a) => !(a.kind === "pending" && a.uri === uri));
    merge(node, frag.root);
    changed = true;
  }
  if (!changed) return { bytes: proof, changed: false, status: "pending" };
  const bytes = serialize(p.hashOp, p.digest, root);
  const check = parseProof(bytes);
  if (!check.ok) throw new ParseError(check.code);
  return { bytes, changed: true, status: "complete" };
}

// web/src/core/index.ts
function fileFromBlob(blob, onProgress) {
  return { size: blob.size, digest: (alg) => hashBlob(blob, alg, onProgress) };
}
export {
  CHECK_IDS,
  DEFAULT_CALENDARS,
  DEFAULT_SERVERS,
  FILE_CHUNK,
  KNOWN_CALENDARS,
  LIMITS,
  MAGIC,
  ParseError,
  REPORT_SPEC,
  STEP_TITLES,
  Sha1Hasher,
  Sha256Hasher,
  agreeOf,
  asciiBytes,
  base64urlDecode,
  base64urlEncode,
  bitcoinTargets,
  bitsToTarget,
  blockHashOf,
  buildReport,
  canonicalBytes,
  canonicalJson,
  classifyScript,
  commitmentFor,
  computePhases,
  concat,
  createStreamingHasher,
  decodePermalink,
  encodePermalink,
  equalBytes,
  fileFromBlob,
  findCommitmentOutput,
  fromHex,
  hashBlob,
  hashBytes,
  hex,
  indexOfBytes,
  isHex,
  keccak256,
  ledgerOutcome,
  ledgerPlan,
  meetsPow,
  normalizeServers,
  parseFragmentTree,
  parseHeader,
  parseLegacyTx,
  parseProof,
  pathTo,
  readCompactSize,
  reversed,
  ripemd160,
  runLedger,
  sha1,
  sha256,
  sha256d,
  stampDigest,
  stripWitness,
  upgradeProof
};

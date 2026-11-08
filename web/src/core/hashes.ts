// Own synchronous implementations of SHA-256, SHA-1, RIPEMD-160 and Keccak-256 (original
// Keccak padding 0x01, not NIST SHA-3), plus incremental hashers for SHA-256 and SHA-1.

export type HashAlg = "sha256" | "sha1" | "ripemd160" | "keccak256";

function rotl(x: number, n: number): number {
  return (x << n) | (x >>> (32 - n));
}
function rotr(x: number, n: number): number {
  return (x >>> n) | (x << (32 - n));
}

/**
 * Merkle-Damgard base: 64-byte blocks, 0x80 padding, 64-bit length.
 * Subclasses provide compress() and the output encoding.
 */
abstract class BlockHasher {
  protected readonly buf = new Uint8Array(64);
  protected bufLen = 0;
  protected total = 0;
  private done = false;

  protected abstract compress(block: Uint8Array, off: number): void;
  protected abstract readonly bigEndian: boolean;
  protected abstract output(): Uint8Array;

  update(chunk: Uint8Array): this {
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

  digest(): Uint8Array {
    if (this.done) throw new Error("hasher already finalized");
    this.done = true;
    const total = this.total;
    const padLen = this.bufLen < 56 ? 56 - this.bufLen : 120 - this.bufLen;
    const pad = new Uint8Array(padLen + 8);
    pad[0] = 0x80;
    const hi = Math.floor(total / 0x20000000);
    const lo = (total * 8) >>> 0;
    const dv = new DataView(pad.buffer);
    if (this.bigEndian) {
      dv.setUint32(padLen, hi);
      dv.setUint32(padLen + 4, lo);
    } else {
      dv.setUint32(padLen, lo, true);
      dv.setUint32(padLen + 4, hi, true);
    }
    // feed the padding through the block machinery without touching `total`
    const saved = this.total;
    this.done = false;
    this.update(pad);
    this.total = saved;
    this.done = true;
    return this.output();
  }
}

// ---- SHA-256 -------------------------------------------------------------

const PRIMES: number[] = [];
for (let n = 2; PRIMES.length < 64; n++) {
  let p = true;
  for (let d = 2; d * d <= n; d++) if (n % d === 0) { p = false; break; }
  if (p) PRIMES.push(n);
}
const frac32 = (x: number): number => Math.floor((x - Math.floor(x)) * 4294967296) >>> 0;
const SHA256_K = new Uint32Array(PRIMES.map((p) => frac32(Math.cbrt(p))));
const SHA256_H0 = new Uint32Array(PRIMES.slice(0, 8).map((p) => frac32(Math.sqrt(p))));

/** Incremental SHA-256. */
export class Sha256Hasher extends BlockHasher {
  protected readonly bigEndian = true;
  private readonly h = new Uint32Array(SHA256_H0);
  private readonly w = new Uint32Array(64);

  protected compress(b: Uint8Array, o: number): void {
    const w = this.w;
    for (let i = 0; i < 16; i++) {
      const j = o + 4 * i;
      w[i] = ((b[j] << 24) | (b[j + 1] << 16) | (b[j + 2] << 8) | b[j + 3]) >>> 0;
    }
    for (let i = 16; i < 64; i++) {
      const x = w[i - 15];
      const y = w[i - 2];
      const s0 = rotr(x, 7) ^ rotr(x, 18) ^ (x >>> 3);
      const s1 = rotr(y, 17) ^ rotr(y, 19) ^ (y >>> 10);
      w[i] = (w[i - 16] + s0 + w[i - 7] + s1) | 0;
    }
    const h = this.h;
    let a = h[0], bb = h[1], c = h[2], d = h[3], e = h[4], f = h[5], g = h[6], hh = h[7];
    for (let i = 0; i < 64; i++) {
      const S1 = rotr(e, 6) ^ rotr(e, 11) ^ rotr(e, 25);
      const ch = (e & f) ^ (~e & g);
      const t1 = (hh + S1 + ch + SHA256_K[i] + w[i]) | 0;
      const S0 = rotr(a, 2) ^ rotr(a, 13) ^ rotr(a, 22);
      const maj = (a & bb) ^ (a & c) ^ (bb & c);
      const t2 = (S0 + maj) | 0;
      hh = g; g = f; f = e; e = (d + t1) | 0; d = c; c = bb; bb = a; a = (t1 + t2) | 0;
    }
    h[0] += a; h[1] += bb; h[2] += c; h[3] += d; h[4] += e; h[5] += f; h[6] += g; h[7] += hh;
  }

  protected output(): Uint8Array {
    const out = new Uint8Array(32);
    const dv = new DataView(out.buffer);
    for (let i = 0; i < 8; i++) dv.setUint32(4 * i, this.h[i]);
    return out;
  }
}

// ---- SHA-1 ---------------------------------------------------------------

/** Incremental SHA-1. */
export class Sha1Hasher extends BlockHasher {
  protected readonly bigEndian = true;
  private readonly h = new Uint32Array([0x67452301, 0xefcdab89, 0x98badcfe, 0x10325476, 0xc3d2e1f0]);
  private readonly w = new Uint32Array(80);

  protected compress(b: Uint8Array, o: number): void {
    const w = this.w;
    for (let i = 0; i < 16; i++) {
      const j = o + 4 * i;
      w[i] = ((b[j] << 24) | (b[j + 1] << 16) | (b[j + 2] << 8) | b[j + 3]) >>> 0;
    }
    for (let i = 16; i < 80; i++) w[i] = rotl(w[i - 3] ^ w[i - 8] ^ w[i - 14] ^ w[i - 16], 1);
    const h = this.h;
    let a = h[0], bb = h[1], c = h[2], d = h[3], e = h[4];
    for (let i = 0; i < 80; i++) {
      let f: number, k: number;
      if (i < 20) { f = (bb & c) | (~bb & d); k = 0x5a827999; }
      else if (i < 40) { f = bb ^ c ^ d; k = 0x6ed9eba1; }
      else if (i < 60) { f = (bb & c) | (bb & d) | (c & d); k = 0x8f1bbcdc; }
      else { f = bb ^ c ^ d; k = 0xca62c1d6; }
      const t = (rotl(a, 5) + f + e + k + w[i]) | 0;
      e = d; d = c; c = rotl(bb, 30); bb = a; a = t;
    }
    h[0] += a; h[1] += bb; h[2] += c; h[3] += d; h[4] += e;
  }

  protected output(): Uint8Array {
    const out = new Uint8Array(20);
    const dv = new DataView(out.buffer);
    for (let i = 0; i < 5; i++) dv.setUint32(4 * i, this.h[i]);
    return out;
  }
}

// ---- RIPEMD-160 ----------------------------------------------------------

const RMD_R1 = [
  0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15,
  7, 4, 13, 1, 10, 6, 15, 3, 12, 0, 9, 5, 2, 14, 11, 8,
  3, 10, 14, 4, 9, 15, 8, 1, 2, 7, 0, 6, 13, 11, 5, 12,
  1, 9, 11, 10, 0, 8, 12, 4, 13, 3, 7, 15, 14, 5, 6, 2,
  4, 0, 5, 9, 7, 12, 2, 10, 14, 1, 3, 8, 11, 6, 15, 13,
];
const RMD_R2 = [
  5, 14, 7, 0, 9, 2, 11, 4, 13, 6, 15, 8, 1, 10, 3, 12,
  6, 11, 3, 7, 0, 13, 5, 10, 14, 15, 8, 12, 4, 9, 1, 2,
  15, 5, 1, 3, 7, 14, 6, 9, 11, 8, 12, 2, 10, 0, 4, 13,
  8, 6, 4, 1, 3, 11, 15, 0, 5, 12, 2, 13, 9, 7, 10, 14,
  12, 15, 10, 4, 1, 5, 8, 7, 6, 2, 13, 14, 0, 3, 9, 11,
];
const RMD_S1 = [
  11, 14, 15, 12, 5, 8, 7, 9, 11, 13, 14, 15, 6, 7, 9, 8,
  7, 6, 8, 13, 11, 9, 7, 15, 7, 12, 15, 9, 11, 7, 13, 12,
  11, 13, 6, 7, 14, 9, 13, 15, 14, 8, 13, 6, 5, 12, 7, 5,
  11, 12, 14, 15, 14, 15, 9, 8, 9, 14, 5, 6, 8, 6, 5, 12,
  9, 15, 5, 11, 6, 8, 13, 12, 5, 12, 13, 14, 11, 8, 5, 6,
];
const RMD_S2 = [
  8, 9, 9, 11, 13, 15, 15, 5, 7, 7, 8, 11, 14, 14, 12, 6,
  9, 13, 15, 7, 12, 8, 9, 11, 7, 7, 12, 7, 6, 15, 13, 11,
  9, 7, 15, 11, 8, 6, 6, 14, 12, 13, 5, 14, 13, 13, 7, 5,
  15, 5, 8, 11, 14, 14, 6, 14, 6, 9, 12, 9, 12, 5, 15, 8,
  8, 5, 12, 9, 12, 5, 14, 6, 8, 13, 6, 5, 15, 13, 11, 11,
];
const RMD_K1 = [0x00000000, 0x5a827999, 0x6ed9eba1, 0x8f1bbcdc, 0xa953fd4e];
const RMD_K2 = [0x50a28be6, 0x5c4dd124, 0x6d703ef3, 0x7a6d76e9, 0x00000000];

function rmdF(j: number, x: number, y: number, z: number): number {
  switch (j) {
    case 0: return x ^ y ^ z;
    case 1: return (x & y) | (~x & z);
    case 2: return (x | ~y) ^ z;
    case 3: return (x & z) | (y & ~z);
    default: return x ^ (y | ~z);
  }
}

class Ripemd160Hasher extends BlockHasher {
  protected readonly bigEndian = false;
  private readonly h = new Uint32Array([0x67452301, 0xefcdab89, 0x98badcfe, 0x10325476, 0xc3d2e1f0]);
  private readonly x = new Uint32Array(16);

  protected compress(b: Uint8Array, o: number): void {
    const x = this.x;
    for (let i = 0; i < 16; i++) {
      const j = o + 4 * i;
      x[i] = ((b[j + 3] << 24) | (b[j + 2] << 16) | (b[j + 1] << 8) | b[j]) >>> 0;
    }
    const h = this.h;
    let a1 = h[0], b1 = h[1], c1 = h[2], d1 = h[3], e1 = h[4];
    let a2 = a1, b2 = b1, c2 = c1, d2 = d1, e2 = e1;
    for (let j = 0; j < 80; j++) {
      const round = j >> 4;
      let t = (rotl((a1 + rmdF(round, b1, c1, d1) + x[RMD_R1[j]] + RMD_K1[round]) | 0, RMD_S1[j]) + e1) | 0;
      a1 = e1; e1 = d1; d1 = rotl(c1, 10); c1 = b1; b1 = t;
      t = (rotl((a2 + rmdF(4 - round, b2, c2, d2) + x[RMD_R2[j]] + RMD_K2[round]) | 0, RMD_S2[j]) + e2) | 0;
      a2 = e2; e2 = d2; d2 = rotl(c2, 10); c2 = b2; b2 = t;
    }
    const t = (h[1] + c1 + d2) | 0;
    h[1] = (h[2] + d1 + e2) | 0;
    h[2] = (h[3] + e1 + a2) | 0;
    h[3] = (h[4] + a1 + b2) | 0;
    h[4] = (h[0] + b1 + c2) | 0;
    h[0] = t;
  }

  protected output(): Uint8Array {
    const out = new Uint8Array(20);
    const dv = new DataView(out.buffer);
    for (let i = 0; i < 5; i++) dv.setUint32(4 * i, this.h[i], true);
    return out;
  }
}

// ---- Keccak-256 (BigInt lanes; messages in a proof are at most 4096 bytes) ----

const M64 = (1n << 64n) - 1n;
const KECCAK_RC: bigint[] = [];
const KECCAK_ROT: number[] = new Array(25).fill(0);
(() => {
  const lfsr = (t: number): number => {
    if (t % 255 === 0) return 1;
    let r = 1;
    for (let i = 1; i <= t % 255; i++) {
      r <<= 1;
      if (r & 0x100) r ^= 0x171;
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
    KECCAK_ROT[x + 5 * y] = (((t + 1) * (t + 2)) / 2) % 64;
    const nx = y;
    y = (2 * x + 3 * y) % 5;
    x = nx;
  }
})();

const rol64 = (v: bigint, n: number): bigint => (n === 0 ? v : ((v << BigInt(n)) | (v >> BigInt(64 - n))) & M64);

function keccakF(s: bigint[]): void {
  const c: bigint[] = new Array(5);
  const b: bigint[] = new Array(25);
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
      for (let x = 0; x < 5; x++) s[x + y] = b[x + y] ^ (~b[((x + 1) % 5) + y] & M64 & b[((x + 2) % 5) + y]);
    }
    s[0] ^= KECCAK_RC[round];
  }
}

export function keccak256(data: Uint8Array): Uint8Array {
  const rate = 136;
  const padded = new Uint8Array(Math.floor(data.length / rate) * rate + rate);
  padded.set(data);
  padded[data.length] ^= 0x01;
  padded[padded.length - 1] ^= 0x80;
  const s: bigint[] = new Array(25).fill(0n);
  for (let off = 0; off < padded.length; off += rate) {
    for (let i = 0; i < rate / 8; i++) {
      let lane = 0n;
      for (let k = 7; k >= 0; k--) lane = (lane << 8n) | BigInt(padded[off + 8 * i + k]);
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

// ---- one-shot helpers ------------------------------------------------------

export function sha256(data: Uint8Array): Uint8Array {
  return new Sha256Hasher().update(data).digest();
}
export function sha1(data: Uint8Array): Uint8Array {
  return new Sha1Hasher().update(data).digest();
}
export function ripemd160(data: Uint8Array): Uint8Array {
  return new Ripemd160Hasher().update(data).digest();
}

export function hashBytes(alg: HashAlg, data: Uint8Array): Uint8Array {
  switch (alg) {
    case "sha256": return sha256(data);
    case "sha1": return sha1(data);
    case "ripemd160": return ripemd160(data);
    case "keccak256": return keccak256(data);
  }
}

export interface StreamingHasher {
  update(chunk: Uint8Array): StreamingHasher;
  digest(): Uint8Array;
}

/** Incremental hasher for the algorithms a browser may be asked to apply to a big file. */
export function createStreamingHasher(alg: "sha256" | "sha1"): StreamingHasher {
  return alg === "sha256" ? new Sha256Hasher() : new Sha1Hasher();
}

/** Anything with a size and slice().arrayBuffer(): Blob, File. */
export interface BlobLike {
  readonly size: number;
  slice(start: number, end: number): { arrayBuffer(): Promise<ArrayBuffer> };
}

export const FILE_CHUNK = 4 * 1024 * 1024;

/** Hash a Blob/File in 4 MiB chunks; works in browsers (no stream API needed). */
export async function hashBlob(
  blob: BlobLike,
  alg: "sha256" | "sha1",
  onProgress?: (done: number, total: number) => void,
  chunkSize: number = FILE_CHUNK,
): Promise<Uint8Array> {
  const h = createStreamingHasher(alg);
  for (let i = 0; i < blob.size; i += chunkSize) {
    const buf = await blob.slice(i, Math.min(i + chunkSize, blob.size)).arrayBuffer();
    h.update(new Uint8Array(buf));
    if (onProgress) onProgress(Math.min(i + chunkSize, blob.size), blob.size);
  }
  return h.digest();
}

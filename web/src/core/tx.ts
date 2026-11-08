// Bitcoin transaction and header helpers: legacy parsing, witness stripping, script
// classification, sha256d, compact-size varints, nBits / proof-of-work check.

import { concat, indexOfBytes, reversed } from "./bytes.js";
import { sha256 } from "./hashes.js";

export function sha256d(b: Uint8Array): Uint8Array {
  return sha256(sha256(b));
}

/** Read a Bitcoin compact-size integer at `pos`. Null when truncated or beyond 2^32 (no real field is that long). */
export function readCompactSize(b: Uint8Array, pos: number): { value: number; next: number } | null {
  if (pos >= b.length) return null;
  const first = b[pos];
  if (first < 0xfd) return { value: first, next: pos + 1 };
  const dv = new DataView(b.buffer, b.byteOffset, b.byteLength);
  if (first === 0xfd) {
    if (pos + 3 > b.length) return null;
    return { value: dv.getUint16(pos + 1, true), next: pos + 3 };
  }
  if (first === 0xfe) {
    if (pos + 5 > b.length) return null;
    return { value: dv.getUint32(pos + 1, true), next: pos + 5 };
  }
  if (pos + 9 > b.length) return null;
  const lo = dv.getUint32(pos + 1, true);
  const hi = dv.getUint32(pos + 5, true);
  if (hi !== 0) return null;
  return { value: lo, next: pos + 9 };
}

export interface TxOutput {
  index: number;
  script: Uint8Array;
}

export interface LegacyTx {
  inputs: number;
  outputs: TxOutput[];
}

/**
 * Parse a legacy (non-witness) transaction that consumes exactly all of `b`.
 * version(4) inputs{hash32 vout4 varint script seq4} outputs{value8 varint script} locktime(4).
 * Input and output counts must be at least 1.
 */
export function parseLegacyTx(b: Uint8Array): LegacyTx | null {
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
  const outputs: TxOutput[] = [];
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

/**
 * Remove witness data. If the two bytes after the version are 00 01 (segwit marker and flag)
 * the transaction is parsed in witness form and returned in legacy form; null when that parse
 * fails. Otherwise the bytes are returned unchanged.
 */
export function stripWitness(b: Uint8Array): Uint8Array | null {
  if (!(b.length >= 6 && b[4] === 0x00 && b[5] === 0x01)) return b;
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

export type ScriptKind = "op_return" | "p2sh" | "p2pkh" | "other";

export function classifyScript(s: Uint8Array): ScriptKind {
  if (s.length > 0 && s[0] === 0x6a) return "op_return";
  if (s.length === 23 && s[0] === 0xa9 && s[1] === 0x14 && s[22] === 0x87) return "p2sh";
  if (s.length === 25 && s[0] === 0x76 && s[1] === 0xa9 && s[2] === 0x14 && s[23] === 0x88 && s[24] === 0xac) return "p2pkh";
  return "other";
}

/** The first output whose script contains `commitment` as a contiguous byte string. */
export function findCommitmentOutput(tx: LegacyTx, commitment: Uint8Array): { index: number; kind: ScriptKind; script: Uint8Array } | null {
  for (const o of tx.outputs) {
    if (indexOfBytes(o.script, commitment) >= 0) return { index: o.index, kind: classifyScript(o.script), script: o.script };
  }
  return null;
}

// ---- block header ------------------------------------------------------------

export interface Header {
  merkleRoot: Uint8Array; // bytes 36..68, internal order
  time: number; // bytes 68..72 LE
  bits: number; // bytes 72..76 LE
}

export function parseHeader(h: Uint8Array): Header {
  const dv = new DataView(h.buffer, h.byteOffset, h.byteLength);
  return { merkleRoot: h.subarray(36, 68), time: dv.getUint32(68, true), bits: dv.getUint32(72, true) };
}

/** Target of a compact nBits value, or null when it is negative, zero, or overflows 256 bits. */
export function bitsToTarget(bits: number): bigint | null {
  const exp = bits >>> 24;
  const mant = bits & 0x007fffff;
  if (mant === 0) return null;
  if (bits & 0x00800000) return null;
  if (exp > 32 || (mant > 0xff && exp > 33) || (mant > 0xffff && exp > 34)) return null;
  return exp <= 3 ? BigInt(mant >> (8 * (3 - exp))) : BigInt(mant) << BigInt(8 * (exp - 3));
}

function leToBigInt(b: Uint8Array): bigint {
  let v = 0n;
  for (let i = b.length - 1; i >= 0; i--) v = (v << 8n) | BigInt(b[i]);
  return v;
}

/** Block hash in display order (reversed sha256d of the 80-byte header). */
export function blockHashOf(header: Uint8Array): Uint8Array {
  return reversed(sha256d(header));
}

/** True when the header's hash is at or below the target of its own nBits. */
export function meetsPow(header: Uint8Array): boolean {
  const target = bitsToTarget(parseHeader(header).bits);
  if (target === null) return false;
  return leToBigInt(sha256d(header)) <= target;
}

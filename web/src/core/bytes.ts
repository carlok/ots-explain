// Byte helpers: hex, base64url, concatenation. No DOM, no Node-only APIs.

const HEX = "0123456789abcdef";
const HEX_TABLE: string[] = [];
for (let i = 0; i < 256; i++) HEX_TABLE.push(HEX[i >> 4] + HEX[i & 15]);

/** Lower-case hex of a byte array. */
export function hex(b: Uint8Array): string {
  let s = "";
  for (let i = 0; i < b.length; i++) s += HEX_TABLE[b[i]];
  return s;
}

function nibble(c: number): number {
  if (c >= 48 && c <= 57) return c - 48;
  if (c >= 97 && c <= 102) return c - 87;
  if (c >= 65 && c <= 70) return c - 55;
  return -1;
}

/** True when `s` is non-empty, of even length, and only 0-9a-fA-F. */
export function isHex(s: string): boolean {
  if (s.length === 0 || s.length % 2 !== 0) return false;
  for (let i = 0; i < s.length; i++) if (nibble(s.charCodeAt(i)) < 0) return false;
  return true;
}

/** Strict hex decoding; null when not hex (empty, odd length, bad character). */
export function fromHex(s: string): Uint8Array | null {
  if (!isHex(s)) return null;
  const out = new Uint8Array(s.length / 2);
  for (let i = 0; i < out.length; i++) {
    out[i] = (nibble(s.charCodeAt(2 * i)) << 4) | nibble(s.charCodeAt(2 * i + 1));
  }
  return out;
}

export function concat(...parts: Uint8Array[]): Uint8Array {
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

export function equalBytes(a: Uint8Array, b: Uint8Array): boolean {
  if (a.length !== b.length) return false;
  for (let i = 0; i < a.length; i++) if (a[i] !== b[i]) return false;
  return true;
}

/** Index of the first occurrence of `needle` in `hay`, or -1. Empty needle never matches. */
export function indexOfBytes(hay: Uint8Array, needle: Uint8Array): number {
  const n = needle.length;
  if (n === 0 || n > hay.length) return -1;
  outer: for (let i = 0; i + n <= hay.length; i++) {
    for (let j = 0; j < n; j++) if (hay[i + j] !== needle[j]) continue outer;
    return i;
  }
  return -1;
}

export function reversed(b: Uint8Array): Uint8Array {
  const out = new Uint8Array(b.length);
  for (let i = 0; i < b.length; i++) out[i] = b[b.length - 1 - i];
  return out;
}

/** ASCII string to bytes (code units are truncated to 8 bits). */
export function asciiBytes(s: string): Uint8Array {
  const out = new Uint8Array(s.length);
  for (let i = 0; i < s.length; i++) out[i] = s.charCodeAt(i) & 0xff;
  return out;
}

const B64URL = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";

/** RFC 4648 section 5, no padding. */
export function base64urlEncode(b: Uint8Array): string {
  let s = "";
  let i = 0;
  for (; i + 2 < b.length; i += 3) {
    const v = (b[i] << 16) | (b[i + 1] << 8) | b[i + 2];
    s += B64URL[v >> 18] + B64URL[(v >> 12) & 63] + B64URL[(v >> 6) & 63] + B64URL[v & 63];
  }
  if (b.length - i === 1) {
    const v = b[i] << 16;
    s += B64URL[v >> 18] + B64URL[(v >> 12) & 63];
  } else if (b.length - i === 2) {
    const v = (b[i] << 16) | (b[i + 1] << 8);
    s += B64URL[v >> 18] + B64URL[(v >> 12) & 63] + B64URL[(v >> 6) & 63];
  }
  return s;
}

/** Strict unpadded base64url decoding; null on any irregularity (padding, bad character, bad length). */
export function base64urlDecode(s: string): Uint8Array | null {
  if (s.length % 4 === 1) return null;
  const vals: number[] = [];
  for (let i = 0; i < s.length; i++) {
    const k = B64URL.indexOf(s[i]);
    if (k < 0) return null;
    vals.push(k);
  }
  const out = new Uint8Array(Math.floor((s.length * 6) / 8));
  let o = 0;
  let i = 0;
  for (; i + 3 < vals.length; i += 4) {
    const v = (vals[i] << 18) | (vals[i + 1] << 12) | (vals[i + 2] << 6) | vals[i + 3];
    out[o++] = v >> 16;
    out[o++] = (v >> 8) & 255;
    out[o++] = v & 255;
  }
  const rest = vals.length - i;
  if (rest === 2) {
    const v = (vals[i] << 18) | (vals[i + 1] << 12);
    if ((v & 0xffff) !== 0) return null; // non-zero trailing bits
    out[o++] = v >> 16;
  } else if (rest === 3) {
    const v = (vals[i] << 18) | (vals[i + 1] << 12) | (vals[i + 2] << 6);
    if ((v & 0xff) !== 0) return null;
    out[o++] = v >> 16;
    out[o++] = (v >> 8) & 255;
  }
  return out;
}

// Permalink (SPEC section 9): BASE[?proof=URL][#h=HEX][&ots=B64]

import { base64urlDecode, base64urlEncode, fromHex, isHex } from "./bytes.js";

export interface PermalinkParts {
  proofUrl?: string | null;
  digestHex?: string | null;
  ots?: Uint8Array | null;
}

export interface DecodedPermalink {
  base: string;
  proofUrl: string | null;
  digestHex: string | null;
  ots: Uint8Array | null;
}

const UNRESERVED = /[A-Za-z0-9\-._~]/;

function percentEncode(s: string): string {
  let out = "";
  for (const b of new TextEncoder().encode(s)) {
    const ch = String.fromCharCode(b);
    out += b < 128 && UNRESERVED.test(ch) ? ch : "%" + (b < 16 ? "0" : "") + b.toString(16).toUpperCase();
  }
  return out;
}

function percentDecode(s: string): string | null {
  const bytes: number[] = [];
  for (let i = 0; i < s.length; i++) {
    const c = s[i];
    if (c === "%") {
      const v = fromHex(s.slice(i + 1, i + 3));
      if (v === null || s.length < i + 3) return null;
      bytes.push(v[0]);
      i += 2;
    } else {
      const code = s.charCodeAt(i);
      if (code > 127) { // already a non-ASCII character: keep its UTF-8 bytes
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

/** `base` must not itself carry a query or fragment. */
export function encodePermalink(base: string, parts: PermalinkParts = {}): string {
  let url = base;
  if (parts.proofUrl) url += "?proof=" + percentEncode(parts.proofUrl);
  const frag: string[] = [];
  if (parts.digestHex) frag.push("h=" + parts.digestHex.toLowerCase());
  if (parts.ots) frag.push("ots=" + base64urlEncode(parts.ots));
  if (frag.length > 0) url += "#" + frag.join("&");
  return url;
}

function firstParams(s: string): Map<string, string> {
  const m = new Map<string, string>();
  if (s === "") return m;
  for (const part of s.split("&")) {
    const eq = part.indexOf("=");
    if (eq < 0) continue;
    const k = part.slice(0, eq);
    if (!m.has(k)) m.set(k, part.slice(eq + 1));
  }
  return m;
}

/** Decode a full URL (or just its query/fragment). Unknown keys are ignored; keys are case-sensitive. */
export function decodePermalink(url: string): DecodedPermalink {
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
    proofUrl: proofRaw === undefined ? null : percentDecode(proofRaw),
    digestHex: hRaw !== undefined && isHex(hRaw) ? hRaw.toLowerCase() : null,
    ots: otsRaw === undefined ? null : base64urlDecode(otsRaw),
  };
}

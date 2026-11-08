// Canonical JSON (SPEC section 8): UTF-8, no whitespace, keys sorted by Unicode code point,
// integers only, strings escaped only as \" \\ \n \r \t and \u00xx for other control characters.

function cmpCodePoints(a: string, b: string): number {
  const ia = a[Symbol.iterator]();
  const ib = b[Symbol.iterator]();
  for (;;) {
    const x = ia.next();
    const y = ib.next();
    if (x.done && y.done) return 0;
    if (x.done) return -1;
    if (y.done) return 1;
    const cx = x.value.codePointAt(0)!;
    const cy = y.value.codePointAt(0)!;
    if (cx !== cy) return cx < cy ? -1 : 1;
  }
}

function quote(s: string): string {
  let out = '"';
  for (let i = 0; i < s.length; i++) {
    const c = s.charCodeAt(i);
    if (c === 0x22) out += '\\"';
    else if (c === 0x5c) out += "\\\\";
    else if (c === 0x0a) out += "\\n";
    else if (c === 0x0d) out += "\\r";
    else if (c === 0x09) out += "\\t";
    else if (c < 0x20) out += "\\u00" + (c < 16 ? "0" : "") + c.toString(16);
    else out += s[i];
  }
  return out + '"';
}

export function canonicalJson(v: unknown): string {
  if (v === null) return "null";
  switch (typeof v) {
    case "boolean": return v ? "true" : "false";
    case "number":
      if (!Number.isSafeInteger(v)) throw new Error("canonical JSON allows integers only: " + String(v));
      return String(v);
    case "string": return quote(v);
    case "object": {
      if (Array.isArray(v)) return "[" + v.map(canonicalJson).join(",") + "]";
      const o = v as Record<string, unknown>;
      const keys = Object.keys(o).sort(cmpCodePoints);
      return "{" + keys.map((k) => quote(k) + ":" + canonicalJson(o[k])).join(",") + "}";
    }
    default:
      throw new Error("not representable in canonical JSON: " + typeof v);
  }
}

/** The same document as UTF-8 bytes (no trailing newline). */
export function canonicalBytes(v: unknown): Uint8Array {
  return new TextEncoder().encode(canonicalJson(v));
}

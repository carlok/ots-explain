// Shared test helpers: (re)builds the core bundle once per process, and loads vectors.
import { readFileSync, existsSync, readdirSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

const here = dirname(fileURLToPath(import.meta.url));
export const ROOT = join(here, "..", "..");
export const VECTORS = join(ROOT, "vectors");

await import("../../web/build-core.mjs"); // rebuilds web/build/core.mjs (atomic write)
export const core = await import("../../web/build/core.mjs");

export const readBin = (...p) => new Uint8Array(readFileSync(join(VECTORS, ...p)));
export const readJson = (...p) => JSON.parse(readFileSync(join(VECTORS, ...p), "utf8"));
export const vectorIndex = () => readJson("index.json").vectors;
export const hasFile = (...p) => existsSync(join(VECTORS, ...p));
export const listDir = (...p) => readdirSync(join(VECTORS, ...p));

// ---- byte building helpers for handcrafted proofs ----
export const H = (s) => Uint8Array.from(Buffer.from(s.replace(/\s+/g, ""), "hex"));
export const cat = (...parts) => core.concat(...parts.map((p) => (typeof p === "string" ? H(p) : p)));
export const MAGIC_HEX = "004f70656e54696d657374616d7073000050726f6f6600bf89e2e884e89294";
export function varuint(n) {
  n = BigInt(n);
  const out = [];
  do {
    let b = Number(n & 0x7fn);
    n >>= 7n;
    if (n > 0n) b |= 0x80;
    out.push(b);
  } while (n > 0n);
  return Uint8Array.from(out);
}
export const varbytes = (b) => cat(varuint(b.length), b);
/** file header: magic, version, file hash op, digest */
export function hdr({ version = 1, op = 0x08, digest = new Uint8Array(32).fill(7) } = {}) {
  return cat(MAGIC_HEX, Uint8Array.of(version, op), digest);
}
export const append = (arg) => cat("f0", varbytes(arg));
export const prepend = (arg) => cat("f1", varbytes(arg));
export const att = (tagHex, payload) => cat("00", tagHex, varbytes(payload));
export const BTC = "0588960d73d71901";
export const LTC = "06869a0d73d71b45";
export const ETH = "30fe8087b5c7ead7";
export const PENDING = "83dfe30d2ef90c8e";
export const btc = (h) => att(BTC, varuint(h));
export const pending = (uri) => att(PENDING, varbytes(new TextEncoder().encode(uri)));
export const proofOf = (...body) => cat(hdr(), ...body);
export const parseCode = (bytes) => {
  const r = core.parseProof(bytes);
  return r.ok ? "ok" : r.code;
};

// ---- a tiny JSON-Schema subset validator (enough for spec/report.schema.json) ----
export function validateSchema(schema, value, path = "$") {
  const errs = [];
  const typeOf = (v) => (v === null ? "null" : Array.isArray(v) ? "array" : Number.isInteger(v) ? "integer" : typeof v);
  const isType = (t, v) => (t === "number" ? typeof v === "number" : t === "integer" ? Number.isInteger(v) : typeOf(v) === t);
  if (schema.const !== undefined && value !== schema.const) errs.push(`${path}: not const ${schema.const}`);
  if (schema.enum && !schema.enum.includes(value)) errs.push(`${path}: ${JSON.stringify(value)} not in enum`);
  if (schema.type) {
    const ts = Array.isArray(schema.type) ? schema.type : [schema.type];
    if (!ts.some((t) => isType(t, value))) errs.push(`${path}: type ${typeOf(value)} not in ${ts}`);
  }
  if (typeof value === "string" && schema.pattern && !new RegExp(schema.pattern).test(value)) errs.push(`${path}: pattern ${schema.pattern} fails for ${value.slice(0, 40)}`);
  if (typeof value === "number" && schema.minimum !== undefined && value < schema.minimum) errs.push(`${path}: below minimum`);
  if (Array.isArray(value)) {
    if (schema.minItems !== undefined && value.length < schema.minItems) errs.push(`${path}: too few items`);
    if (schema.maxItems !== undefined && value.length > schema.maxItems) errs.push(`${path}: too many items`);
    if (schema.items) value.forEach((v, i) => errs.push(...validateSchema(schema.items, v, `${path}[${i}]`)));
  }
  if (value !== null && typeof value === "object" && !Array.isArray(value)) {
    for (const k of schema.required ?? []) if (!(k in value)) errs.push(`${path}: missing ${k}`);
    for (const [k, v] of Object.entries(value)) {
      if (schema.properties && k in schema.properties) errs.push(...validateSchema(schema.properties[k], v, `${path}.${k}`));
      else if (schema.additionalProperties === false) errs.push(`${path}: unexpected key ${k}`);
    }
  }
  if (schema.oneOf) {
    const ok = schema.oneOf.filter((s) => validateSchema(s, value, path).length === 0).length;
    if (ok !== 1) errs.push(`${path}: oneOf matched ${ok}`);
  }
  return errs;
}
export const REPORT_SCHEMA = JSON.parse(readFileSync(join(ROOT, "spec", "report.schema.json"), "utf8"));
export const STEPS_JSON = JSON.parse(readFileSync(join(ROOT, "spec", "steps.json"), "utf8"));

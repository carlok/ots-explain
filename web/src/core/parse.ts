// The .ots parser (SPEC sections 3-5). Every message is computed while parsing because the
// limits depend on the results. Errors carry one code from SPEC section 4.

import { equalBytes, hex } from "./bytes.js";
import { keccak256, ripemd160, sha1, sha256 } from "./hashes.js";

export type ParseErrorCode =
  | "bad_magic" | "unsupported_version" | "unknown_file_hash_op" | "truncated" | "trailing_garbage"
  | "unknown_op" | "repeated_op" | "arg_length" | "msg_too_long" | "result_too_long" | "empty_message"
  | "varuint_too_long" | "payload_too_long" | "bad_attestation_payload" | "bad_uri" | "height_too_large"
  | "recursion_limit";

export class ParseError extends Error {
  constructor(readonly code: ParseErrorCode) {
    super(code);
    this.name = "ParseError";
  }
}

export type OpName = "append" | "prepend" | "sha256" | "sha1" | "ripemd160" | "keccak256" | "reverse" | "hexlify";
export type HashOpName = "sha256" | "sha1" | "ripemd160";
export type AttestationKind = "bitcoin" | "litecoin" | "ethereum" | "pending" | "unknown";

export interface TreeNode {
  id: number;
  parent: number; // -1 for the root
  op: OpName | null;
  arg: Uint8Array | null;
  msg: Uint8Array; // the message at this node (the digest column of the report)
  depth: number; // number of ops on the path from the root
}

export interface ProofAttestation {
  index: number;
  node: number;
  kind: AttestationKind;
  height: number | null;
  uri: string | null;
  tag: Uint8Array;
  payload: Uint8Array;
}

export interface ParsedProof {
  size: number;
  version: 1;
  hashOp: HashOpName;
  digest: Uint8Array;
  nodes: TreeNode[];
  attestations: ProofAttestation[];
  maxDepth: number;
}

export type ParseResult = { ok: true; proof: ParsedProof } | { ok: false; code: ParseErrorCode };

export const MAGIC = new Uint8Array([
  0x00, 0x4f, 0x70, 0x65, 0x6e, 0x54, 0x69, 0x6d, 0x65, 0x73, 0x74, 0x61, 0x6d, 0x70, 0x73, 0x00,
  0x00, 0x50, 0x72, 0x6f, 0x6f, 0x66, 0x00, 0xbf, 0x89, 0xe2, 0xe8, 0x84, 0xe8, 0x92, 0x94,
]);

export const LIMITS = {
  maxArg: 4096,
  maxResult: 4096,
  maxMsg: 4096,
  maxHexlifyMsg: 2048,
  maxPayload: 8192,
  maxUri: 1000,
  maxVaruintBytes: 9,
  maxHeight: 4294967295n,
  recursion: 256,
} as const;

const TAGS: Record<string, AttestationKind> = {
  "0588960d73d71901": "bitcoin",
  "06869a0d73d71b45": "litecoin",
  "30fe8087b5c7ead7": "ethereum",
  "83dfe30d2ef90c8e": "pending",
};

const HASH_OPS: Record<number, HashOpName> = { 0x02: "sha1", 0x03: "ripemd160", 0x08: "sha256" };
const HASH_LEN: Record<HashOpName, number> = { sha1: 20, ripemd160: 20, sha256: 32 };

const OP_BY_TAG: Record<number, OpName> = {
  0xf0: "append", 0xf1: "prepend", 0x08: "sha256", 0x02: "sha1", 0x03: "ripemd160",
  0x67: "keccak256", 0xf2: "reverse", 0xf3: "hexlify",
};

class Reader {
  pos = 0;
  constructor(
    readonly b: Uint8Array,
    readonly onShort: ParseErrorCode = "truncated",
    readonly onLong: ParseErrorCode = "varuint_too_long",
  ) {}

  get left(): number {
    return this.b.length - this.pos;
  }

  u8(): number {
    if (this.pos >= this.b.length) throw new ParseError(this.onShort);
    return this.b[this.pos++];
  }

  take(n: number): Uint8Array {
    if (n > this.left) throw new ParseError(this.onShort);
    const out = this.b.subarray(this.pos, this.pos + n);
    this.pos += n;
    return out;
  }

  /** LEB128, at most 9 bytes (63 bits). */
  varuint(): bigint {
    let value = 0n;
    let shift = 0n;
    for (let i = 0; i < LIMITS.maxVaruintBytes; i++) {
      const byte = this.u8();
      value |= BigInt(byte & 0x7f) << shift;
      if ((byte & 0x80) === 0) return value;
      shift += 7n;
    }
    throw new ParseError(this.onLong);
  }

  /** varuint length, then bytes. `tooLong` is the code for length > max (or < min). */
  varbytes(max: number, min: number, tooLong: ParseErrorCode): Uint8Array {
    const l = this.varuint();
    if (l > BigInt(max) || l < BigInt(min)) throw new ParseError(tooLong);
    return this.take(Number(l));
  }
}

function applyOp(op: OpName, arg: Uint8Array | null, msg: Uint8Array): Uint8Array {
  const maxMsg = op === "hexlify" ? LIMITS.maxHexlifyMsg : LIMITS.maxMsg;
  if (msg.length > maxMsg) throw new ParseError("msg_too_long");
  let r: Uint8Array;
  switch (op) {
    case "append": {
      r = new Uint8Array(msg.length + arg!.length);
      r.set(msg);
      r.set(arg!, msg.length);
      break;
    }
    case "prepend": {
      r = new Uint8Array(msg.length + arg!.length);
      r.set(arg!);
      r.set(msg, arg!.length);
      break;
    }
    case "sha256": r = sha256(msg); break;
    case "sha1": r = sha1(msg); break;
    case "ripemd160": r = ripemd160(msg); break;
    case "keccak256": r = keccak256(msg); break;
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

function parseAttestationPayload(kind: AttestationKind, payload: Uint8Array): { height: number | null; uri: string | null } {
  const r = new Reader(payload, "bad_attestation_payload", "bad_attestation_payload");
  let height: number | null = null;
  let uri: string | null = null;
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
      const ok = (c >= 0x41 && c <= 0x5a) || (c >= 0x61 && c <= 0x7a) || (c >= 0x30 && c <= 0x39) ||
        c === 0x2d || c === 0x2e || c === 0x5f || c === 0x2f || c === 0x3a;
      if (!ok) throw new ParseError("bad_uri");
      s += String.fromCharCode(c);
    }
    uri = s;
  }
  if (kind !== "unknown" && r.left !== 0) throw new ParseError("bad_attestation_payload");
  return { height, uri };
}

export function parseProof(bytes: Uint8Array): ParseResult {
  try {
    return { ok: true, proof: parseOrThrow(bytes) };
  } catch (e) {
    if (e instanceof ParseError) return { ok: false, code: e.code };
    throw e;
  }
}

function parseOrThrow(bytes: Uint8Array): ParsedProof {
  const r = new Reader(bytes);
  // the reference reads len(MAGIC) bytes and compares: a short file is a bad magic, not a truncation
  const magic = bytes.subarray(0, MAGIC.length);
  if (!equalBytes(magic, MAGIC)) throw new ParseError("bad_magic");
  r.pos = MAGIC.length;
  if (r.u8() !== 1) throw new ParseError("unsupported_version");
  const hashOp = HASH_OPS[r.u8()];
  if (hashOp === undefined) throw new ParseError("unknown_file_hash_op");
  const digest = r.take(HASH_LEN[hashOp]);
  return parseTree(r, digest, hashOp, bytes.length);
}

/** SPEC 12.5: a bare timestamp over `msg` (any length a node may have), read exactly like the tree of a proof. */
export function parseFragmentTree(msg: Uint8Array, body: Uint8Array): ParsedProof {
  if (msg.length < 1 || msg.length > LIMITS.maxMsg) throw new ParseError("arg_length");
  return parseTree(new Reader(body), msg, "sha256", body.length);
}

function parseTree(r: Reader, digest: Uint8Array, hashOp: HashOpName, size: number): ParsedProof {
  const nodes: TreeNode[] = [{ id: 0, parent: -1, op: null, arg: null, msg: digest, depth: 0 }];
  const attestations: ProofAttestation[] = [];
  let maxDepth = 0;

  const readTimestamp = (nodeId: number, msg: Uint8Array, limit: number, depth: number): void => {
    if (limit === 0) throw new ParseError("recursion_limit");
    const seen = new Set<string>();
    const entry = (tag: number): void => {
      if (tag === 0x00) {
        const attTag = r.take(8);
        const payload = r.varbytes(LIMITS.maxPayload, 0, "payload_too_long");
        const kind = TAGS[hex(attTag)] ?? "unknown";
        const { height, uri } = parseAttestationPayload(kind, payload);
        attestations.push({ index: attestations.length, node: nodeId, kind, height, uri, tag: attTag, payload });
        return;
      }
      const op = OP_BY_TAG[tag];
      if (op === undefined) throw new ParseError("unknown_op");
      let arg: Uint8Array | null = null;
      if (op === "append" || op === "prepend") arg = r.varbytes(LIMITS.maxArg, 1, "arg_length");
      const key = tag.toString(16) + ":" + (arg ? hex(arg) : "");
      if (seen.has(key)) throw new ParseError("repeated_op");
      seen.add(key);
      const result = applyOp(op, arg, msg);
      const child: TreeNode = { id: nodes.length, parent: nodeId, op, arg, msg: result, depth: depth + 1 };
      nodes.push(child);
      if (child.depth > maxDepth) maxDepth = child.depth;
      readTimestamp(child.id, result, limit - 1, depth + 1);
    };
    let tag = r.u8();
    while (tag === 0xff) {
      entry(r.u8());
      tag = r.u8();
    }
    entry(tag);
  };

  readTimestamp(0, digest, LIMITS.recursion, 0);
  if (r.left !== 0) throw new ParseError("trailing_garbage");
  return { size, version: 1, hashOp, digest, nodes, attestations, maxDepth };
}

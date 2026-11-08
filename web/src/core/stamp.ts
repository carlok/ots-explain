// Stamping and upgrading (SPEC section 12). The network is an injected function; nothing here
// touches the platform except through `call`. Reuses the section-3 parser for calendar answers.

import { concat, equalBytes, hex } from "./bytes.js";
import { sha256 } from "./hashes.js";
import { MAGIC, ParseError, parseFragmentTree, parseProof } from "./parse.js";
import type { HashOpName, OpName, ParsedProof } from "./parse.js";

// ---------------------------------------------------------------- 12.1 constants

const MAX_CALENDAR_RESPONSE = 10000;

export const DEFAULT_CALENDARS: string[] = [
  "https://alice.btc.calendar.opentimestamps.org",
  "https://bob.btc.calendar.opentimestamps.org",
  "https://finney.calendar.eternitywall.com",
];

export const KNOWN_CALENDARS: string[] = [
  ...DEFAULT_CALENDARS,
  "https://btc.calendar.catallaxy.com",
  "https://ots.btc.catallaxy.com",
];

/** (url, body?) -> status and body. A body present means POST, absent means GET. Failures reject. */
export type CalendarCall = (url: string, body?: Uint8Array) => Promise<{ status: number; body: Uint8Array }>;

function stripSlashes(s: string): string {
  let n = s.length;
  while (n > 0 && s.charCodeAt(n - 1) === 0x2f) n--;
  return s.slice(0, n);
}

/** base with trailing "/" removed, then "/", then path. */
function join(base: string, path: string): string {
  return stripSlashes(base) + "/" + path;
}

/** A calendar failed to give a usable answer; the message is the reason for the log line. */
class Failure extends Error {}

function messageOf(e: unknown): string {
  return e instanceof Error ? e.message : String(e);
}

// ---------------------------------------------------------------- 12.2 commitment

/** c = SHA-256(digest || nonce): the only value sent to a calendar. */
export function commitmentFor(digest: Uint8Array, nonce: Uint8Array): Uint8Array {
  return sha256(concat(digest, nonce));
}

// ---------------------------------------------------------------- tree model

interface TAtt {
  kind: string;
  height: number | null;
  uri: string | null;
  tag: Uint8Array;
  payload: Uint8Array;
}
interface TEdge {
  op: OpName;
  arg: Uint8Array | null;
  child: TNode;
}
interface TNode {
  msg: Uint8Array;
  atts: TAtt[];
  edges: TEdge[];
}

const OP_BYTE: Record<OpName, number> = {
  append: 0xf0, prepend: 0xf1, sha256: 0x08, sha1: 0x02, ripemd160: 0x03, keccak256: 0x67, reverse: 0xf2, hexlify: 0xf3,
};
const HASH_OP_BYTE: Record<HashOpName, number> = { sha256: 0x08, sha1: 0x02, ripemd160: 0x03 };

function toTree(p: ParsedProof): TNode {
  const nodes: TNode[] = p.nodes.map((n) => ({ msg: n.msg, atts: [], edges: [] }));
  for (const n of p.nodes) {
    if (n.parent >= 0) nodes[n.parent].edges.push({ op: n.op!, arg: n.arg ? n.arg.slice() : null, child: nodes[n.id] });
  }
  for (const a of p.attestations) {
    nodes[a.node].atts.push({
      kind: a.kind, height: a.height, uri: a.uri, tag: a.tag.slice(), payload: a.payload.slice(),
    });
  }
  return nodes[0];
}

/** SPEC 12.5: a bare timestamp over `msg`, parsed as section 3 parses a proof's tree. */
function parseFragment(msg: Uint8Array, body: Uint8Array): { root: TNode; proof: ParsedProof } {
  if (body.length > MAX_CALENDAR_RESPONSE) throw new ParseError("payload_too_long");
  const proof = parseFragmentTree(msg, body);
  return { root: toTree(proof), proof };
}

function sameArg(a: Uint8Array | null, b: Uint8Array | null): boolean {
  if (a === null || b === null) return a === b;
  return equalBytes(a, b);
}

function cloneNode(n: TNode): TNode {
  return {
    msg: n.msg,
    atts: n.atts.map((a) => ({ ...a, tag: a.tag.slice(), payload: a.payload.slice() })),
    edges: n.edges.map((e) => ({ op: e.op, arg: e.arg ? e.arg.slice() : null, child: cloneNode(e.child) })),
  };
}

/** SPEC 12.4. */
function merge(into: TNode, frag: TNode): void {
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

// ---------------------------------------------------------------- 12.6 serialization

function varuint(n: number): Uint8Array {
  const out: number[] = [];
  let v = n;
  do {
    let b = v % 128;
    v = Math.floor(v / 128);
    if (v > 0) b |= 0x80;
    out.push(b);
  } while (v > 0);
  return Uint8Array.from(out);
}

function varbytes(b: Uint8Array): Uint8Array {
  return concat(varuint(b.length), b);
}

function cmpBytes(a: Uint8Array, b: Uint8Array): number {
  const n = Math.min(a.length, b.length);
  for (let i = 0; i < n; i++) if (a[i] !== b[i]) return a[i] - b[i];
  return a.length - b.length;
}

function attSecondary(a: TAtt): Uint8Array {
  if (a.uri !== null) return Uint8Array.from(a.uri, (c) => c.charCodeAt(0) & 0xff);
  return a.payload;
}

function cmpAtt(a: TAtt, b: TAtt): number {
  return cmpBytes(a.tag, b.tag) || (a.height ?? 0) - (b.height ?? 0) || cmpBytes(attSecondary(a), attSecondary(b));
}

function cmpEdge(a: TEdge, b: TEdge): number {
  return OP_BYTE[a.op] - OP_BYTE[b.op] || cmpBytes(a.arg ?? new Uint8Array(0), b.arg ?? new Uint8Array(0));
}

function writeNode(n: TNode, out: Uint8Array[]): void {
  if (n.atts.length + n.edges.length === 0) throw new Error("a timestamp node has no entries");
  const atts = n.atts.slice().sort(cmpAtt); // Array.prototype.sort is stable
  const edges = n.edges.slice().sort(cmpEdge);
  let left = atts.length + edges.length;
  // every entry but the last is preceded by 0xff
  const lead = (): void => {
    if (--left > 0) out.push(Uint8Array.of(0xff));
  };
  for (const a of atts) {
    lead();
    out.push(Uint8Array.of(0x00), a.tag, varbytes(a.payload));
  }
  for (const e of edges) {
    lead();
    out.push(Uint8Array.of(OP_BYTE[e.op]));
    if (e.op === "append" || e.op === "prepend") out.push(varbytes(e.arg!));
    writeNode(e.child, out);
  }
}

function serialize(hashOp: HashOpName, digest: Uint8Array, root: TNode): Uint8Array {
  const out: Uint8Array[] = [MAGIC, Uint8Array.of(0x01, HASH_OP_BYTE[hashOp]), digest];
  writeNode(root, out);
  return concat(...out);
}

// ---------------------------------------------------------------- 12.3 stamp

export async function stampDigest(
  digest: Uint8Array,
  calendars: string[],
  call: CalendarCall,
  nonce: Uint8Array,
  log: (line: string) => void,
): Promise<Uint8Array> {
  if (digest.length !== 32) throw new Error("the digest must be 32 bytes");
  if (nonce.length !== 16) throw new Error("the nonce must be 16 bytes");
  const m1 = concat(digest, nonce);
  const c = sha256(m1);
  const tip: TNode = { msg: c, atts: [], edges: [] };
  const root: TNode = {
    msg: digest, atts: [],
    edges: [{ op: "append", arg: nonce.slice(), child: { msg: m1, atts: [], edges: [{ op: "sha256", arg: null, child: tip }] } }],
  };
  let accepted = 0;
  for (const cal of calendars) {
    let frag: TNode;
    try {
      let res: { status: number; body: Uint8Array };
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

// ---------------------------------------------------------------- 12.7 upgrade

export async function upgradeProof(
  proof: Uint8Array,
  call: CalendarCall,
  allowed: string[],
  log: (line: string) => void,
): Promise<{ bytes: Uint8Array; changed: boolean; status: string }> {
  const parsed = parseProof(proof);
  if (!parsed.ok) throw new ParseError(parsed.code);
  const p = parsed.proof;

  const hasBitcoin = p.attestations.some((a) => a.kind === "bitcoin");
  const hasPending = p.attestations.some((a) => a.kind === "pending");
  if (hasBitcoin && !hasPending) return { bytes: proof, changed: false, status: "nothing_to_do" };

  const root = toTree(p);
  // pending attestations in tree order: depth first, a node's own attestations, then its children in creation order
  const todo: { node: TNode; uri: string }[] = [];
  const walk = (n: TNode): void => {
    for (const a of n.atts) if (a.kind === "pending") todo.push({ node: n, uri: a.uri! });
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
    let res: { status: number; body: Uint8Array };
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
    let frag: { root: TNode; proof: ParsedProof };
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

// Assembles the whole report (SPEC sections 2, 8, 11).

import { hex, isHex } from "./bytes.js";
import { runLedger, ledgerOutcome, type FetchText, type Ledger, type Server, type Status } from "./ledger.js";
import { parseProof, type ParsedProof, type ParseErrorCode, type HashOpName } from "./parse.js";
import { computePhases, type Phases } from "./phases.js";

export const REPORT_SPEC = "ots-explain-report/1";

export const STEP_TITLES = {
  file_hash: "File to hash",
  structure: "Proof structure",
  hash_steps: "Hash steps",
  ledger: "The ledger",
  verdict: "Verdict",
} as const;

export interface FileInput {
  size: number;
  /** Called at most once, only when the proof parsed and its header algorithm is sha256 or sha1. */
  digest: (alg: "sha256" | "sha1") => Promise<Uint8Array> | Uint8Array;
}

export interface BuildOptions {
  proof: Uint8Array | null;
  file?: FileInput | null;
  digestHex?: string | null;
  ledger?: { servers?: Server[] | null; fetchText: FetchText } | null;
}

export interface StepEntry {
  id: keyof typeof STEP_TITLES;
  title: string;
  status: Status;
  code: string;
}

export interface WhereToLook {
  kind: "block" | "tx" | "raw_hex";
  server: string;
  url: string;
}

export interface ReportAttestation {
  index: number;
  node: number;
  kind: string;
  height: number | null;
  uri: string | null;
  tag: string;
  payload: string;
  phases: Phases | null;
  where_to_look: WhereToLook[];
}

export interface ReportProof {
  size: number;
  version: 1;
  hash_op: HashOpName;
  digest: string;
  nodes: number;
  ops: number;
  max_depth: number;
  tree: { id: number; parent: number; op: string | null; arg: string | null; digest: string }[];
  attestations: ReportAttestation[];
}

export interface Report {
  spec: typeof REPORT_SPEC;
  input: { mode: "file" | "digest" | "none"; size: number | null; digest: string | null; digest_alg: HashOpName | null };
  error: { code: ParseErrorCode } | null;
  proof: ReportProof | null;
  steps: StepEntry[];
  ledger: Ledger | null;
  verdict: { status: Status; code: "proved" | "failed" | "incomplete"; block: number | null; time: number | null; unverified: number[] };
}

function whereToLook(height: number, txid: string): WhereToLook[] {
  const out: WhereToLook[] = [];
  const sites: [string, string][] = [["blockstream.info", "https://blockstream.info"], ["mempool.space", "https://mempool.space"]];
  for (const [server, site] of sites) {
    out.push({ kind: "block", server, url: server === "blockstream.info" ? `${site}/block-height/${height}` : `${site}/block/${height}` });
    out.push({ kind: "tx", server, url: `${site}/tx/${txid}` });
    out.push({ kind: "raw_hex", server, url: `${site}/api/tx/${txid}/hex` });
  }
  return out;
}

function reportProof(p: ParsedProof): ReportProof {
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
      digest: hex(n.msg),
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
        where_to_look: phases === null || a.height === null ? [] : whereToLook(a.height, phases.txid),
      };
    }),
  };
}

export async function buildReport(opts: BuildOptions): Promise<Report> {
  const parsed = parseProof(opts.proof ?? new Uint8Array(0));
  const mode: Report["input"]["mode"] = opts.file ? "file" : opts.digestHex !== undefined && opts.digestHex !== null ? "digest" : "none";

  // ---- step 1 ----
  let inSize: number | null = null;
  let inDigest: string | null = null;
  let s1: { status: Status; code: string };
  if (mode === "file") inSize = opts.file!.size;
  if (mode === "digest" && isHex(opts.digestHex!)) inDigest = opts.digestHex!.toLowerCase();

  if (!parsed.ok) {
    s1 = { status: "SKIP", code: "no_proof" };
  } else if (mode === "none") {
    s1 = { status: "SKIP", code: "no_input" };
  } else if (mode === "file") {
    if (parsed.proof.hashOp === "ripemd160") s1 = { status: "SKIP", code: "alg_unsupported" };
    else {
      inDigest = hex(await opts.file!.digest(parsed.proof.hashOp));
      s1 = inDigest === hex(parsed.proof.digest) ? { status: "PASS", code: "ok" } : { status: "FAIL", code: "mismatch" };
    }
  } else if (inDigest === null || inDigest.length !== parsed.proof.digest.length * 2) {
    s1 = { status: "FAIL", code: "bad_digest" };
  } else {
    s1 = inDigest === hex(parsed.proof.digest) ? { status: "PASS", code: "ok" } : { status: "FAIL", code: "mismatch" };
  }

  // ---- steps 2, 3 ----
  const s2 = parsed.ok ? { status: "PASS" as Status, code: "ok" } : { status: "FAIL" as Status, code: parsed.code };
  let s3: { status: Status; code: string };
  if (!parsed.ok) s3 = { status: "SKIP", code: "no_proof" };
  else if (s1.status === "PASS") s3 = { status: "PASS", code: "ok" };
  else s3 = { status: "SKIP", code: "not_tied" };

  // ---- step 4 ----
  let ledger: Ledger | null = null;
  let s4: { status: Status; code: string };
  if (!parsed.ok) s4 = { status: "SKIP", code: "no_proof" };
  else if (!opts.ledger) s4 = { status: "SKIP", code: "not_requested" };
  else {
    ledger = await runLedger(parsed.proof, opts.ledger.servers, opts.ledger.fetchText);
    s4 = ledger === null ? { status: "SKIP", code: "no_bitcoin" } : ledgerOutcome(ledger);
  }

  // ---- verdict ----
  const all = [s1, s2, s3, s4];
  const vstatus: Status = all.some((s) => s.status === "FAIL") ? "FAIL" : all.some((s) => s.status === "SKIP") ? "SKIP" : "PASS";
  let block: number | null = null;
  let time: number | null = null;
  if (vstatus === "PASS" && parsed.ok && ledger !== null) {
    let best: { height: number; attestation: number } | null = null;
    for (const a of parsed.proof.attestations) {
      if (a.kind === "bitcoin" && a.height !== null && (best === null || a.height < best.height)) best = { height: a.height, attestation: a.index };
    }
    if (best !== null) {
      block = best.height;
      const al = ledger.attestations.find((x) => x.attestation === best!.attestation);
      time = al?.servers.find((s) => s.time !== null)?.time ?? null;
    }
  }
  const unverified = parsed.ok ? parsed.proof.attestations.filter((a) => a.kind !== "bitcoin").map((a) => a.index) : [];

  const steps: StepEntry[] = [
    { id: "file_hash", title: STEP_TITLES.file_hash, ...s1 },
    { id: "structure", title: STEP_TITLES.structure, ...s2 },
    { id: "hash_steps", title: STEP_TITLES.hash_steps, ...s3 },
    { id: "ledger", title: STEP_TITLES.ledger, ...s4 },
    { id: "verdict", title: STEP_TITLES.verdict, status: vstatus, code: vstatus === "PASS" ? "proved" : vstatus === "FAIL" ? "failed" : "incomplete" },
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
      unverified,
    },
  };
}


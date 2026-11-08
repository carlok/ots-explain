// The ledger (SPEC section 7, step 4). All network access goes through an injected fetchText.

import { equalBytes, fromHex, hex, isHex } from "./bytes.js";
import type { ParsedProof, ProofAttestation } from "./parse.js";
import { computePhases, type Phases } from "./phases.js";
import { blockHashOf, meetsPow, parseHeader, stripWitness } from "./tx.js";

export type Status = "PASS" | "FAIL" | "SKIP";
export type FetchText = (url: string) => Promise<{ status: number; body: string }>;

export interface Server {
  name: string;
  base: string;
}

export const DEFAULT_SERVERS: readonly Server[] = [
  { name: "blockstream.info", base: "https://blockstream.info/api" },
  { name: "mempool.space", base: "https://mempool.space/api" },
];

export type CheckId = "block_hash" | "header" | "merkle_root" | "txids" | "raw_tx" | "output";
export const CHECK_IDS: readonly CheckId[] = ["block_hash", "header", "merkle_root", "txids", "raw_tx", "output"];

export interface Check {
  id: CheckId;
  status: Status;
  code: string;
}

export interface ServerResult {
  server: string;
  status: Status;
  block_hash: string | null;
  header: string | null;
  time: number | null;
  checks: Check[];
}

export interface AttestationLedger {
  attestation: number;
  agree: boolean | null;
  servers: ServerResult[];
}

export interface PlanEntry {
  attestation: number;
  server: string;
  url: string;
}

export interface Ledger {
  servers: Server[];
  plan: PlanEntry[];
  attestations: AttestationLedger[];
}

/** Empty or missing list means the defaults; trailing slashes are removed from the bases. */
export function normalizeServers(servers?: readonly Server[] | null): Server[] {
  const list = servers && servers.length > 0 ? servers : DEFAULT_SERVERS;
  return list.map((s) => ({ name: s.name, base: s.base.replace(/\/+$/, "") }));
}

export interface BitcoinTarget {
  att: ProofAttestation;
  phases: Phases | null;
  /** message m_K on the attestation's node */
  root: Uint8Array;
  /** message m_t (the transaction), when phases exist */
  tx: Uint8Array | null;
}

export function bitcoinTargets(proof: ParsedProof): BitcoinTarget[] {
  const out: BitcoinTarget[] = [];
  for (const att of proof.attestations) {
    if (att.kind !== "bitcoin") continue;
    const { phases } = computePhases(proof, att);
    out.push({
      att,
      phases,
      root: proof.nodes[att.node].msg,
      tx: phases === null ? null : proof.nodes[phases.path[phases.transaction_index]].msg,
    });
  }
  return out;
}

/** The requests that can happen, before any is made. `{block_hash}` stands for the hash not yet known. */
export function ledgerPlan(proof: ParsedProof, servers?: readonly Server[] | null): PlanEntry[] {
  const list = normalizeServers(servers);
  const plan: PlanEntry[] = [];
  for (const t of bitcoinTargets(proof)) {
    for (const s of list) {
      const add = (path: string) => plan.push({ attestation: t.att.index, server: s.name, url: s.base + path });
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

type Got = { kind: "ok"; body: string } | { kind: "not_found" } | { kind: "unreachable" };

async function get(fetchText: FetchText, url: string): Promise<Got> {
  try {
    const res = await fetchText(url);
    if (res.status === 404) return { kind: "not_found" };
    if (res.status !== 200) return { kind: "unreachable" };
    return { kind: "ok", body: typeof res.body === "string" ? res.body : "" };
  } catch {
    return { kind: "unreachable" };
  }
}

const trim = (s: string): string => s.replace(/^[ \t\r\n\f\v]+|[ \t\r\n\f\v]+$/g, "");

function combine(statuses: Status[]): Status {
  if (statuses.includes("FAIL")) return "FAIL";
  if (statuses.includes("SKIP")) return "SKIP";
  return "PASS";
}

async function runServer(t: BitcoinTarget, server: Server, fetchText: FetchText): Promise<ServerResult> {
  const res: ServerResult = { server: server.name, status: "PASS", block_hash: null, header: null, time: null, checks: [] };
  let halted = false;
  let header: Uint8Array | null = null;
  const h = t.att.height;

  const record = (id: CheckId, status: Status, code: string): void => {
    res.checks.push({ id, status, code });
    if (status !== "PASS") halted = true;
  };
  const gate = (id: CheckId): boolean => {
    if (halted) {
      res.checks.push({ id, status: "SKIP", code: "not_run" });
      return false;
    }
    return true;
  };
  const gateTx = (id: CheckId): boolean => {
    if (!gate(id)) return false;
    if (t.phases === null) {
      res.checks.push({ id, status: "SKIP", code: "no_transaction" });
      return false;
    }
    return true;
  };
  const httpFail = (id: CheckId, g: Got): boolean => {
    if (g.kind === "not_found") record(id, "FAIL", "not_found");
    else if (g.kind === "unreachable") record(id, "SKIP", "unreachable");
    return g.kind !== "ok";
  };

  // block_hash
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

  // header
  if (gate("header")) {
    const g = await get(fetchText, `${server.base}/block/${res.block_hash}/header`);
    if (!httpFail("header", g) && g.kind === "ok") {
      const body = trim(g.body);
      if (body.length !== 160 || !isHex(body)) record("header", "FAIL", "bad_response");
      else {
        res.header = body.toLowerCase();
        header = fromHex(res.header);
        if (hex(blockHashOf(header!)) !== res.block_hash) record("header", "FAIL", "bad_hash");
        else if (!meetsPow(header!)) record("header", "FAIL", "bad_pow");
        else {
          res.time = parseHeader(header!).time;
          record("header", "PASS", "ok");
        }
      }
    }
  }

  // merkle_root
  if (gate("merkle_root")) {
    if (equalBytes(parseHeader(header!).merkleRoot, t.root)) record("merkle_root", "PASS", "ok");
    else record("merkle_root", "FAIL", "mismatch");
  }

  // txids
  if (gateTx("txids")) {
    const g = await get(fetchText, `${server.base}/block/${res.block_hash}/txids`);
    if (!httpFail("txids", g) && g.kind === "ok") {
      let list: unknown = null;
      try {
        list = JSON.parse(g.body);
      } catch {
        list = null;
      }
      if (!Array.isArray(list) || !list.every((x) => typeof x === "string")) record("txids", "FAIL", "bad_response");
      else if (!list.includes(t.phases!.txid)) record("txids", "FAIL", "not_in_block");
      else record("txids", "PASS", "ok");
    }
  }

  // raw_tx
  if (gateTx("raw_tx")) {
    const g = await get(fetchText, `${server.base}/tx/${t.phases!.txid}/hex`);
    if (!httpFail("raw_tx", g) && g.kind === "ok") {
      const raw = fromHex(trim(g.body));
      const stripped = raw === null ? null : stripWitness(raw);
      if (stripped === null) record("raw_tx", "FAIL", "bad_response");
      else if (!equalBytes(stripped, t.tx!)) record("raw_tx", "FAIL", "mismatch");
      else record("raw_tx", "PASS", "ok");
    }
  }

  // output: the stripped server transaction equals the proof's (raw_tx passed), so the proof's output is the server's
  if (gateTx("output")) {
    if (t.phases!.output !== null) record("output", "PASS", "ok");
    else record("output", "FAIL", "no_output");
  }

  res.status = combine(res.checks.map((c) => c.status));
  return res;
}

export function agreeOf(servers: ServerResult[]): boolean | null {
  const headers = servers.map((s) => s.header).filter((x): x is string => x !== null);
  if (headers.length < 2) return null;
  return headers.every((x) => x === headers[0]);
}

/** Run every check on every server, sequentially and deterministically. */
export async function runLedger(proof: ParsedProof, servers: readonly Server[] | null | undefined, fetchText: FetchText): Promise<Ledger | null> {
  const targets = bitcoinTargets(proof);
  if (targets.length === 0) return null;
  const list = normalizeServers(servers);
  const attestations: AttestationLedger[] = [];
  for (const t of targets) {
    const results: ServerResult[] = [];
    for (const s of list) results.push(await runServer(t, s, fetchText));
    attestations.push({ attestation: t.att.index, agree: agreeOf(results), servers: results });
  }
  return { servers: list, plan: ledgerPlan(proof, list), attestations };
}

/** Step 4 status and code over a finished ledger. */
export function ledgerOutcome(l: Ledger): { status: Status; code: string } {
  if (l.attestations.some((a) => a.agree === false)) return { status: "FAIL", code: "disagree" };
  const all = l.attestations.flatMap((a) => a.servers.flatMap((s) => s.checks.map((c) => c.status)));
  if (all.includes("FAIL")) return { status: "FAIL", code: "check_failed" };
  if (all.includes("SKIP")) return { status: "SKIP", code: "incomplete" };
  return { status: "PASS", code: "ok" };
}

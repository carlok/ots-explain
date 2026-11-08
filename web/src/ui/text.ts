// Plain-text rendering of a report. No DOM: used by the page (copy report) and by the tests, which
// compare it with python/verify_ots.py --steps character by character.

import type { Report } from "../core/index.js";
import stepsSpec from "../../../spec/steps.json";

export const WHY: Record<string, string> = Object.fromEntries(stepsSpec.steps.map((s) => [s.id, s.why]));

export const MSG: Record<string, Record<string, string>> = {
  file_hash: {
    ok: "the digest of your input equals the digest the proof names",
    mismatch: "your input does not hash to the digest in the proof: this proof is not about it",
    bad_digest: "that digest is not valid hex or has the wrong length for the proof's algorithm",
    no_input: "no file or digest given, so nothing ties the proof to your data",
    no_proof: "the proof could not be read, so the algorithm is unknown",
    alg_unsupported: "this proof names RIPEMD-160, which this tool does not use to hash files; pass --digest HEX instead",
  },
  hash_steps: {
    ok: "every operation was recomputed from your digest",
    not_tied: "shown from the digest inside the proof, not confirmed against your input",
    no_proof: "no readable proof",
  },
  ledger: {
    ok: "every Bitcoin attestation was confirmed by every server asked",
    not_requested: "not asked: no network was used",
    no_bitcoin: "the proof has no Bitcoin attestation to check",
    no_proof: "no readable proof",
    check_failed: "at least one check failed",
    disagree: "the servers gave different headers",
    incomplete: "nothing failed, but some check could not be completed",
  },
  verdict: { proved: "", failed: "at least one check failed", incomplete: "some checks were skipped, so no verdict is given" },
};

export const KIND_NAME: Record<string, string> = { bitcoin: "Bitcoin", litecoin: "Litecoin", ethereum: "Ethereum", pending: "pending", unknown: "unknown" };

export const STEP_ORDER = ["file_hash", "structure", "hash_steps", "ledger", "verdict"];

export function when(ts: number): string {
  return new Date(ts * 1000).toISOString().replace("T", " ").replace(/\.\d+Z$/, " UTC");
}

type TreeNode = { id: number; parent: number; op: string | null; arg: string | null; digest: string };

export interface Hop { n: number; op: string; arg: string | null; digest: string; phase: string | null }
export interface Path { attestation: number; kind: string; start: string; hops: Hop[] }

/** The chain of operations from the proof digest to each attestation, with the phase each hop belongs to. */
export function paths(report: Report): Path[] {
  const proof = report.proof;
  if (!proof) return [];
  const nodes = new Map<number, TreeNode>(proof.tree.map((n) => [n.id, n]));
  return proof.attestations.map((a) => {
    const chain: TreeNode[] = [];
    for (let k = a.node; k !== -1; k = nodes.get(k)!.parent) chain.push(nodes.get(k)!);
    chain.reverse();
    const ph = a.phases;
    const hops: Hop[] = [];
    for (let i = 1; i < chain.length; i++) {
      let phase: string | null = null;
      if (ph) {
        if (i <= ph.commitment_index) phase = "calendar's tree";
        else if (i <= ph.txid_index) phase = "the transaction";
        else phase = "the block's merkle path";
      }
      hops.push({ n: i, op: chain[i].op ?? "", arg: chain[i].arg, digest: chain[i].digest, phase });
    }
    return { attestation: a.index, kind: a.kind, start: chain[0].digest, hops };
  });
}

function shortArg(arg: string): string {
  const s = " " + arg;
  return s.length < 70 ? s : s.slice(0, 34) + ".." + s.slice(-30);
}

function pad(n: number, w: number): string { return String(n).padStart(w, " "); }

export function renderText(report: Report, steps = false): string {
  const L: string[] = [];
  const inp = report.input, proof = report.proof;
  L.push("OpenTimestamps proof, hop by hop");
  L.push("input: " + (inp.mode === "file" ? `file (${inp.size} bytes)` : inp.mode === "digest" ? "a digest" : "proof only"));
  for (const s of report.steps) {
    const n = STEP_ORDER.indexOf(s.id) + 1;
    L.push("");
    L.push(`[${s.status}] ${n}. ${s.title}`);
    L.push("    " + WHY[s.id]);
    if (s.id === "structure") {
      if (report.error) L.push("    cannot read it: " + report.error.code);
      else if (proof) {
        L.push(`    version 1, header algorithm ${proof.hash_op}, ${proof.size} bytes, ${proof.nodes} nodes, ${proof.ops} operations, depth ${proof.max_depth}`);
        L.push("    proof digest: " + proof.digest);
        for (const a of proof.attestations) {
          const what = a.height !== null ? "block " + a.height : a.uri ? a.uri : "tag " + a.tag;
          L.push(`    attestation ${a.index}: ${KIND_NAME[a.kind]} (${what})`);
        }
      }
    } else if (s.id === "file_hash" && inp.digest) {
      L.push("    digest: " + inp.digest);
    } else if (s.id === "verdict" && s.status === "PASS") {
      const v = report.verdict;
      L.push(`    This file existed before block ${v.block} (header time ${when(v.time!)}; miners' clocks are approximate).`);
      if (v.unverified.length) L.push("    Not checked here: attestation(s) " + v.unverified.join(", ") + ".");
    }
    const m = MSG[s.id]?.[s.code];
    if (m) L.push("    -> " + m);
    if (s.id === "hash_steps" && proof && steps) {
      for (const p of paths(report)) {
        L.push(`    path to attestation ${p.attestation} (${KIND_NAME[p.kind]}):`);
        L.push("      0  start        " + p.start);
        let last: string | null = null;
        for (const h of p.hops) {
          if (h.phase && h.phase !== last) { last = h.phase; L.push("      -- phase: " + last); }
          const arg = h.arg ? shortArg(h.arg) : "";
          L.push(`    ${pad(h.n, 3)}  ${h.op}${arg}`);
          L.push("           = " + h.digest);
        }
      }
    }
    if (s.id === "ledger" && report.ledger) {
      for (const r of report.ledger.attestations) {
        for (const sv of r.servers) {
          const bad = sv.checks.filter((c) => c.status !== "PASS").map((c) => `${c.id} ${c.code}`).join(", ");
          L.push(`    attestation ${r.attestation} on ${sv.server}: ${sv.status}${sv.status !== "PASS" ? "  (" + bad + ")" : ""}`);
        }
      }
    }
    if (s.id === "ledger" && proof) {
      for (const a of proof.attestations) for (const w of a.where_to_look) L.push(`    look: ${w.server} ${w.kind} ${w.url}`);
    }
  }
  return L.join("\n") + "\n";
}

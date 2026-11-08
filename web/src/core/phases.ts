// Phases of a Bitcoin attestation (SPEC section 6).

import { hex, reversed } from "./bytes.js";
import type { ParsedProof, ProofAttestation } from "./parse.js";
import { findCommitmentOutput, parseLegacyTx, type ScriptKind } from "./tx.js";

export interface PhasesOutput {
  index: number;
  kind: ScriptKind;
  script: string;
}

export interface Phases {
  path: number[];
  commitment_index: number;
  transaction_index: number;
  txid_index: number;
  root_index: number;
  commitment: string;
  txid: string;
  output: PhasesOutput | null;
}

export type PhasesCode = "no_transaction" | "no_txid_hash";

export interface PhasesResult {
  phases: Phases | null;
  phases_code: PhasesCode | null;
}

/** Node ids from the root to `node`. */
export function pathTo(proof: ParsedProof, node: number): number[] {
  const path: number[] = [];
  for (let n = node; n !== -1; n = proof.nodes[n].parent) path.push(n);
  return path.reverse();
}

export function computePhases(proof: ParsedProof, att: ProofAttestation): PhasesResult {
  const none = (code: PhasesCode): PhasesResult => ({ phases: null, phases_code: code });
  if (att.kind !== "bitcoin") return { phases: null, phases_code: null };
  const path = pathTo(proof, att.node);
  const K = path.length - 1;
  const msg = (i: number) => proof.nodes[path[i]].msg;
  const opAt = (i: number) => proof.nodes[path[i]].op;

  let t = -1;
  let tx = null;
  for (let i = 1; i <= K; i++) {
    tx = parseLegacyTx(msg(i));
    if (tx !== null) { t = i; break; }
  }
  if (tx === null) return none("no_transaction");

  let c = t;
  while (c > 0 && (opAt(c) === "append" || opAt(c) === "prepend")) c--;
  if (c === t) return none("no_transaction");

  if (!(t + 2 <= K && opAt(t + 1) === "sha256" && opAt(t + 2) === "sha256")) return none("no_txid_hash");
  const txid = hex(reversed(msg(t + 2)));

  const commitment = msg(c);
  const found = findCommitmentOutput(tx, commitment);
  return {
    phases: {
      path,
      commitment_index: c,
      transaction_index: t,
      txid_index: t + 2,
      root_index: K,
      commitment: hex(commitment),
      txid,
      output: found === null ? null : { index: found.index, kind: found.kind, script: hex(found.script) },
    },
    phases_code: null,
  };
}


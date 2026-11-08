// The page. All state is in this file's variables; nothing is stored, and nothing is sent anywhere
// except the GET requests the person approves in the "ask the chain" panel (or the one ?proof= fetch).

import {
  buildReport, canonicalJson, DEFAULT_SERVERS, decodePermalink, encodePermalink, fileFromBlob, fromHex, hex, isHex,
  DEFAULT_CALENDARS, KNOWN_CALENDARS, MAGIC, commitmentFor, stampDigest, upgradeProof, type CalendarCall,
  ledgerPlan, parseProof, type Report, type Server, type FetchText, type FileInput,
} from "../core/index.js";
import stepsSpec from "../../../spec/steps.json";
import { KIND_NAME, MSG, paths, renderText, when, type Path } from "./text.js";

declare const __VERSION__: string;

// ------------------------------------------------------------------ tiny DOM helpers

type Child = Node | string | null | false | undefined;
type Props = Record<string, unknown> | null;

function h<K extends keyof HTMLElementTagNameMap>(tag: K, props?: Props, ...kids: Child[]): HTMLElementTagNameMap[K] {
  const el = document.createElement(tag);
  for (const [k, v] of Object.entries(props ?? {})) {
    if (v === null || v === undefined || v === false) continue;
    if (k === "class") el.className = String(v);
    else if (k.startsWith("on") && typeof v === "function") el.addEventListener(k.slice(2), v as EventListener);
    else el.setAttribute(k, v === true ? "" : String(v));
  }
  for (const c of kids) if (c !== null && c !== undefined && c !== false) el.append(c);
  return el;
}
const $ = <T extends HTMLElement>(id: string): T => document.getElementById(id) as T;

const BADGE: Record<string, [string, string]> = { PASS: ["✓", "Passed"], FAIL: ["✕", "Failed"], SKIP: ["–", "Skipped"] };
function badge(status: string): HTMLElement {
  const [icon, word] = BADGE[status];
  return h("span", { class: "badge " + status }, h("span", { "aria-hidden": "true" }, icon), " " + word);
}
const mono = (s: string, cls = "") => h("code", { class: ("hex " + cls).trim() }, s);

// ------------------------------------------------------------------ state

const MAX_PROOF = 16 * 1024 * 1024;
let file: File | null = null;
let proofBytes: Uint8Array | null = null;
let proofLabel = "";
let report: Report | null = null;
let showHops = false;
let runId = 0;
let ledgerServers: Server[] | null = null; // set once the person approved a ledger run
let customBase = "";
let disabledDefaults = new Set<string>();
let proofUrlFromLink: string | null = null;
let lastFocus: string | null = null;

type Mode = "check" | "stamp";
let mode: Mode = "check";
const stamp = {
  file: null as File | null, name: "", digest: null as Uint8Array | null, nonce: null as Uint8Array | null,
  bytes: null as Uint8Array | null, log: [] as string[], busy: false, disabled: new Set<string>(), custom: "",
};
let upgraded: Uint8Array | null = null; // the last upgraded proof, offered for download
let upgradeLog: string[] = [];
let customCalendar = "";

const digestCache = new WeakMap<File, Map<string, Uint8Array>>();

function live(msg: string): void { $("live").textContent = msg; }

// ------------------------------------------------------------------ inputs

function sizeText(n: number): string {
  return n < 1024 ? n + " bytes" : n < 1048576 ? (n / 1024).toFixed(1) + " KiB" : n < 1073741824 ? (n / 1048576).toFixed(1) + " MiB" : (n / 1073741824).toFixed(2) + " GiB";
}

function showChosen(): void {
  $("file-name").textContent = file ? `${file.name}, ${sizeText(file.size)}` : "";
  $("proof-name").textContent = proofBytes ? `${proofLabel}, ${sizeText(proofBytes.length)}` : "";
  $("drop-file").classList.toggle("has", !!file);
  $("drop-proof").classList.toggle("has", !!proofBytes);
}

async function setProofFile(f: File): Promise<void> {
  if (f.size > MAX_PROOF) { live(`${f.name} is ${sizeText(f.size)}: far too big for an .ots proof.`); return; }
  proofBytes = new Uint8Array(await f.arrayBuffer());
  proofLabel = f.name;
  ledgerServers = null;
  ($("proofhex") as HTMLTextAreaElement).value = ""; proofPasteError = null;
}

// ------------------------------------------------------------------ pasted text

type Pasted =
  | { kind: "empty" }
  | { kind: "digest"; hex: string; algs: string }
  | { kind: "proof"; bytes: Uint8Array }
  | { kind: "bad"; why: string };

const MAGIC_HEX = hex(MAGIC);
const PASTED = "pasted proof";

/** What a pasted string is: a file hash (told apart by its length), an .ots proof (by its header), or why it is neither. */
function classify(text: string): Pasted {
  const s = text.replace(/\s+/g, "").replace(/^0x/i, "").toLowerCase();
  if (!s) return { kind: "empty" };
  const bad = s.search(/[^0-9a-f]/);
  if (bad >= 0) return { kind: "bad", why: `This is not hex: it contains "${s[bad]}". Hex uses only the digits 0-9 and the letters a-f.` };
  if (s.length % 2) return { kind: "bad", why: `${s.length} hex characters is an odd number. Each byte is two characters, so one is missing or one is extra.` };
  if (s.startsWith(MAGIC_HEX)) {
    if (s.length / 2 > MAX_PROOF) return { kind: "bad", why: "This is far too big for an .ots proof." };
    return { kind: "proof", bytes: fromHex(s)! }; // s is checked to be even-length hex above
  }
  if (s.length === 64) return { kind: "digest", hex: s, algs: "SHA-256" };
  if (s.length === 40) return { kind: "digest", hex: s, algs: "SHA-1 or RIPEMD-160 (both are 40 hex characters; the proof says which)" };
  if (MAGIC_HEX.startsWith(s)) return { kind: "bad", why: `This is the start of an .ots header and nothing after it: ${s.length / 2} of its ${MAGIC.length} bytes.` };
  if (s.length > 64) return { kind: "bad", why: `This is not an .ots proof: every proof starts with the header ${MAGIC_HEX.slice(0, 32)}… (the bytes of "OpenTimestamps"), and this starts with ${s.slice(0, 16)}….` };
  return { kind: "bad", why: `${s.length / 2} bytes is not the size of a file hash: SHA-256 is 32 bytes (64 hex characters), SHA-1 and RIPEMD-160 are 20 bytes (40).` };
}

let proofPasteError: string | null = null;
let moveNote: string | null = null;
let hintNodes: Node[] = [];

function setPastedProof(bytes: Uint8Array): void {
  proofBytes = bytes; proofLabel = PASTED; ledgerServers = null; proofPasteError = null;
}

/** The line under the inputs: what is missing, what was understood, or why a pasted string cannot be used. */
function guide(): void {
  const m = $("input-msg");
  const stampBtn = $("stamp-this") as HTMLButtonElement;
  const pasted = file ? ({ kind: "empty" } as Pasted) : classify(($("digest") as HTMLInputElement).value);
  let text: string | null = null, bad = false, stampable: string | null = null;
  if (proofPasteError) { text = "The proof: " + proofPasteError; bad = true; }
  else if (pasted.kind === "bad") { text = "The hash: " + pasted.why; bad = true; }
  else if (!proofBytes) {
    if (pasted.kind === "digest") {
      text = `That is a file's hash (${pasted.algs}). A hash alone cannot be checked: the timestamp is in the .ots proof made for it. Drop or paste that proof to check it against this hash, or stamp the hash now to start a new proof.`;
      if (pasted.algs === "SHA-256") stampable = pasted.hex;
    } else if (file) text = "Now the .ots proof for this file: drop it or paste its hex.";
  } else if (pasted.kind === "digest") text = `Checking the proof against the pasted hash (${pasted.algs}).`;
  else if (!file) text = "No file and no hash, so step 1 is skipped. Add the file or paste its hash to check that too.";
  if (moveNote) { text = moveNote + (text ? " " + text : ""); moveNote = null; }
  if (text === null) m.replaceChildren(...hintNodes.map((n) => n.cloneNode(true)));
  else m.textContent = text;
  m.classList.toggle("bad", bad);
  stampBtn.hidden = !stampable;
  stampBtn.dataset.hex = stampable ?? "";
}

function setFile(f: File | null): void {
  file = f;
  if (f) { ($("digest") as HTMLInputElement).value = ""; }
  ledgerServers = null;
}

async function accept(files: File[]): Promise<void> {
  if (mode === "stamp") { if (files[0]) await setStampFile(files[0]); return; }
  const proofs = files.filter((f) => /\.ots$/i.test(f.name));
  const others = files.filter((f) => !/\.ots$/i.test(f.name));
  if (proofs[0]) await setProofFile(proofs[0]);
  if (others[0]) setFile(others[0]);
  showChosen();
  schedule();
}

// ------------------------------------------------------------------ running

function schedule(): void { void run(); }

function fileInput(f: File): FileInput {
  const base = fileFromBlob(f, (done, total) => {
    const p = $("progress") as HTMLProgressElement;
    p.hidden = false; p.max = total; p.value = done;
    const pct = Math.floor((done / total) * 100);
    if (pct % 25 === 0 || done === total) live(`Hashing ${f.name}: ${pct}%`);
  });
  return {
    size: base.size,
    digest: async (alg) => {
      let m = digestCache.get(f);
      if (!m) digestCache.set(f, (m = new Map()));
      let d = m.get(alg);
      if (!d) { d = await base.digest(alg); m.set(alg, d); }
      return d;
    },
  };
}

const fetchText: FetchText = async (url) => {
  const ctl = new AbortController();
  const timer = setTimeout(() => ctl.abort(), 15000);
  try {
    const r = await fetch(url, { method: "GET", cache: "no-store", credentials: "omit", referrerPolicy: "no-referrer", signal: ctl.signal });
    return { status: r.status, body: await r.text() };
  } finally { clearTimeout(timer); }
};

const calendarCall: CalendarCall = async (url, body) => {
  const ctl = new AbortController();
  const timer = setTimeout(() => ctl.abort(), 20000);
  try {
    const r = await fetch(url, {
      method: body ? "POST" : "GET", body: body as BodyInit | undefined, headers: { Accept: "application/vnd.opentimestamps.v1" },
      cache: "no-store", credentials: "omit", referrerPolicy: "no-referrer", signal: ctl.signal,
    });
    return { status: r.status, body: new Uint8Array(await r.arrayBuffer()) };
  } finally { clearTimeout(timer); }
};

function download(bytes: Uint8Array | string, name: string, type: string): void {
  const a = h("a", { href: URL.createObjectURL(new Blob([bytes as BlobPart], { type })), download: name });
  document.body.append(a); a.click(); a.remove();
}

function proofFileName(): string {
  const base = proofLabel.replace(/ \(upgraded\)$/, "");
  return /\.ots$/i.test(base) ? base : (file?.name ?? (base || "proof")) + ".ots";
}

async function run(): Promise<void> {
  const my = ++runId;
  guide();
  const pasted = file ? ({ kind: "empty" } as Pasted) : classify(($("digest") as HTMLInputElement).value);
  const digestText = pasted.kind === "digest" ? pasted.hex : "";
  if (!proofBytes || pasted.kind === "bad") {
    report = null; render(); live(proofBytes ? "The pasted hash cannot be used: see the note under the inputs." : "Pick an .ots proof to begin."); return;
  }
  $("busy").hidden = false;
  live("Reading the proof…");
  try {
    report = await buildReport({
      proof: proofBytes,
      file: file ? fileInput(file) : null,
      digestHex: !file && digestText ? digestText : null,
      ledger: ledgerServers ? { servers: ledgerServers, fetchText } : null,
    });
  } catch (e) {
    if (my === runId) { live("Something went wrong: " + (e instanceof Error ? e.message : String(e))); $("busy").hidden = true; }
    return;
  }
  if (my !== runId) return;
  ($("progress") as HTMLProgressElement).hidden = true;
  $("busy").hidden = true;
  render();
  const v = report.verdict;
  live(v.status === "PASS" ? `Verdict: proved. Before block ${v.block}.` : v.status === "FAIL" ? "Verdict: a check failed." : "Verdict: not proven yet, some checks were skipped.");
}

// ------------------------------------------------------------------ rendering

function verdictBanner(r: Report): HTMLElement {
  const v = r.verdict;
  let title: string, sub: Child[];
  if (v.status === "PASS") {
    title = `Proved: this existed before Bitcoin block ${v.block}.`;
    const al = r.ledger?.attestations.find((a) => a.servers.some((s) => s.time === v.time));
    sub = [`Block header time ${when(v.time!)} (miners' clocks are only approximate). Confirmed by ${al ? al.servers.length : 0} explorer${al && al.servers.length === 1 ? "" : "s"}.`];
    if (v.unverified.length) sub.push(" Attestation " + v.unverified.join(", ") + " is not a Bitcoin one and was not checked here.");
  } else {
    title = v.status === "FAIL" ? "A check failed: this proof does not hold." : "Not proven yet.";
    const items = r.steps.filter((s) => s.id !== "verdict" && s.status === v.status).map((s) => `${s.title}: ${MSG[s.id]?.[s.code] ?? s.code}`);
    sub = [h("ul", null, ...items.map((t) => h("li", null, t)))];
  }
  return h("section", { class: "verdict " + v.status, "aria-labelledby": "verdict-title" },
    h("h2", { id: "verdict-title" }, title), h("div", { class: "vsub" }, ...sub));
}

function stepCard(r: Report, i: number): HTMLElement {
  const s = r.steps[i];
  const body = h("div", { class: "detail" });
  const msg = MSG[s.id]?.[s.code];
  if (msg) body.append(h("p", { class: "msg" }, msg));
  const spec = stepsSpec.steps[i];

  if (s.id === "file_hash") {
    if (r.input.mode === "file") body.append(h("p", { class: "meta" }, `File ${file?.name ?? ""}, ${r.input.size} bytes`));
    if (r.input.digest) body.append(h("p", { class: "meta" }, `${r.input.digest_alg ?? ""} of your input`, mono(r.input.digest)));
    if (r.proof && s.status === "FAIL") body.append(h("p", { class: "meta" }, "digest the proof names", mono(r.proof.digest)));
  } else if (s.id === "structure" && r.proof) {
    const p = r.proof;
    body.append(h("dl", { class: "facts" },
      h("dt", null, "header algorithm"), h("dd", null, p.hash_op),
      h("dt", null, "size"), h("dd", null, `${p.size} bytes`),
      h("dt", null, "tree"), h("dd", null, `${p.nodes} nodes, ${p.ops} operations, depth ${p.max_depth}`),
      h("dt", null, "digest it starts from"), h("dd", null, mono(p.digest))));
    body.append(h("ul", { class: "atts" }, ...p.attestations.map((a) => {
      const what = a.height !== null ? "block " + a.height : a.uri ?? "tag " + a.tag;
      const note = a.kind === "pending" ? "Not in a block yet: the calendar will add the Bitcoin path after a few hours (upgrade the proof, then check again)."
        : a.kind === "bitcoin" ? "" : "Not checked by this tool.";
      return h("li", null, h("span", { class: "chip " + a.kind }, KIND_NAME[a.kind]), ` attestation ${a.index}: ${what}`, note && h("div", { class: "note" }, note));
    })));
  } else if (s.id === "hash_steps" && r.proof) {
    for (const p of paths(r)) {
      const table = h("div", { class: "hops", role: "table", "aria-label": `Hops to attestation ${p.attestation}` });
      table.append(hop("0", "start", "", p.start));
      let last: string | null = null;
      for (const hp of p.hops) {
        if (hp.phase && hp.phase !== last) { last = hp.phase; table.append(h("div", { class: "phase", role: "row" }, h("span", { role: "cell" }, PHASE_TEXT[last]))); }
        table.append(hop(String(hp.n), hp.op, hp.arg ?? "", hp.digest));
      }
      body.append(chainSummary(r, p), h("details", { class: "path", open: showHops }, h("summary", null, `Every hop to attestation ${p.attestation} (${p.hops.length})`), table));
    }
  } else if (s.id === "ledger") {
    ledgerBody(r, body);
  } else if (s.id === "verdict") {
    body.textContent = "";
    body.append(h("p", { class: "msg" }, r.verdict.status === "PASS" ? "All four checks passed and none was skipped." : msg ?? ""));
  }
  const title = h("h3", { id: "h-" + s.id, tabindex: "-1" }, s.title);
  return h("li", { class: "step " + s.status, id: "step-" + s.id },
    h("div", { class: "num", "aria-hidden": "true" }, String(i + 1)),
    h("div", { class: "sbody" }, h("div", { class: "shead" }, title, badge(s.status)), h("p", { class: "why" }, spec.why), body));
}

const PHASE_NAME: Record<string, string> = {
  "calendar's tree": "the calendar's tree", "the transaction": "the Bitcoin transaction", "the block's merkle path": "the block's merkle path",
};
const shortHex = (d: string) => h("code", { class: "hex", title: d }, d.length > 24 ? d.slice(0, 10) + "\u2026" + d.slice(-10) : d);

/** The chain at a glance: the digest you start from, the digest each phase ends on, and where the path ends. */
function chainSummary(r: Report, p: Path): HTMLElement {
  const att = r.proof!.attestations[p.attestation];
  const groups: { name: string; count: number; out: string }[] = [];
  for (const hp of p.hops) {
    const name = hp.phase ? PHASE_NAME[hp.phase] : att.kind === "pending" ? "to the calendar's commitment" : "to the attestation";
    const g = groups[groups.length - 1];
    if (g && g.name === name) { g.count++; g.out = hp.digest; } else groups.push({ name, count: 1, out: hp.digest });
  }
  const end = att.kind === "bitcoin" ? `Bitcoin block ${att.height}` : att.kind === "pending" ? `promised by ${att.uri ?? "a calendar"}, not in a block yet` : `${KIND_NAME[att.kind]} attestation, not checked here`;
  return h("ol", { class: "chain", "aria-label": `Attestation ${p.attestation}: from your digest to ${end}` },
    h("li", { class: "link start" }, h("span", { class: "lname" }, "your digest"), shortHex(p.start)),
    ...groups.map((g) => h("li", { class: "link" }, h("span", { class: "lname" }, g.name, h("span", { class: "lcount" }, `${g.count} hop${g.count === 1 ? "" : "s"}`)), shortHex(g.out))),
    h("li", { class: "link end " + att.kind }, h("span", { class: "lname" }, end)));
}

const PHASE_TEXT: Record<string, string> = {
  "calendar's tree": "The calendar's tree — your digest is mixed with a random nonce and with other people's, and hashed up to a single commitment.",
  "the transaction": "The transaction — that commitment sits inside a Bitcoin transaction; these hops rebuild it and hash it to its id.",
  "the block's merkle path": "The block's merkle path — the transaction id is hashed up the block's tree to the root stored in the block header.",
};

function hop(n: string, op: string, arg: string, digest: string): HTMLElement {
  return h("div", { class: "hop", role: "row" },
    h("span", { class: "n", role: "cell" }, n),
    h("span", { class: "op", role: "cell" }, op, arg && mono(arg, "arg")),
    h("span", { class: "res", role: "cell" }, mono(digest)));
}

const LEDGER_CODE: Record<string, string> = {
  ok: "ok", bad_response: "unexpected answer format", bad_hash: "header does not hash to the block hash", bad_pow: "header does not meet its own proof-of-work target",
  mismatch: "differs from what the proof says", not_in_block: "transaction is not in that block", not_found: "the server has no such item", no_output: "no output carries the commitment",
  unreachable: "could not reach the server", no_transaction: "the proof has no readable transaction", not_run: "not run",
};
const CHECK_TITLE: Record<string, string> = Object.fromEntries(stepsSpec.ledger_checks.map((c) => [c.id, c.title]));

function ledgerBody(r: Report, body: HTMLElement): void {
  const bitcoin = r.proof?.attestations.some((a) => a.kind === "bitcoin");
  if (r.ledger) {
    for (const a of r.ledger.attestations) {
      body.append(h("h4", null, `Attestation ${a.attestation}`, a.agree === true ? h("span", { class: "note inline" }, ": the servers agree") : a.agree === false ? h("span", { class: "note inline bad" }, ": the servers disagree") : h("span", { class: "note inline" }, ": one server, nothing to compare")));
      for (const sv of a.servers) {
        body.append(h("details", { class: "server", open: sv.status !== "PASS" || showHops },
          h("summary", null, badge(sv.status), " ", sv.server, sv.time !== null && h("span", { class: "note inline" }, ", header time " + when(sv.time))),
          h("ul", { class: "checks" }, ...sv.checks.map((c) => h("li", null, badge(c.status), ` ${CHECK_TITLE[c.id]}`, c.status !== "PASS" && h("span", { class: "note inline" }, " — " + (LEDGER_CODE[c.code] ?? c.code)))))));
      }
    }
  }
  if (r.proof?.attestations.some((a) => a.kind === "pending")) body.append(upgradePanel(r));
  if (bitcoin) body.append(consentPanel(r));
  const links = r.proof?.attestations.flatMap((a) => a.where_to_look) ?? [];
  if (links.length) {
    body.append(h("details", { class: "look" }, h("summary", null, "Look for yourself (opens a third-party site)"),
      h("ul", null, ...links.map((l) => h("li", null, h("a", { href: l.url, target: "_blank", rel: "noopener noreferrer" }, `${l.server}: ${l.kind === "raw_hex" ? "raw transaction" : l.kind === "tx" ? "transaction" : "block"}`), " ", h("span", { class: "note inline" }, l.url))))));
  }
}

function upgradePanel(r: Report): HTMLElement {
  const proof = r.proof!;
  const pend = proof.attestations.filter((a) => a.kind === "pending" && a.uri);
  const custom = h("input", { type: "url", id: "ucal", placeholder: "https://calendar.example.org", value: customCalendar, spellcheck: "false", autocomplete: "off" }) as HTMLInputElement;
  const plan = h("pre", { class: "plan", id: "uplan", tabindex: "0", "aria-label": "Calendar URLs that will be requested" });
  const go = h("button", { type: "button", class: "primary", id: "upgrade" }, "Ask the calendar");
  const allowed = () => [...KNOWN_CALENDARS, ...(customCalendar.trim() ? [customCalendar.trim().replace(/\/+$/, "")] : [])];
  const refresh = () => {
    const ok = new Set(allowed());
    const lines = pend.map((a) => {
      const u = a.uri!.replace(/\/+$/, ""), d = proof.tree.find((n) => n.id === a.node)!.digest;
      return ok.has(u) && d.length === 64 ? `GET ${u}/timestamp/${d}` : `(not asked: ${u} is not a calendar this page knows)`;
    });
    plan.textContent = lines.join("\n");
    go.toggleAttribute("disabled", !lines.some((l) => l.startsWith("GET ")));
  };
  custom.addEventListener("input", () => { customCalendar = custom.value; refresh(); });
  go.addEventListener("click", async () => {
    go.setAttribute("disabled", ""); live("Asking the calendar…");
    upgradeLog = [];
    try {
      const res = await upgradeProof(proofBytes!, calendarCall, allowed(), (l) => upgradeLog.push(l));
      if (res.changed) { proofBytes = res.bytes; upgraded = res.bytes; proofLabel = proofLabel.replace(/ \(upgraded\)$/, "") + " (upgraded)"; ledgerServers = null; showChosen(); }
      live(res.changed ? "The calendar had the Bitcoin path: the proof was upgraded." : "Not upgraded yet: see the messages in the ledger step.");
    } catch (e) { upgradeLog.push(e instanceof Error ? e.message : String(e)); live("The upgrade did not work."); }
    lastFocus = "h-ledger"; schedule();
  });
  refresh();
  return h("div", { class: "consent" },
    h("h4", null, "This proof is still pending"),
    h("p", null, "A calendar has promised to put it into a Bitcoin block, which takes a few hours. Once it has, ask it for the rest of the path. Only the commitment named in the proof is sent, to the calendar the proof names, and only if this page knows that calendar."),
    plan, h("label", { class: "custom" }, h("span", null, "Another calendar to allow (optional)"), custom),
    upgradeLog.length > 0 && h("ul", { class: "log" }, ...upgradeLog.map((l) => h("li", null, l))), go);
}

function chosenServers(): Server[] {
  const s = DEFAULT_SERVERS.filter((d) => !disabledDefaults.has(d.name)).map((d) => ({ ...d }));
  const c = customBase.trim().replace(/\/+$/, "");
  if (c) s.push({ name: c, base: c });
  return s;
}

function customError(v: string): string | null {
  if (!v.trim()) return null;
  let u: URL;
  try { u = new URL(v.trim()); } catch { return "That is not a URL."; }
  const local = ["localhost", "127.0.0.1", "[::1]"].includes(u.hostname);
  if (u.protocol !== "https:" && !(u.protocol === "http:" && local)) return "Use https:// (http:// only for localhost).";
  if (u.search || u.hash) return "Give the base URL only, without ? or #.";
  return null;
}

function consentPanel(r: Report): HTMLElement {
  const parsed = parseProof(proofBytes!);
  const plan = h("pre", { class: "plan", id: "plan", tabindex: "0", "aria-label": "URLs that will be requested" });
  const err = h("p", { class: "note bad", id: "custom-err" });
  const go = h("button", { type: "button", class: "primary", id: "ask" }, ledgerServers ? "Ask again" : "Ask these servers");
  const refresh = () => {
    const e = customError(customBase);
    err.textContent = e ?? "";
    const servers = chosenServers();
    go.toggleAttribute("disabled", !!e || servers.length === 0 || !parsed.ok);
    plan.textContent = parsed.ok && !e && servers.length ? ledgerPlan(parsed.proof, servers).map((p) => p.url).join("\n") : "";
  };
  const boxes = DEFAULT_SERVERS.map((d) => {
    const cb = h("input", { type: "checkbox", checked: !disabledDefaults.has(d.name) }) as HTMLInputElement;
    cb.addEventListener("change", () => { cb.checked ? disabledDefaults.delete(d.name) : disabledDefaults.add(d.name); refresh(); });
    return h("label", { class: "check" }, cb, h("span", null, d.name, " ", mono(d.base)));
  });
  const custom = h("input", { type: "url", id: "custom", placeholder: "https://esplora.example.org/api", value: customBase, spellcheck: "false", autocomplete: "off", "aria-describedby": "custom-err" }) as HTMLInputElement;
  custom.addEventListener("input", () => { customBase = custom.value; refresh(); });
  go.addEventListener("click", () => { lastFocus = "h-ledger"; ledgerServers = chosenServers(); live("Asking the explorers…"); schedule(); });
  refresh();
  return h("div", { class: "consent" },
    h("h4", null, "Check the chain"),
    h("p", null, "Steps 1–3 ran entirely in this tab. To see that the final digest really sits in a Bitcoin block, the page can ask block explorers. It sends only a block height, a block hash and a transaction id — public data. Your file, its hash and the proof are never sent. The explorers will see your IP address."),
    h("fieldset", null, h("legend", null, "Ask these explorers"), ...boxes,
      h("label", { class: "custom" }, h("span", null, "Your own Esplora server (optional)"), custom), err,
      h("p", { class: "note" }, "Two servers that give the same answer are better than one; with a single server there is nothing to compare.")),
    h("p", { class: "plabel" }, "The page will request exactly these URLs (GET only; {block_hash} is replaced by the first answer):"),
    plan, go);
}

function actions(r: Report): HTMLElement {
  const copy = async (text: string, what: string) => {
    try { await navigator.clipboard.writeText(text); }
    catch {
      const t = h("textarea", { "aria-hidden": "true" }) as HTMLTextAreaElement; t.value = text; document.body.append(t); t.select();
      try { document.execCommand("copy"); } catch { /* the live message below still tells the truth */ }
      t.remove();
    }
    live(what + " copied.");
  };
  const jsonText = () => canonicalJson(r) + "\n";
  const hopsBox = h("input", { type: "checkbox", checked: showHops }) as HTMLInputElement;
  hopsBox.addEventListener("change", () => { showHops = hopsBox.checked; lastFocus = null; render(); });
  return h("div", { class: "actions", role: "group", "aria-label": "Report" },
    h("button", { type: "button", onclick: () => copy(renderText(r, showHops), "Text report") }, "Copy report"),
    h("button", { type: "button", onclick: () => {
      const a = h("a", { href: URL.createObjectURL(new Blob([jsonText()], { type: "application/json" })), download: "ots-report.json" });
      document.body.append(a); a.click(); a.remove(); live("JSON report downloaded.");
    } }, "Download JSON"),
    h("button", { type: "button", onclick: () => window.print() }, "Print"),
    upgraded && h("button", { type: "button", onclick: () => { download(upgraded!, proofFileName(), "application/octet-stream"); live("Upgraded proof downloaded."); } }, "Download upgraded .ots"),
    h("label", { class: "check inline" }, hopsBox, h("span", null, "Show every hop")));
}

function sharePanel(r: Report): HTMLElement | null {
  if (!proofBytes || !r.input.digest) return null;
  const base = location.href.replace(/[#?].*$/, "");
  const out = h("input", { type: "text", readonly: "", id: "link", "aria-label": "Permalink" }) as HTMLInputElement;
  const purl = h("input", { type: "url", id: "purl", placeholder: "https://example.org/report.txt.ots", spellcheck: "false" }) as HTMLInputElement;
  const upd = () => { out.value = encodePermalink(base, { digestHex: r.input.digest, ots: proofBytes, proofUrl: purl.value.trim() || null }); };
  purl.addEventListener("input", upd); upd();
  return h("details", { class: "share" }, h("summary", null, "Link to this check"),
    h("p", null, "The link carries the file's hash and the proof — not the file — after the #, which browsers never send to a server. Anyone who opens it sees the same five steps."),
    location.protocol === "file:" && h("p", { class: "note" }, "You are running the page from a local file, so this link only works on this computer. Host the page to share it."),
    h("label", { class: "custom" }, h("span", null, "Where the proof is hosted (optional, adds ?proof=…; fetched only after a click)"), purl),
    h("div", { class: "linkrow" }, out, h("button", { type: "button", onclick: () => { out.select(); void navigator.clipboard?.writeText(out.value).catch(() => document.execCommand("copy")); live("Link copied."); } }, "Copy link")));
}

function render(): void {
  const root = $("result");
  root.textContent = "";
  root.hidden = !report;
  if (!report) return;
  const r = report;
  root.append(verdictBanner(r), actions(r), h("ol", { class: "steps" }, ...r.steps.map((_, i) => stepCard(r, i))));
  const share = sharePanel(r);
  if (share) root.append(share);
  if (lastFocus) { document.getElementById(lastFocus)?.focus(); lastFocus = null; }
}

// ------------------------------------------------------------------ link loading

async function fetchProofFromLink(): Promise<void> {
  const url = proofUrlFromLink!;
  live("Fetching the proof…");
  try {
    const u = new URL(url);
    if (u.protocol !== "https:" && !(u.protocol === "http:" && ["localhost", "127.0.0.1"].includes(u.hostname))) throw new Error("only https:// addresses are fetched");
    const ctl = new AbortController(); const t = setTimeout(() => ctl.abort(), 15000);
    const resp = await fetch(url, { cache: "no-store", credentials: "omit", referrerPolicy: "no-referrer", signal: ctl.signal });
    clearTimeout(t);
    if (!resp.ok) throw new Error("the server answered " + resp.status);
    const buf = new Uint8Array(await resp.arrayBuffer());
    if (buf.length > MAX_PROOF) throw new Error("the answer is too big for a proof");
    proofBytes = buf; proofLabel = u.pathname.split("/").pop() || u.host;
    ledgerServers = null;
    $("link-note").hidden = true;
    showChosen(); schedule();
  } catch (e) {
    live("Could not fetch the proof: " + (e instanceof Error ? e.message : String(e)) + ". The server may not allow other pages to read it; download it and pick it above instead.");
  }
}

function loadFromLink(): void {
  const d = decodePermalink(location.href);
  if (d.digestHex) ($("digest") as HTMLInputElement).value = d.digestHex;
  if (d.ots) { proofBytes = d.ots; proofLabel = "proof from the link"; }
  if (d.proofUrl && !d.ots) {
    proofUrlFromLink = d.proofUrl;
    $("link-url").textContent = d.proofUrl;
    $("link-note").hidden = false;
  }
  showChosen();
  if (proofBytes) schedule(); else guide();
}


// ------------------------------------------------------------------ stamping

function calendarList(): string[] {
  const l = DEFAULT_CALENDARS.filter((c) => !stamp.disabled.has(c));
  const c = stamp.custom.trim().replace(/\/+$/, "");
  return c ? [...l, c] : l;
}

function renderStamp(): void {
  const out = $("stamp-out");
  out.textContent = "";
  $("sfile-name").textContent = stamp.file ? `${stamp.file.name}, ${sizeText(stamp.file.size)}` : stamp.digest ? "a pasted hash" : "";
  $("drop-sfile").classList.toggle("has", !!stamp.digest);
  if (!stamp.digest) return;
  const digest = stamp.digest;
  if (!stamp.nonce) stamp.nonce = crypto.getRandomValues(new Uint8Array(16));
  const nonce = stamp.nonce;
  const commitment = hex(commitmentFor(digest, nonce));

  const plan = h("pre", { class: "plan", id: "splan", tabindex: "0", "aria-label": "Requests that will be made" });
  const err = h("p", { class: "note bad", id: "scustom-err" });
  const go = h("button", { type: "button", class: "primary", id: "send" }, stamp.bytes ? "Send again with a new random number" : "Send to the calendars");
  const refresh = () => {
    const e = customError(stamp.custom);
    err.textContent = e ?? "";
    const cals = calendarList();
    go.toggleAttribute("disabled", !!e || !cals.length || stamp.busy);
    plan.textContent = e ? "" : cals.map((c) => `POST ${c}/digest\n     body: ${commitment}`).join("\n");
  };
  const boxes = DEFAULT_CALENDARS.map((c) => {
    const cb = h("input", { type: "checkbox", checked: !stamp.disabled.has(c) }) as HTMLInputElement;
    cb.addEventListener("change", () => { cb.checked ? stamp.disabled.delete(c) : stamp.disabled.add(c); refresh(); });
    return h("label", { class: "check" }, cb, h("span", null, mono(c)));
  });
  const custom = h("input", { type: "url", id: "scustom", placeholder: "https://calendar.example.org", value: stamp.custom, spellcheck: "false", autocomplete: "off", "aria-describedby": "scustom-err" }) as HTMLInputElement;
  custom.addEventListener("input", () => { stamp.custom = custom.value; refresh(); });
  go.addEventListener("click", () => void sendStamp());

  out.append(
    h("section", { class: "card" }, h("h3", null, "1. The file's fingerprint"),
      h("p", { class: "meta" }, "SHA-256", mono(hex(digest)))),
    h("section", { class: "card", "aria-labelledby": "h-ask" }, h("h3", { id: "h-ask", tabindex: "-1" }, "2. Ask the calendars"),
      h("p", null, "A calendar is a free public server that collects many commitments and writes one of them into a Bitcoin transaction every few hours. You will send it a ", h("em", null, "commitment"), ": the SHA-256 of your file's hash plus a random 16-byte number that stays inside your .ots. The file, its hash and the random number are not sent, so the calendar learns nothing about the file."),
      h("fieldset", null, h("legend", null, "Ask these calendars"), ...boxes,
        h("label", { class: "custom" }, h("span", null, "Another calendar (optional)"), custom), err,
        h("p", { class: "note" }, "A browser can only read an answer from a calendar that allows it. If every one fails here, the command-line script does the same job without that limit.")),
      h("p", { class: "msg", id: "s-privacy" }, "Nothing has been sent yet. The button sends the calendars you ticked only the 32-byte commitment below, made from this hash and a random number. The file never leaves this computer, and not even its hash is sent."),
      h("p", { class: "plabel" }, "The page will make exactly these requests:"), plan, go),
  );
  refresh();
  if (stamp.bytes || stamp.log.length) out.append(stampResult());
}

function stampResult(): HTMLElement {
  const name = (stamp.file?.name ?? hex(stamp.digest!).slice(0, 12)) + ".ots";
  const card = h("section", { class: "card", "aria-labelledby": "h-sres" }, h("h3", { id: "h-sres", tabindex: "-1" }, "3. The proof"),
    h("ul", { class: "log" }, ...stamp.log.map((l) => h("li", { class: /accepted/.test(l) ? "ok" : "no" }, l))));
  if (stamp.bytes) {
    const bytes = stamp.bytes;
    card.append(
      h("p", { class: "msg" }, `Done: ${name} (${bytes.length} bytes). It is pending.`),
      h("p", null, "Pending means the calendars have promised, not yet written it to Bitcoin. Keep the .ots next to the file. In a few hours, open \"Check a proof\", load the .ots and press \"Ask the calendar\" to add the Bitcoin path; then the verdict can turn green."),
      h("div", { class: "actions" },
        h("button", { type: "button", class: "primary", onclick: () => { download(bytes, name, "application/octet-stream"); live(name + " downloaded."); } }, "Download the .ots"),
        h("button", { type: "button", onclick: () => openInChecker(bytes, name) }, "Open it in the checker")));
  } else {
    card.append(h("p", { class: "msg" }, "No calendar accepted the commitment."), h("p", { class: "note" }, "Check the connection, try another calendar, or use python/ots_stamp.py, which is not limited by what a browser may read."));
  }
  return card;
}

async function sendStamp(): Promise<void> {
  if (!stamp.digest || stamp.busy) return;
  stamp.busy = true; stamp.log = []; stamp.bytes = null;
  live("Asking the calendars…"); $("busy").hidden = false;
  try { stamp.bytes = await stampDigest(stamp.digest, calendarList(), calendarCall, stamp.nonce!, (l) => stamp.log.push(l)); }
  catch (e) { stamp.log.push(e instanceof Error ? e.message : String(e)); }
  stamp.busy = false; $("busy").hidden = true;
  const keep = stamp.bytes;
  if (keep) stamp.nonce = null; // this nonce now lives in the proof; the next send (and the plan shown for it) gets a fresh one
  renderStamp();
  live(keep ? "Done: a pending proof is ready to download." : "No calendar accepted the commitment.");
  document.getElementById("h-sres")?.focus();
}

async function setStampFile(f: File): Promise<void> {
  stamp.file = f; stamp.bytes = null; stamp.log = []; stamp.nonce = null; stamp.digest = null; renderStamp();
  ($("sdigest") as HTMLInputElement).value = "";
  live(`Hashing ${f.name}…`); $("busy").hidden = false;
  try {
    stamp.digest = await fileFromBlob(f, (done, total) => {
      const p = $("progress") as HTMLProgressElement; p.hidden = false; p.max = total; p.value = done;
    }).digest("sha256");
  } finally { ($("progress") as HTMLProgressElement).hidden = true; $("busy").hidden = true; }
  renderStamp();
  live("Hashed. Now choose which calendars to ask.");
}

function openInChecker(bytes: Uint8Array, name: string): void {
  proofBytes = bytes; proofLabel = name; ledgerServers = null; upgraded = null; upgradeLog = [];
  if (stamp.file) { setFile(stamp.file); } else if (stamp.digest) { file = null; ($("digest") as HTMLInputElement).value = hex(stamp.digest); }
  setMode("check"); showChosen(); schedule();
}

function setMode(m: Mode, focus = false): void {
  mode = m;
  for (const k of ["check", "stamp"] as const) {
    const on = k === m;
    $("tab-" + k).setAttribute("aria-selected", String(on));
    $("tab-" + k).setAttribute("tabindex", on ? "0" : "-1");
    $("view-" + k).hidden = !on;
  }
  if (focus) $("tab-" + m).focus();
  live(m === "check" ? "Check a proof." : "Stamp a file.");
  if (m === "stamp") renderStamp();
}

// ------------------------------------------------------------------ theme and wiring

function applyTheme(t: string): void {
  if (t === "light" || t === "dark") document.documentElement.setAttribute("data-theme", t); else document.documentElement.removeAttribute("data-theme");
  $("theme").textContent = "Theme: " + t;
}

function init(): void {
  $("version").textContent = __VERSION__;
  let theme = "auto";
  try { theme = localStorage.getItem("ots-theme") || "auto"; } catch { /* storage may be blocked */ }
  applyTheme(theme);
  $("theme").addEventListener("click", () => {
    theme = theme === "auto" ? "light" : theme === "light" ? "dark" : "auto";
    applyTheme(theme);
    try { localStorage.setItem("ots-theme", theme); } catch { /* fine */ }
  });
  $("file").addEventListener("change", (e) => { const f = (e.target as HTMLInputElement).files?.[0] ?? null; setFile(f); showChosen(); schedule(); });
  $("proof").addEventListener("change", async (e) => { const f = (e.target as HTMLInputElement).files?.[0]; if (f) { await setProofFile(f); showChosen(); schedule(); } });
  hintNodes = [...$("input-msg").childNodes].map((n) => n.cloneNode(true));
  const digestField = $("digest") as HTMLInputElement, proofField = $("proofhex") as HTMLTextAreaElement;
  let t: number | undefined;
  const soon = () => { clearTimeout(t); t = window.setTimeout(schedule, 250); };
  digestField.addEventListener("input", () => {
    file = null; ($("file") as HTMLInputElement).value = ""; ledgerServers = null;
    const p = classify(digestField.value);
    if (p.kind === "proof") { // a proof pasted into the hash box: put it where it belongs
      setPastedProof(p.bytes); proofField.value = digestField.value.trim(); digestField.value = "";
      moveNote = "That was a proof, not a hash, so it went into the proof box.";
    }
    showChosen(); soon();
  });
  proofField.addEventListener("input", () => {
    const p = classify(proofField.value);
    proofPasteError = null;
    if (p.kind === "proof") { setPastedProof(p.bytes); ($("proof") as HTMLInputElement).value = ""; }
    else {
      if (proofLabel === PASTED) { proofBytes = null; proofLabel = ""; ledgerServers = null; }
      if (p.kind === "digest") { // a hash pasted into the proof box
        proofField.value = ""; digestField.value = p.hex; file = null; ($("file") as HTMLInputElement).value = "";
        moveNote = "That was a file's hash, not a proof, so it went into the hash box.";
      } else if (p.kind === "bad") proofPasteError = p.why;
    }
    showChosen(); soon();
  });
  $("explain").addEventListener("click", () => { clearTimeout(t); schedule(); });
  $("stamp-this").addEventListener("click", () => {
    const hx = ($("stamp-this") as HTMLButtonElement).dataset.hex;
    if (!hx) return;
    setMode("stamp");
    const sd = $("sdigest") as HTMLInputElement;
    sd.value = hx; sd.dispatchEvent(new Event("input"));
    document.getElementById("h-ask")?.focus();
  });
  document.addEventListener("paste", (e) => { // a paste anywhere outside a field goes to the box it belongs in
    if (mode !== "check" || (e.target as HTMLElement | null)?.closest?.("input, textarea")) return;
    const text = e.clipboardData?.getData("text") ?? "";
    const p = classify(text);
    if (p.kind === "empty") return;
    e.preventDefault();
    const field = p.kind === "proof" ? proofField : digestField;
    field.value = text.trim(); field.dispatchEvent(new Event("input"));
  });
  for (const m of ["check", "stamp"] as const) {
    $("tab-" + m).addEventListener("click", () => setMode(m));
    $("tab-" + m).addEventListener("keydown", (e) => {
      const k = (e as KeyboardEvent).key;
      if (k === "ArrowRight" || k === "ArrowLeft" || k === "Home" || k === "End") { e.preventDefault(); setMode(k === "ArrowRight" || k === "End" ? "stamp" : "check", true); }
    });
  }
  $("sfile").addEventListener("change", (e) => { const f = (e.target as HTMLInputElement).files?.[0]; if (f) void setStampFile(f); });
  $("sdigest").addEventListener("input", () => {
    const v = ($("sdigest") as HTMLInputElement).value.trim().toLowerCase();
    stamp.file = null; ($("sfile") as HTMLInputElement).value = ""; stamp.bytes = null; stamp.log = []; stamp.nonce = null;
    stamp.digest = v.length === 64 && isHex(v) ? fromHex(v) : null;
    renderStamp();
  });
  $("fetch-proof").addEventListener("click", () => void fetchProofFromLink());
  let depth = 0;
  window.addEventListener("dragenter", (e) => { e.preventDefault(); depth++; document.body.classList.add("dragging"); });
  window.addEventListener("dragleave", () => { if (--depth <= 0) { depth = 0; document.body.classList.remove("dragging"); } });
  window.addEventListener("dragover", (e) => e.preventDefault());
  window.addEventListener("drop", (e) => { e.preventDefault(); depth = 0; document.body.classList.remove("dragging"); void accept([...(e.dataTransfer?.files ?? [])]); });
  window.addEventListener("beforeprint", () => document.querySelectorAll("details").forEach((d) => d.setAttribute("open", "")));
  loadFromLink();
}

init();

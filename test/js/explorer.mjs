// In-memory Esplora servers for ledger tests: mine tiny blocks around a proof's merkle roots.
import { core, H, cat } from "./helper.mjs";

export function mineHeader({ merkleRoot, time = 1500000000, bits = 0x207fffff, prev = new Uint8Array(32).fill(1), version = 0x20000000 }) {
  const h = new Uint8Array(80);
  const dv = new DataView(h.buffer);
  dv.setUint32(0, version, true);
  h.set(prev, 4);
  h.set(merkleRoot, 36);
  dv.setUint32(68, time, true);
  dv.setUint32(72, bits, true);
  for (let nonce = 0; nonce < 1 << 22; nonce++) {
    dv.setUint32(76, nonce, true);
    if (core.meetsPow(h)) return h;
  }
  throw new Error("could not mine");
}

export const hashOf = (header) => core.hex(core.blockHashOf(header));

/**
 * files: map from path (e.g. "block-height/10") to body string.
 * addBlock registers the four kinds of resource for one block.
 */
export class Explorer {
  constructor() {
    this.files = new Map();
  }
  addBlock({ height, header, txids = [], txs = {} }) {
    const hash = hashOf(header);
    this.files.set(`block-height/${height}`, hash);
    this.files.set(`block/${hash}/header`, core.hex(header));
    this.files.set(`block/${hash}/txids`, JSON.stringify(txids));
    for (const [txid, hexBody] of Object.entries(txs)) this.files.set(`tx/${txid}/hex`, hexBody);
    return hash;
  }
  set(path, body) {
    this.files.set(path, body);
    return this;
  }
  delete(path) {
    this.files.delete(path);
    return this;
  }
  /** fetchText for base "mem://<name>" */
  fetcher(name, log) {
    const prefix = `mem://${name}/`;
    return (url) => {
      if (log) log.push(url);
      if (!url.startsWith(prefix)) return Promise.reject(new Error("wrong server " + url));
      const body = this.files.get(url.slice(prefix.length));
      return Promise.resolve(body === undefined ? { status: 404, body: "Not Found" } : { status: 200, body });
    };
  }
}

/** Route different bases to different explorers. */
export function router(map, log) {
  return (url) => {
    if (log) log.push(url);
    for (const [prefix, fn] of Object.entries(map)) if (url.startsWith(prefix)) return fn(url);
    return Promise.reject(new Error("no route " + url));
  };
}

/**
 * A proof with a handcrafted transaction around the digest. Returns the proof bytes, the txid and tx.
 * `merklePath` is a list of extra ops after the txid hash; the final root is the message the block must carry.
 */
export function makeProof({ digest = new Uint8Array(32).fill(0x11), txOutScript, heights, inInput = false, tail = [] } = {}) {
  const cs = (n) => Uint8Array.of(n);
  const input = (s) => cat(new Uint8Array(32).fill(9), "00000000", cs(s.length), s, "ffffffff");
  const script = txOutScript ?? cat("6a20", digest);
  const ins = inInput ? [input(cat("51", digest))] : [input(new Uint8Array(0))];
  const outs = inInput ? [cat("0000000000000000", cs(1), "51")] : [cat("0000000000000000", cs(script.length), script)];
  const tx = cat("01000000", "01", ...ins, "01", ...outs, "00000000");
  const at = core.indexOfBytes(tx, digest);
  const pre = tx.subarray(0, at), post = tx.subarray(at + digest.length);
  return { tx, pre, post, digest, txid: core.hex(core.reversed(core.sha256d(tx))) };
}

// A tiny client for the ots-explain REST API (python/ots_api.py). Plain ES module, no dependencies; works in
// browsers and Node >= 18 (global fetch). The API takes digests, so hash the file first (see sha256Hex).
//
//   import { OtsApi, sha256Hex } from "./ots-api.mjs";
//   const api = new OtsApi("http://127.0.0.1:8787");
//   const report = await api.verify({ proof: otsBytes, digest: await sha256Hex(fileBytes) });
//   report.verdict.status   // "PASS" | "FAIL" | "SKIP"

export class OtsApiError extends Error {
  constructor(status, code, message) { super(message); this.name = "OtsApiError"; this.status = status; this.code = code; }
}

const toB64 = (u8) => { let s = ""; for (let i = 0; i < u8.length; i += 0x8000) s += String.fromCharCode(...u8.subarray(i, i + 0x8000)); return btoa(s); };
const fromB64 = (b) => Uint8Array.from(atob(b), (c) => c.charCodeAt(0));

/** SHA-256 of bytes as lowercase hex (WebCrypto: browsers and Node >= 18). For big files hash in chunks yourself. */
export async function sha256Hex(bytes) {
  const d = new Uint8Array(await crypto.subtle.digest("SHA-256", bytes));
  return Array.from(d, (x) => x.toString(16).padStart(2, "0")).join("");
}

export class OtsApi {
  constructor(baseUrl = "http://127.0.0.1:8787", { token = null, fetch: f = globalThis.fetch } = {}) {
    this.base = baseUrl.replace(/\/+$/, ""); this.token = token; this.f = f;
  }
  async #call(method, path, body, raw) {
    const headers = { Accept: "application/json" };
    if (body !== undefined) headers["Content-Type"] = "application/json";
    if (this.token) headers.Authorization = "Bearer " + this.token;
    const r = await this.f(this.base + path, { method, headers, body: body === undefined ? undefined : JSON.stringify(body) });
    const text = await r.text();
    if (raw) return { status: r.status, text, headers: r.headers };
    let obj; try { obj = JSON.parse(text); } catch { throw new OtsApiError(r.status, "bad_response", "the server did not answer JSON"); }
    if (!r.ok) throw new OtsApiError(r.status, obj.error?.code ?? "error", obj.error?.message ?? text);
    return obj;
  }
  health() { return this.#call("GET", "/v1/health"); }
  /** proof: Uint8Array of the .ots; digest: hex (optional); ledger: true or {servers:[url,...]} (needs a server with --allow-network) */
  verify({ proof, digest, ledger, steps } = {}) {
    return this.#call("POST", "/v1/verify", { proof_b64: toB64(proof), ...(digest ? { digest } : {}), ...(ledger ? { ledger } : {}), ...(steps ? { steps } : {}) });
  }
  async verifyText({ proof, digest, ledger, steps } = {}) {
    const r = await this.#call("POST", "/v1/verify", { proof_b64: toB64(proof), format: "text", ...(digest ? { digest } : {}), ...(ledger ? { ledger } : {}), ...(steps ? { steps } : {}) }, true);
    if (r.status !== 200) throw new OtsApiError(r.status, "error", r.text);
    return r.text;
  }
  async stamp({ digest, calendars } = {}) {
    const r = await this.#call("POST", "/v1/stamp", { digest, ...(calendars ? { calendars } : {}) });
    return { proof: fromB64(r.proof_b64), status: r.status, log: r.log };
  }
  async upgrade({ proof } = {}) {
    const r = await this.#call("POST", "/v1/upgrade", { proof_b64: toB64(proof) });
    return { proof: fromB64(r.proof_b64), changed: r.changed, status: r.status, log: r.log };
  }
  async permalink({ digest, proof, base, proofUrl } = {}) {
    return (await this.#call("POST", "/v1/permalink", { digest, proof_b64: toB64(proof), base, ...(proofUrl ? { proof_url: proofUrl } : {}) })).url;
  }
  async decodePermalink(url) {
    const r = await this.#call("POST", "/v1/permalink/decode", { url });
    return { digest: r.digest, proof: r.proof_b64 === null ? null : fromB64(r.proof_b64), proofUrl: r.proof_url };
  }
}

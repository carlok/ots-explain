// A fake fetchText serving files from vectors/explorer/<scenario>/<path>.
// URL form: mock://<scenario>/<path>. A missing file answers 404.
import { readFileSync } from "node:fs";
import { join } from "node:path";
import { VECTORS } from "./helper.mjs";

export function fileFetch({ log, overrides = {} } = {}) {
  return async (url) => {
    if (log) log.push(url);
    for (const [prefix, fn] of Object.entries(overrides)) {
      if (url.includes(prefix)) {
        const r = await fn(url);
        if (r !== undefined) return r;
      }
    }
    const m = /^mock:\/\/([^/]+)\/(.*)$/.exec(url);
    if (!m) throw new Error("unsupported url " + url);
    try {
      return { status: 200, body: readFileSync(join(VECTORS, "explorer", m[1], m[2]), "utf8") };
    } catch {
      return { status: 404, body: "not found" };
    }
  };
}

export const MOCK2 = [
  { name: "blockstream.info", base: "mock://synthetic" },
  { name: "mempool.space", base: "mock://synthetic" },
];

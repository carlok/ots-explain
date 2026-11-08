// The JS client against a real python/ots_api.py process (and the mock calendar + explorer for the network parts).
import test from "node:test";
import assert from "node:assert/strict";
import { spawn } from "node:child_process";
import { readFileSync } from "node:fs";
import { createInterface } from "node:readline";
import { join } from "node:path";
import { ROOT } from "./helper.mjs";
import { OtsApi, OtsApiError, sha256Hex } from "../../clients/js/ots-api.mjs";

const env = { ...process.env, no_proxy: "127.0.0.1,localhost", NO_PROXY: "127.0.0.1,localhost" };
const procs = [];
function start(args) {
  const p = spawn("python3", args, { env, cwd: ROOT, stdio: ["ignore", "pipe", "inherit"] });
  procs.push(p);
  return new Promise((res, rej) => {
    const rl = createInterface({ input: p.stdout });
    rl.once("line", (l) => res({ p, line: l }));
    p.once("exit", (c) => rej(new Error("exited early " + c)));
  });
}
test.after(() => procs.forEach((p) => p.kill()));

const hw = (f) => new Uint8Array(readFileSync(join(ROOT, "vectors", "hello-world", f)));

test("offline: health, verify, text, permalink, errors", async () => {
  const { line } = await start(["python/ots_api.py", "--port", "0"]);
  const base = /http:\/\/[\d.]+:\d+/.exec(line)[0];
  const api = new OtsApi(base);
  assert.equal((await api.health()).network, false);
  const proof = hw("proof.ots"), digest = await sha256Hex(hw("data.bin"));
  const rep = await api.verify({ proof, digest });
  assert.deepEqual(rep.steps.slice(0, 3).map((s) => s.status), ["PASS", "PASS", "PASS"]);
  assert.match(await api.verifyText({ proof, digest }), /Proof structure/);
  const url = await api.permalink({ digest, proof, base: "https://example.org/" });
  const d = await api.decodePermalink(url);
  assert.equal(d.digest, digest);
  assert.deepEqual(d.proof, proof);
  await assert.rejects(api.stamp({ digest }), (e) => e instanceof OtsApiError && e.code === "network_disabled" && e.status === 403);
  const bad = await api.verify({ proof: new Uint8Array([1, 2, 3]) });
  assert.equal(bad.verdict.status, "FAIL");
});

test("token is sent and enforced", async () => {
  const { line } = await start(["python/ots_api.py", "--port", "0", "--token", "t0k"]);
  const base = /http:\/\/[\d.]+:\d+/.exec(line)[0];
  await assert.rejects(new OtsApi(base).verify({ proof: hw("proof.ots") }), (e) => e.status === 401);
  assert.equal((await new OtsApi(base, { token: "t0k" }).verify({ proof: hw("proof.ots") })).input.mode, "none");
});

test("network: stamp, upgrade and verify through the API against the mocks", async () => {
  const { line } = await start(["test/mock_calendar.py"]);
  const m = JSON.parse(line);
  const { line: l2 } = await start(["python/ots_api.py", "--port", "0", "--allow-network", "--calendar-allow", m.calendar, "--esplora-allow", m.esplora]);
  const api = new OtsApi(/http:\/\/[\d.]+:\d+/.exec(l2)[0]);
  const digest = await sha256Hex(new TextEncoder().encode("js client file"));
  const st = await api.stamp({ digest, calendars: [m.calendar] });
  assert.equal(st.status, "pending");
  assert.ok(st.proof instanceof Uint8Array);
  assert.equal((await api.upgrade({ proof: st.proof })).changed, false);
  await fetch(m.calendar + "/__ready", { method: "POST" });
  const up = await api.upgrade({ proof: st.proof });
  assert.equal(up.status, "complete");
  const rep = await api.verify({ proof: up.proof, digest, ledger: { servers: [m.esplora] } });
  assert.deepEqual(rep.steps.map((s) => s.status), Array(5).fill("PASS"));
  await assert.rejects(api.stamp({ digest, calendars: ["http://169.254.169.254"] }), (e) => e.code === "calendar_not_allowed");
});

// Headless-Chrome smoke test of dist/index.html, opened from file:// like a person would.
//   node test/browser/smoke.mjs [--shots DIR]        (needs Chrome/Chromium + the `playwright` package; skips if absent)
// It checks: no network before consent, five steps, mismatch handling, the ledger run against the mock
// explorer, keyboard operation, live region, CSP, themes, print, permalink round trip, ?proof= click-to-fetch,
// and that the JSON the page produces is byte-identical to python/verify_ots.py --json.
import { spawn, spawnSync } from "node:child_process";
import { createHash } from "node:crypto";
import { createRequire } from "node:module";
import { mkdirSync, readFileSync, writeFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";

const root = join(dirname(fileURLToPath(import.meta.url)), "..", "..");
const shots = process.argv.includes("--shots") ? process.argv[process.argv.indexOf("--shots") + 1] : null;
if (shots) mkdirSync(shots, { recursive: true });
const require = createRequire(import.meta.url);
let chromium;
const engine = process.env.OTS_BROWSER || "chromium"; // chromium | firefox | webkit
try { chromium = require("playwright")[engine]; } catch { console.log("SKIP: playwright is not installed"); process.exit(0); }

let passed = 0, failed = 0;
const check = (ok, name, extra = "") => { if (ok) passed++; else { failed++; console.log("FAIL:", name, extra); } };

// ---- mock explorer
const mock = spawn("python3", [join(root, "test/mock_esplora.py"), "--port", "0"], { stdio: ["ignore", "pipe", "inherit"] });
const port = await new Promise((res, rej) => {
  let buf = ""; mock.stdout.on("data", (d) => { buf += d; const m = buf.match(/127\.0\.0\.1:(\d+)/); if (m) res(+m[1]); });
  mock.on("exit", () => rej(new Error("mock exited")));
  setTimeout(() => rej(new Error("mock did not start")), 8000);
});
const base = `http://127.0.0.1:${port}/synthetic`;
const calProc = spawn("python3", [join(root, "test/mock_calendar.py")], { stdio: ["ignore", "pipe", "inherit"] });
const cal = await new Promise((res, rej) => { let b = ""; calProc.stdout.on("data", (d) => { b += d; if (b.includes("\n")) res(JSON.parse(b)); }); setTimeout(() => rej(new Error("mock calendar did not start")), 8000); });
const page_url = pathToFileURL(join(root, "dist/index.html")).href;
const V = (id, f) => join(root, "vectors", id, f);

const browser = await chromium.launch();
const ctx = await browser.newContext({ acceptDownloads: true, viewport: { width: 1000, height: 900 } });
const page = await ctx.newPage();
const requests = [], posts = [], consoleMsgs = [];
ctx.on("request", (r) => { if (!r.url().startsWith("file:") && !r.url().startsWith("data:")) { requests.push(r.url()); if (r.method() === "POST") posts.push({ url: r.url(), body: r.postDataBuffer() }); } });
page.on("console", (m) => consoleMsgs.push(m.text()));
page.on("pageerror", (e) => consoleMsgs.push("PAGEERROR " + e.message));

try {
  await page.goto(page_url);
  check((await page.title()).includes("ots-explain"), "title");
  const csp = await page.getAttribute('meta[http-equiv="Content-Security-Policy"]', "content");
  check(/default-src 'none'/.test(csp) && !/unsafe-/.test(csp), "CSP is strict (no unsafe-*)", csp);

  // keyboard: Tab order reaches the file inputs, and they show a focus ring on their label
  for (let i = 0; i < 4; i++) await page.keyboard.press("Tab"); // skip link, theme, the active tab, then the file input
  check(await page.evaluate(() => document.activeElement?.id) === "file", "Tab reaches the file input (4th stop)");
  check(await page.evaluate(() => getComputedStyle(document.getElementById("drop-file")).outlineStyle) !== "none", "focus ring on the drop zone");

  // 1. file + proof: steps 1-3 pass, no network
  await page.setInputFiles("#file", V("hello-world", "data.bin"));
  await page.setInputFiles("#proof", V("hello-world", "proof.ots"));
  await page.waitForSelector("#result .steps");
  const stepsText = await page.$$eval("#result .step", (els) => els.map((e) => [e.id, e.className.replace("step ", "")]));
  check(stepsText.length === 5, "five steps", JSON.stringify(stepsText));
  check(JSON.stringify(stepsText.map((s) => s[1])) === JSON.stringify(["PASS", "PASS", "PASS", "SKIP", "SKIP"]), "statuses PASS PASS PASS SKIP SKIP", JSON.stringify(stepsText));
  check((await page.textContent("#verdict-title")).startsWith("Not proven yet"), "offline verdict is 'Not proven yet', never green");
  check(requests.length === 0, "no network request before consent", requests.join(","));
  check(/Verdict/.test(await page.textContent("#live")), "live region announces the verdict", await page.textContent("#live"));
  check(await page.$eval("#plan", (e) => e.textContent.includes("blockstream.info/api/block-height/358391")), "plan lists the default URLs first");
  if (shots) await page.screenshot({ path: join(shots, "1-offline.png"), fullPage: true });

  // 2. wrong file -> FAIL on step 1
  await page.setInputFiles("#file", V("merkle1", "data.bin"));
  await page.waitForFunction(() => document.querySelector("#step-file_hash")?.classList.contains("FAIL"));
  check((await page.textContent("#verdict-title")).startsWith("A check failed"), "mismatch gives a failure verdict");
  check(await page.$eval("#step-hash_steps", (e) => e.classList.contains("SKIP")), "hash steps are skipped when not tied to the input");
  await page.setInputFiles("#file", V("hello-world", "data.bin"));
  await page.waitForFunction(() => document.querySelector("#step-file_hash")?.classList.contains("PASS"));

  // 3. ledger via keyboard against the mock
  await page.uncheck('.consent input[type="checkbox"] >> nth=0');
  await page.uncheck('.consent input[type="checkbox"] >> nth=1');
  check(await page.$eval("#ask", (b) => b.disabled), "ask button disabled with no server chosen");
  await page.fill("#custom", "ftp://nope");
  check((await page.textContent("#custom-err")).length > 0, "bad custom URL is explained");
  await page.fill("#custom", base);
  check(await page.$eval("#plan", (e, b) => e.textContent.startsWith(b + "/block-height/358391"), base), "plan shows the custom server URLs");
  await page.focus("#ask"); await page.keyboard.press("Enter");
  await page.waitForFunction(() => document.querySelector("#verdict-title")?.textContent.startsWith("Proved"), null, { timeout: 15000 });
  check(requests.length > 0 && requests.every((u) => u.startsWith(`http://127.0.0.1:${port}/`)), "only the approved server was contacted", requests.join(","));
  check(!requests.some((u) => /example|blockstream|mempool/.test(u)), "no default server was contacted when unchecked");
  check(/Proved: this existed before Bitcoin block 358391/.test(await page.textContent("#verdict-title")), "verdict text names the block");
  check(await page.evaluate(() => document.activeElement?.id) === "h-ledger", "focus moves to the ledger step after the run");
  if (shots) await page.screenshot({ path: join(shots, "2-proved.png"), fullPage: true });

  // 4. JSON from the page equals the Python script's, byte for byte
  const [dl] = await Promise.all([page.waitForEvent("download"), page.click("text=Download JSON")]);
  const pageJson = readFileSync(await dl.path(), "utf8");
  const py = spawnSync("python3", ["-I", join(root, "python/verify_ots.py"), V("hello-world", "data.bin"), V("hello-world", "proof.ots"), "--esplora", base, "--yes", "--json"], { encoding: "utf8" });
  check(py.status === 0, "python exits 0 on the same input", py.stderr);
  if (pageJson !== py.stdout && shots) { writeFileSync(join(shots, "page.json"), pageJson); writeFileSync(join(shots, "python.json"), py.stdout); }
  check(pageJson === py.stdout, "page JSON === python JSON (byte-identical)", `page ${pageJson.length} bytes, python ${py.stdout.length} bytes`);

  // 5. text report copy, hops toggle
  await page.check("text=Show every hop");
  check((await page.$$eval("details.path[open]", (e) => e.length)) >= 1, "hops expand");
  check((await page.$$eval(".hop", (e) => e.length)) > 5, "hop rows rendered");

  // 6. permalink round trip in a fresh page
  const link = await page.inputValue("#link");
  check(link.startsWith("file://") && link.includes("#h=") && link.includes("&ots="), "permalink has #h= and &ots=", link.slice(0, 120));
  const p2 = await ctx.newPage(); const before = requests.length;
  await p2.goto(link);
  await p2.waitForSelector("#result .steps");
  check(await p2.$eval("#step-file_hash", (e) => e.classList.contains("PASS")), "permalink: step 1 passes from the hash in the link");
  check(requests.length === before, "permalink load makes no request");
  await p2.close();

  // 7. ?proof= is only fetched after a click
  const p3 = await ctx.newPage(); const r0 = requests.length;
  await p3.goto(page_url + "?proof=" + encodeURIComponent(`http://127.0.0.1:${port}/proofs/hello-world`) + "#h=" + (JSON.parse(pageJson).input.digest));
  check(await p3.isVisible("#link-note"), "?proof= shows a notice");
  await p3.waitForTimeout(300);
  check(requests.length === r0, "?proof= is not fetched before the click");
  await p3.click("#fetch-proof");
  await p3.waitForSelector("#result .steps");
  check(requests.length === r0 + 1, "?proof= fetched exactly once after the click", requests.slice(r0).join(","));
  check(await p3.$eval("#step-file_hash", (e) => e.classList.contains("PASS")), "?proof= + #h= gives step 1 PASS");
  await p3.close();

  // 8. pasted digest, no file
  const p4 = await ctx.newPage();
  await p4.goto(page_url);
  await p4.setInputFiles("#proof", V("hello-world", "proof.ots"));
  await p4.fill("#digest", JSON.parse(pageJson).input.digest);
  await p4.waitForFunction(() => document.querySelector("#step-file_hash")?.classList.contains("PASS"));
  check(true, "pasted hex digest works");
  // 9. themes + print + mobile
  const bg = () => p4.evaluate(() => getComputedStyle(document.body).backgroundColor);
  const b0 = await bg(); await p4.click("#theme"); const b1 = await bg(); await p4.click("#theme"); const b2 = await bg();
  check(new Set([b0, b1, b2]).size >= 2 && b1 !== b2, "theme button changes the background", [b0, b1, b2].join(" | "));
  if (shots) { await p4.screenshot({ path: join(shots, "3-dark.png"), fullPage: true }); }
  await p4.emulateMedia({ media: "print" });
  check(await p4.$eval(".inputs", (e) => getComputedStyle(e).display === "none"), "print hides the inputs");
  if (engine === "chromium") { const pdf = await p4.pdf(); check(pdf.length > 3000, "print produces a PDF", String(pdf.length)); }
  await p4.emulateMedia({ media: "screen" });
  await p4.setViewportSize({ width: 375, height: 800 });
  check(await p4.evaluate(() => document.documentElement.scrollWidth <= window.innerWidth), "no horizontal scroll at 375 px", String(await p4.evaluate(() => document.documentElement.scrollWidth)));
  if (shots) await p4.screenshot({ path: join(shots, "4-mobile.png"), fullPage: true });
  // 9b. the donation block: plain links to the calendars' own pages, no addresses in the page, no request
  const rd = requests.length;
  const hrefs = await p4.$$eval("aside.support a", (a) => a.map((x) => [x.href, x.rel]));
  check(hrefs.length === 5 && hrefs.every(([u, r]) => u.startsWith("https://") && /noopener/.test(r)), "donation links are https and rel=noopener", JSON.stringify(hrefs));
  check(!/\b(bc1|lnbc|[13][a-km-zA-HJ-NP-Z1-9]{25,34})\w*/.test(await p4.$eval("aside.support", (e) => e.textContent)), "no wallet address or invoice is embedded in the page");
  check(requests.length === rd, "the donation block makes no request");
  // 10. CSP blocks injected inline script
  await p4.addScriptTag({ content: "window.__injected = 1" }).catch(() => {});
  check(await p4.evaluate(() => window.__injected) === undefined, "CSP blocks an injected inline script");
  await p4.close();


  // 11. stamping from the page: the file is hashed here; only a 32-byte commitment goes to the calendar
  const p5 = await ctx.newPage();
  await p5.goto(page_url);
  await p5.click("#tab-stamp");
  check(await p5.isVisible("#view-stamp") && !(await p5.isVisible("#view-check")), "stamp tab shows its own view");
  const fileBytes = readFileSync(V("hello-world", "data.bin"));
  const fileDigest = createHash("sha256").update(fileBytes).digest();
  const rs0 = requests.length;
  await p5.setInputFiles("#sfile", V("hello-world", "data.bin"));
  await p5.waitForSelector("#send");
  const plan5 = await p5.textContent("#splan");
  check(requests.length === rs0, "hashing the file for stamping makes no request");
  const commit = plan5.match(/body: ([0-9a-f]{64})/)?.[1];
  check(!!commit && commit !== fileDigest.toString("hex") && !plan5.includes(fileDigest.toString("hex")), "the plan shows a commitment that is not the file's hash", plan5);
  check(plan5.includes("blockstream") === false && plan5.includes("alice.btc.calendar.opentimestamps.org"), "plan lists the default calendars first");
  for (let i = 0; i < 3; i++) await p5.uncheck(`#view-stamp fieldset input[type=checkbox] >> nth=${i}`);
  check(await p5.$eval("#send", (b) => b.disabled), "send disabled with no calendar chosen");
  await p5.fill("#scustom", cal.calendar);
  const rs1 = requests.length, ps1 = posts.length;
  await p5.focus("#send"); await p5.keyboard.press("Enter");
  await p5.waitForSelector("text=Download the .ots", { timeout: 15000 });
  check(requests.length - rs1 === 1 && requests[requests.length - 1] === cal.calendar + "/digest", "exactly one request, to the calendar's /digest", requests.slice(rs1).join(","));
  const body = posts[ps1].body;
  check(body.length === 32 && body.toString("hex") === commit, "the POST body is the 32-byte commitment shown in the plan");
  check(!body.includes(fileDigest) && !body.includes(fileBytes), "neither the file nor its hash is in the request");
  const [dl2] = await Promise.all([p5.waitForEvent("download"), p5.click("text=Download the .ots")]);
  const otsPath = join(root, "test", "browser", ".stamped.ots");
  await dl2.saveAs(otsPath);
  const pyOff = spawnSync("python3", ["-I", join(root, "python/verify_ots.py"), V("hello-world", "data.bin"), otsPath, "--json"], { encoding: "utf8" });
  const offRep = JSON.parse(pyOff.stdout);
  check(offRep.steps.map((x) => x.status).join() === "PASS,PASS,PASS,SKIP,SKIP" && offRep.proof.attestations[0].kind === "pending", "the downloaded .ots is a valid pending proof of that file (python)", pyOff.stdout.slice(0, 200));
  if (shots) await p5.screenshot({ path: join(shots, "5-stamped.png"), fullPage: true });

  // 12. open it in the checker, upgrade before and after the 'block', then check the ledger
  await p5.click("text=Open it in the checker");
  await p5.waitForSelector("#upgrade");
  check(await p5.$eval("#step-file_hash", (e) => e.classList.contains("PASS")), "the stamped file and proof are tied in the checker");
  check((await p5.textContent("#uplan")).includes("not a calendar this page knows"), "an unknown calendar is not asked without being allowed");
  check(await p5.$eval("#upgrade", (b) => b.disabled), "upgrade disabled while no pending calendar is allowed");
  await p5.fill("#ucal", cal.calendar);
  check((await p5.textContent("#uplan")).startsWith("GET " + cal.calendar + "/timestamp/"), "upgrade plan lists the GET URL");
  await p5.click("#upgrade");
  await p5.waitForSelector("text=not confirmed yet");
  check(!(await p5.isVisible("text=Download upgraded .ots")), "no upgraded proof offered while the calendar says not yet");
  await fetch(cal.calendar + "/__ready", { method: "POST" });
  await p5.fill("#ucal", cal.calendar);
  await p5.click("#upgrade");
  await p5.waitForSelector("text=Download upgraded .ots");
  check(await p5.$eval("#step-hash_steps", (e) => e.classList.contains("PASS")), "after the upgrade the hash steps still pass");
  for (let i = 0; i < 2; i++) await p5.uncheck(`.consent input[type=checkbox] >> nth=${i}`);
  await p5.fill("#custom", cal.esplora);
  await p5.click("#ask");
  await p5.waitForFunction(() => document.querySelector("#verdict-title")?.textContent.startsWith("Proved"), null, { timeout: 15000 });
  check(true, "stamp -> upgrade -> ledger check ends in 'Proved' in the page");
  const [dl3] = await Promise.all([p5.waitForEvent("download"), p5.click("text=Download upgraded .ots")]);
  const up = join(root, "test", "browser", ".upgraded.ots"); await dl3.saveAs(up);
  const [dl4] = await Promise.all([p5.waitForEvent("download"), p5.click("text=Download JSON")]);
  const pj = readFileSync(await dl4.path(), "utf8");
  const pyOn = spawnSync("python3", ["-I", join(root, "python/verify_ots.py"), V("hello-world", "data.bin"), up, "--esplora", cal.esplora, "--yes", "--json"], { encoding: "utf8" });
  check(pyOn.status === 0 && pyOn.stdout === pj, "the page's JSON for the stamped+upgraded proof equals python's, byte for byte", `exit ${pyOn.status}`);
  await p5.close();

  // 13. hostile input: file names, ?proof= and #h= carrying markup or javascript: must stay inert text
  const p6 = await ctx.newPage(); const rh = requests.length;
  const evil = "\"><img src=x onerror=window.__x=1>";
  await p6.goto(page_url + "?proof=" + encodeURIComponent("javascript:window.__x=1//" + evil) + "#h=" + encodeURIComponent(evil));
  check(await p6.isVisible("#link-note"), "hostile ?proof= shows the notice");
  await p6.click("#fetch-proof");
  await p6.waitForFunction(() => /only https/.test(document.getElementById("live").textContent));
  check(requests.length === rh, "a javascript: ?proof= is refused without any request");
  await p6.setInputFiles("#file", { name: evil + ".bin", mimeType: "application/octet-stream", buffer: Buffer.from("x") });
  await p6.setInputFiles("#proof", { name: evil + ".ots", mimeType: "application/octet-stream", buffer: readFileSync(V("hello-world", "proof.ots")) });
  await p6.waitForSelector("#result .steps");
  await p6.fill("#custom", "https://x.example/" + evil);
  await p6.fill("#purl", evil).catch(() => {});
  const inert = await p6.evaluate(() => ({ x: window.__x, bad: document.querySelectorAll("img, iframe, object, embed, script[src]").length, js: document.querySelectorAll('a[href^="javascript:" i]').length, inline: document.querySelectorAll("[onerror],[onclick],[onload]").length }));
  check(inert.x === undefined && inert.bad === 0 && inert.js === 0 && inert.inline === 0, "markup in names and URLs is rendered as text, nothing executes", JSON.stringify(inert));
  await p6.close();

  const bad = consoleMsgs.filter((m) => !/Content Security Policy|Refused to execute inline script|Failed to load resource/.test(m) && /error|PAGEERROR/i.test(m));
  check(bad.length === 0, "no unexpected console errors", bad.join(" | "));
} catch (e) {
  failed++; console.log("FAIL: exception", e.stack || e);
} finally {
  await browser.close(); mock.kill(); calProc.kill();
}
console.log(`browser smoke (${engine}): ${passed} checks passed, ${failed} failed`);
process.exit(failed ? 1 : 0);

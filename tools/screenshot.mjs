// Takes the README's hero picture: the page, with the real proof in vectors/real/ checked against the two public explorers.
//   ./podman.sh hero            (runs this inside the ci image; writes docs/hero.png; asks blockstream.info and mempool.space)
// Not part of the tests: it needs the network and a real Bitcoin block.
import { createRequire } from "node:module";
import { readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";

const root = join(dirname(fileURLToPath(import.meta.url)), "..");
const out = process.argv[2] || join(root, "docs", "hero.png");
const { chromium } = createRequire(import.meta.url)("playwright");
const hex = readFileSync(join(root, "vectors/real/dummy-2026-11-08.confirmed.ots")).toString("hex");
const digest = "fb415de6e7484a2f9d685c857bb6c80ea98019c25a91665372c48b09f62c2da3";

const browser = await chromium.launch();
const ctx = await browser.newContext({ viewport: { width: 1080, height: 1180 }, deviceScaleFactor: 1.5, colorScheme: "light" });
const page = await ctx.newPage();
await page.goto(pathToFileURL(join(root, "dist/index.html")).href);
await page.locator("#proofhex").fill(hex);
await page.locator("#digest").fill(digest);
await page.locator("#explain").click();
await page.locator("#ask").click();
await page.getByText(/Proved: this existed/).first().waitFor({ timeout: 45000 });
await page.waitForTimeout(500);
await page.evaluate(() => window.scrollTo(0, 0));
await page.screenshot({ path: out });
console.log("wrote", out);
await browser.close();

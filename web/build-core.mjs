// Bundle web/src/core/index.ts into web/build/core.mjs (ESM, platform neutral, ES2022, no minify).
// Run: node web/build-core.mjs
import { build } from "esbuild";
import { mkdirSync, renameSync, writeFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

const here = dirname(fileURLToPath(import.meta.url));
const out = join(here, "build", "core.mjs");
mkdirSync(dirname(out), { recursive: true });

const result = await build({
  entryPoints: [join(here, "src", "core", "index.ts")],
  bundle: true,
  format: "esm",
  platform: "neutral",
  target: "es2022",
  minify: false,
  sourcemap: "inline",
  sourcesContent: false,
  write: false,
  logLevel: "warning",
  outfile: out,
});
// write to a temporary name and rename, so concurrent test processes never read a half-written file
const tmp = `${out}.${process.pid}.tmp`;
writeFileSync(tmp, result.outputFiles[0].contents);
renameSync(tmp, out);

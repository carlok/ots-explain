// Build dist/index.html: one self-contained file (inline CSS + minified JS, a CSP that names their hashes).
//   node web/build.mjs
import { build } from "esbuild";
import { createHash } from "node:crypto";
import { mkdirSync, readFileSync, writeFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

const root = join(dirname(fileURLToPath(import.meta.url)), "..");
const pkg = JSON.parse(readFileSync(join(root, "package.json"), "utf8"));

const js = await build({
  entryPoints: [join(root, "web/src/ui/main.ts")],
  bundle: true, minify: true, format: "iife", target: "es2022", platform: "browser",
  write: false, legalComments: "none", charset: "ascii", logLevel: "warning",
  define: { __VERSION__: JSON.stringify(pkg.version) },
});
let script = js.outputFiles[0].text.trim().replace(/<\/(script)/gi, "<\\/$1").replace(/<!--/g, "<\\!--");
let css = readFileSync(join(root, "web/src/ui/style.css"), "utf8").replace(/\/\*[\s\S]*?\*\//g, "").replace(/\n+/g, "\n").trim();

const sha = (s) => `'sha256-${createHash("sha256").update(s, "utf8").digest("base64")}'`;
let html = readFileSync(join(root, "web/index.html"), "utf8");
// replacer functions: the script contains "$" sequences that must not be interpreted
html = html.replace("{{SCRIPT_HASH}}", () => sha(script)).replace("{{STYLE_HASH}}", () => sha(css))
  .replace("{{CSS}}", () => css).replace("{{JS}}", () => script);

mkdirSync(join(root, "dist"), { recursive: true });
writeFileSync(join(root, "dist/index.html"), html);
console.log(`dist/index.html ${Buffer.byteLength(html)} bytes (js ${Buffer.byteLength(script)}, css ${Buffer.byteLength(css)})`);

// The same core as a plain ES module for direct use from Node or another page (README: "Use it as a library").
const lib = await build({
  entryPoints: [join(root, "web/src/core/index.ts")],
  bundle: true, minify: false, format: "esm", target: "es2022", platform: "neutral",
  write: false, legalComments: "none", logLevel: "warning",
});
writeFileSync(join(root, "dist/ots-explain-core.mjs"), lib.outputFiles[0].text);
console.log(`dist/ots-explain-core.mjs ${Buffer.byteLength(lib.outputFiles[0].text)} bytes`);

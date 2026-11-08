#!/usr/bin/env python3
# Copyright 2026 the ots-explain authors. Licensed under the Apache License, Version 2.0.
"""Differential test on real-world proofs nobody wrote for this project.

    python3 tools/wild_diff.py [--per-repo 5] [--max 60] [--dir vectors/wild] [--no-fetch]

1. Finds `.ots` files on GitHub (public code-search API, unauthenticated, rate limited), keeps those that start with the
   OpenTimestamps magic, at most --per-repo from each repository, and downloads them to --dir (git-ignored: these are
   other people's files with unknown licences, so they are NOT committed). A manifest with each file's source URL and
   SHA-256 is written next to them. Only the proof is downloaded, never the file it is about.
2. Runs both implementations on each proof, with the digest taken from the proof (offline, ledger off), and diffs the
   canonical JSON, the text report and the text report with every hop.
Prints one line of totals and every divergence. Exit 0 = no divergence. It talks to api.github.com and
raw.githubusercontent.com only, and nothing but a search query and file paths is sent.
"""
import argparse, base64, collections, hashlib, json, os, subprocess, sys, tempfile, time, urllib.parse, urllib.request

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(ROOT, "python"))
import verify_ots as V  # noqa: E402

MAGIC = bytes.fromhex("004f70656e54696d657374616d7073000050726f6f6600bf89e2e884e89294")
UA = {"User-Agent": "ots-explain-wild-diff", "Accept": "application/vnd.github+json"}


def get(url, tries=3):
    for i in range(tries):
        try:
            with urllib.request.urlopen(urllib.request.Request(url, headers=UA), timeout=30) as r: return r.read()
        except Exception as e:
            if i == tries - 1: raise
            time.sleep(2 * (i + 1))


def search(per_repo, maximum):
    found = collections.defaultdict(list)
    for page in (1, 2, 3):
        d = json.loads(get("https://api.github.com/search/code?q=extension:ots&per_page=100&page=%d" % page))
        for it in d["items"]: found[it["repository"]["full_name"]].append(it["path"])
        if len(d["items"]) < 100: break
    out = []
    for repo, paths in sorted(found.items()):
        for p in sorted(paths)[:per_repo * 4]: out.append((repo, p))
    return out


def fetch(dest, per_repo, maximum):
    os.makedirs(dest, exist_ok=True)
    manifest, per = [], collections.Counter()
    for repo, path in search(per_repo, maximum):
        if len(manifest) >= maximum: break
        if per[repo] >= per_repo: continue
        url = "https://raw.githubusercontent.com/%s/HEAD/%s" % (repo, "/".join(urllib.parse.quote(x) for x in path.split("/")))
        try: data = get(url)
        except Exception: continue
        if len(data) > 400000: continue
        if not data.startswith(MAGIC):  # some projects store the proof as base64 text; decode it (and say so in the manifest)
            try: dec = base64.b64decode(data.strip(), validate=True)
            except Exception: continue
            if not dec.startswith(MAGIC): continue
            data, b64 = dec, True
        else: b64 = False
        name = "%s__%s.ots" % (repo.replace("/", "_"), hashlib.sha256(path.encode()).hexdigest()[:8])
        open(os.path.join(dest, name), "wb").write(data)
        manifest.append({"name": name, "repo": repo, "path": path, "url": url, "sha256": hashlib.sha256(data).hexdigest(), "was_base64": b64})
        per[repo] += 1
    json.dump(manifest, open(os.path.join(dest, "manifest.json"), "w"), indent=1)
    return manifest


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    ap.add_argument("--per-repo", type=int, default=5); ap.add_argument("--max", type=int, default=60)
    ap.add_argument("--dir", default=os.path.join(ROOT, "vectors", "wild")); ap.add_argument("--no-fetch", action="store_true")
    a = ap.parse_args(argv)
    if not a.no_fetch: fetch(a.dir, a.per_repo, a.max)
    manifest = json.load(open(os.path.join(a.dir, "manifest.json")))
    cases = []
    for m in manifest:
        proof = os.path.join(a.dir, m["name"])
        try: digest = V.parse_proof(open(proof, "rb").read()).digest.hex()
        except Exception: digest = "00" * 32
        cases.append({"name": m["name"][:-4], "proof": proof, "digest": digest})
    with tempfile.TemporaryDirectory() as tmp:
        mf = os.path.join(tmp, "m.json"); json.dump(cases, open(mf, "w"))
        r = subprocess.run(["node", os.path.join(ROOT, "test", "js", "conformance-run.mjs"), mf, os.path.join(tmp, "ts")], capture_output=True, text=True)
        if r.returncode: print(r.stdout, r.stderr); return 2
        diffs, verdicts = [], collections.Counter()
        for c in cases:
            proof = open(c["proof"], "rb").read()
            rep = V.build_report(proof, digest_hex=c["digest"])
            verdicts[(rep["error"] or {}).get("code", "parsed") if rep.get("error") else "parsed"] += 1
            mine = {"json": V.canonical_json(rep) + "\n", "txt": V.render_text(rep, False), "steps.txt": V.render_text(rep, True)}
            for ext, text in mine.items():
                theirs = open(os.path.join(tmp, "ts", "%s.%s" % (c["name"], ext if ext != "txt" else "txt"))).read()
                if text != theirs: diffs.append((c["name"], ext))
    print("wild proofs: %d from %d repositories; parsed %d, unparsed %s; divergences between Python and TypeScript: %d"
          % (len(cases), len({m["repo"] for m in manifest}), verdicts["parsed"], dict((k, v) for k, v in verdicts.items() if k != "parsed"), len(diffs)))
    for d in diffs: print("  DIFF", *d)
    return 1 if diffs else 0


if __name__ == "__main__": sys.exit(main())

# Backlog

Ranked by "how much it matters before this goes public", then by effort. **Who** says who can do it: *me* = the
author's sandbox could do it, *you* = needs a networked machine or an account. Updated 2026-11-08.

| # | Item | Why it matters | Effort | Who | Status |
|---|------|----------------|--------|-----|--------|
| 1 | Run the verifier against the **real explorers** (`tools/live_check.py --yes`) | Everything online was tested against synthetic data and mocks; an unexpected Esplora response shape is the likeliest first bug | 2 min | you | open |
| 2 | **Record real explorer responses** (`tools/record_explorer.py --yes`) and commit `vectors/explorer/recorded-*` | Turns #1 into permanent regression tests | 5 min | you | open |
| 3 | **Real calendar** stamp and upgrade from the terminal, then from the page (CORS) | Real calendars were never contacted; whether browsers may read their answers is unknown | hours (mostly waiting) | you | open |
| 4 | **Podman**: build the runtime and test images | The Containerfile (and the new `api` command) was never built | 10 min | you | open |
| 5 | **Pin GitHub Actions to commit SHAs** | Supply chain; Dependabot then keeps them current | easy | me | **done** (9 actions, `# vN` comments) |
| 6 | Make the workflows **run once** (CI, Pages, release, CodeQL) | They parse as YAML but have never executed | 20 min after the repo exists | you | open (YAML validated) |
| 7 | **Real-world proofs** as test data | Imported and handcrafted proofs were all written by test authors | easy | me | **done as far as it goes**: `tools/wild_diff.py` (2 raw files exist on GitHub; both parse, 0 divergences) and `vectors/upgrade/` (7 upgrade cases on the official 44-byte nodes, replayed in both languages). Better proofs: stamp your own (#3) and add them |
| 8 | Repository settings: private vulnerability reporting, branch protection on `main`, Pages source | `gh` is not authenticated here | 5 min | you | open (`tools/create_github_repo.sh` does About/topics) |
| 9 | Accept a **base64 or hex pasted proof** (two of the few real proofs on GitHub are stored as base64 text) | Real people paste what they have; today it is `bad_magic` | medium: spec section, both implementations, vectors | me | hex: done in the page (paste box, 2026-11-08); base64 and the Python script: open |
| 10 | **SPV / your own node**: check the block hash against a Bitcoin Core RPC (`--bitcoin-rpc`) and the real difficulty | Removes "two explorers agree" as the trust root; the README says so | medium-hard | me + you | open |

Not planned: verifying Litecoin or Ethereum attestations (calendars only anchor in Bitcoin; each chain needs its own
header and consensus check), uploading anything anywhere, accounts, analytics.

Ideas after v0.1.0: Italian translation of the page and the report, a "what does this proof prove, in one sentence"
summary for non-technical readers, WebAssembly-free hashing of files above 2 GB, a calendar status page.

# Guide for coding agents

This file is for automated coding assistants and humans using agent tooling. The normative behaviour contract is
`spec/SPEC.md`; human-oriented onboarding is `README.md` and `CONTRIBUTING.md`.

## Maintainer contact

Reach the maintainer on GitHub as **[@carlok](https://github.com/carlok)** for issues and discussions. Security
vulnerabilities: private reporting only — see `SECURITY.md` (no public issues). Code of conduct reports: see
`CODE_OF_CONDUCT.md`. Do not put maintainer email addresses in commits or issues; the approved contact email appears
only in `CODE_OF_CONDUCT.md`.

## Agent rules (non-negotiable)

* **Increase test coverage before each commit** when you change logic. Run `npm run coverage` and add or extend tests
  for new branches, errors, and conformance-relevant behaviour. Do not shrink coverage without a stated reason in the
  pull request.
* **Never commit secrets or host-specific values** (API tokens, personal Esplora or calendar URLs tied to one machine,
  `GH_TOKEN`, `OTS_API_TOKEN`, home paths, machine names). Use placeholders in docs and examples (`s3cret`, `https://my.esplora/api`).
* **Keep public docs general** (`README.md`, `docs/`, comments in `spec/`): no private URLs, no one-off production
  hostnames, no credentials. Put environment-specific notes in local-only notes or omit them.

## Setup

Requirements match CI: **Node.js 22**, **Python ≥ 3.9**, **npm** from the repo root.

```sh
npm install
pip install coverage    # optional; only for npm run coverage
npx playwright install --with-deps chromium   # browser smoke test (CI also runs firefox/webkit)
```

Podman/Docker workflow (optional, matches `Containerfile`):

```sh
./podman.sh test        # full suite inside the test image
```

No runtime npm or pip dependencies for the shipped page or `python/` scripts; only devDependencies in `package.json`.

## Test and coverage commands

These are the same commands CI and `CONTRIBUTING.md` expect.

| Goal | Command |
|------|---------|
| Full local suite (default before a PR) | `npm run test:all` |
| Typecheck only | `npm run typecheck` |
| Build `dist/` | `npm run build` |
| Node unit tests | `npm test` |
| Python unit tests | `npm run test:py` |
| Python/JS conformance | `npm run test:conformance` |
| Browser smoke (Chromium) | `npm run test:browser` |
| Python only (stdlib, no node) | `python3 -m unittest discover -s test -p 'test_*.py' -v` |
| Coverage (Node experimental + coverage.py) | `npm run coverage` |

After `npm run build`, CI also requires `dist/index.html` to be committed and under 150 KB:

```sh
git diff --exit-code -- dist/index.html
```

Fuzz (CI `full` job, optional locally):

```sh
OTS_FUZZ_N=4000 OTS_FUZZ_SEED=1 python3 -m unittest discover -s test -p 'test_fuzz.py' -v
```

## Project layout

```
spec/           SPEC.md (normative), report.schema.json, steps.json, openapi.json, QUESTIONS-*.md
vectors/        Proof fixtures, synthetic explorer data, provenance (LGPL vectors documented in PROVENANCE.md)
python/         verify_ots.py, ots_stamp.py, ots_api.py (stdlib only)
clients/        Thin API clients (js, python)
web/            TypeScript core and page UI; build.mjs writes dist/
dist/           Built single-file page + ots-explain-core.mjs (commit after build)
test/           Python unittest, Node test runner, browser smoke, mocks
tools/          Maintenance scripts (vectors, explorer recording, e2e)
contrib/        Example systemd/cron, headers — not loaded at runtime
docs/           Threat model, backlog, going-online checks
.github/        CI (ci.yml runs unit matrix + full job with coverage), CodeQL, Pages, release
```

Two implementations must agree: TypeScript (`web/src/core`) and Python (`python/verify_ots.py`). `test/test_conformance.py`
diffs reports on every vector.

## Conventions

* **Spec first:** behaviour changes need `spec/SPEC.md`, both implementations, and tests in one change.
* **API parity:** `python/ots_api.py` and `spec/openapi.json` stay in sync (`test/test_api.py`).
* **No silent network:** new fetches require user-visible consent and tests with mocks (`test/mock_esplora.py`, etc.).
* **No new runtime deps** in the page or Python verifier; dev-only tools are fine.
* **Changelog:** add a line under `CHANGELOG.md` → Unreleased for user-visible changes.
* **Vectors:** new proofs need provenance in `vectors/PROVENANCE.md`; prefer handcrafted via `tools/make_handcrafted.py` for parse errors.
* **Licence:** project code is Apache-2.0 (`LICENSE`); do not change licence text. Imported LGPL test vectors stay as documented in `vectors/PROVENANCE.md`.

## Pull request checklist

Use `.github/PULL_REQUEST_TEMPLATE.md`. Paste `npm run test:all` output (or list what you did not run). Confirm
`CHANGELOG.md` when appropriate. Security issues: private advisory on the repo, not a public issue — see `SECURITY.md`.

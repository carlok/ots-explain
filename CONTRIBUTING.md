# Contributing

Thanks for looking. The project is small on purpose: one spec, two implementations, one conformance test.

## Ground rules

* **The spec is the contract.** `spec/SPEC.md` decides behaviour. If you change behaviour, change the spec in the
  same pull request, then both implementations, then the tests. A change in only one implementation will fail
  `test/test_conformance.py`, which is its job.
* The REST API (`python/ots_api.py`) and `spec/openapi.json` change together; `test/test_api.py` fails if a route is undocumented.
* **No runtime dependencies**, in the page or in `python/`. Dev-only tools (esbuild, TypeScript, Playwright,
  coverage.py) are fine. The page must stay a single file under 150 KB with a strict CSP and no `eval`.
* **Nothing touches the network unless the person asked.** New network calls need a consent step that lists the URLs first, and a mock in `test/`.
* **Tests first** for parsers and hash steps. A new parse error needs a handcrafted vector (`tools/make_handcrafted.py`).
* Prefer free, actively maintained, lightweight tools.

## Set up and check

```sh
npm install
npm run test:all          # typecheck, build, node tests, python tests + conformance, browser smoke test
npm run coverage          # optional; coverage.py is `pip install coverage`
```

The browser smoke test needs Chrome or Chromium that Playwright can drive (`npx playwright install chromium`).
Python 3.9 is the minimum: no `match`, no `X | Y` annotations at runtime.

## Pull requests

Small and focused, with the output of `npm run test:all`. Mention which of these you did **not** run (e.g. Podman).
Add a line to `CHANGELOG.md` under "Unreleased".

## New test vectors

Prefer proofs you stamped yourself. If you copy one from another project, record where it came from and under
which licence in `vectors/PROVENANCE.md`.

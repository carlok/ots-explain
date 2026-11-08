# Changelog

Format: [Keep a Changelog](https://keepachangelog.com/en/1.1.0/). Versions: [SemVer](https://semver.org/).

## [Unreleased]

### Fixed
- Page, "Check a proof": pasting a file's hash did nothing visible and there was no button to start. There is now an "Explain" button (checking also runs on paste), a box for the proof as hex, and a line under the inputs that says what is missing or why a paste cannot be used (not hex, odd length, no .ots header, a hash where a proof belongs or the reverse). A bare hash is named by its length (64: SHA-256; 40: SHA-1 or RIPEMD-160) and offers "Stamp this hash", which opens Stamp with it filled in. Browser smoke test: 12 new checks.

### Added
- Static page `dist/index.html` (single file, strict CSP, light/dark, print, copyable text report, JSON download, permalinks).
- `python/verify_ots.py` (stdlib only, Python ≥ 3.9) and `python/ots_stamp.py` (stamp, upgrade, watch).
- Spec, JSON schema, 21 imported + 24 handcrafted vectors, conformance test (511 cases, JSON/text/permalink).
- Stamp and upgrade in the page (`web/src/core/stamp.ts`, written from SPEC section 12 alone), diffed against `ots_stamp.py` over real HTTP. The independent writer found that SPEC 12.7 skipped the 44-byte nodes real calendar proofs hang pending attestations on; fixed.
- REST API `python/ots_api.py` (verify, stamp, upgrade, permalinks; digests only, network off by default, allow-lists, optional token and CORS origin), OpenAPI 3.1 in `spec/openapi.json`, JS and Python clients in `clients/`, `api` container command, library bundle `dist/ots-explain-core.mjs`.
- `vectors/upgrade/` (7 upgrade cases, replayed in both languages), `tools/wild_diff.py` (differential test on real-world proofs from GitHub), `docs/BACKLOG.md`; workflow actions pinned to commit SHAs.
- `podman.sh` and a `ci` image target: test, build, serve, api, cli, live checks and repo creation without installing anything on the host.
- Containerfile (untested), cron and systemd examples, offline demo.
- `tools/e2e_real.sh`: one real end-to-end run in Podman (tests, images, a real stamp of a dummy file, the pending check, live explorer and wild checks), logging under the git-ignored `e2e/`.

# Changelog

Format: [Keep a Changelog](https://keepachangelog.com/en/1.1.0/). Versions: [SemVer](https://semver.org/).

## [Unreleased]

### Added
- Static page `dist/index.html` (single file, strict CSP, light/dark, print, copyable text report, JSON download, permalinks).
- `python/verify_ots.py` (stdlib only, Python ≥ 3.9) and `python/ots_stamp.py` (stamp, upgrade, watch).
- Spec, JSON schema, 21 imported + 24 handcrafted vectors, conformance test (511 cases, JSON/text/permalink).
- Stamp and upgrade in the page (`web/src/core/stamp.ts`, written from SPEC section 12 alone), diffed against `ots_stamp.py` over real HTTP. The independent writer found that SPEC 12.7 skipped the 44-byte nodes real calendar proofs hang pending attestations on; fixed.
- REST API `python/ots_api.py` (verify, stamp, upgrade, permalinks; digests only, network off by default, allow-lists, optional token and CORS origin), OpenAPI 3.1 in `spec/openapi.json`, JS and Python clients in `clients/`, `api` container command, library bundle `dist/ots-explain-core.mjs`.
- `vectors/upgrade/` (7 upgrade cases, replayed in both languages), `tools/wild_diff.py` (differential test on real-world proofs from GitHub), `docs/BACKLOG.md`; workflow actions pinned to commit SHAs.
- `podman.sh` and a `ci` image target: test, build, serve, api, cli, live checks and repo creation without installing anything on the host.
- Containerfile (untested), cron and systemd examples, offline demo.

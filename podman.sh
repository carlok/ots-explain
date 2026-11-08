#!/bin/sh
# Everything in containers. The host needs Podman (or set CONTAINER=docker) and this folder, nothing else:
# no npm install, no Python packages, no browser, no git or gh on the host. Files are written only where noted.
#
#   ./podman.sh test            typecheck, build, node + Python tests, conformance, fuzz, browser smoke test (Chromium inside)
#   ./podman.sh coverage        the same tests with coverage numbers
#   ./podman.sh build           build the page; writes dist/index.html and dist/ots-explain-core.mjs into ./dist
#   ./podman.sh serve           the page on http://localhost:8080/
#   ./podman.sh api [args]      the REST API on http://127.0.0.1:8787 (needs OTS_API_TOKEN; args e.g. --allow-network)
#   ./podman.sh cli ARGS...     verify_ots.py / ots_stamp.py in the current folder:  cli verify f f.ots | cli stamp f | cli upgrade f.ots
#   ./podman.sh live-check [--yes]   list the real explorers it would ask; add --yes to ask them
#   ./podman.sh record [--yes]   list, or with --yes record, real explorer answers into ./vectors/explorer/recorded-*
#   ./podman.sh wild            diff both implementations on real-world proofs fetched from GitHub (nothing is saved on the host)
#   ./podman.sh repo [owner/name]   create the private GitHub repo (needs GH_TOKEN in the environment; writes ./.git)
#   ./podman.sh clean           remove the images this script built
set -eu
cd "$(dirname "$0")"
C="${CONTAINER:-podman}"
cmd="${1:-help}"; [ $# -gt 0 ] && shift
ci()      { $C build -q --target ci -t ots-explain-ci . >/dev/null; }
runtime() { $C build -q --target runtime -t ots-explain . >/dev/null; }
case "$cmd" in
  test)      ci; $C run --rm --ipc=host ots-explain-ci npm run test:all ;;
  coverage)  ci; $C run --rm --ipc=host ots-explain-ci npm run coverage ;;
  build)     ci; mkdir -p dist; $C run --rm -v "$PWD/dist:/out:Z" ots-explain-ci sh -c 'npm run build >/dev/null && cp dist/index.html dist/ots-explain-core.mjs /out/ && ls -l /out' ;;
  serve)     runtime; $C run --rm -p 127.0.0.1:8080:8080 ots-explain serve ;;
  api)       runtime; [ -n "${OTS_API_TOKEN:-}" ] || { echo "set OTS_API_TOKEN first (the API refuses a container bind without a token)" >&2; exit 2; }
             $C run --rm -p 127.0.0.1:8787:8787 -e OTS_API_TOKEN ots-explain api "$@" ;;
  cli)       runtime; $C run --rm -it -v "$PWD:/work:Z" -w /work ots-explain "$@" ;;
  live-check) ci; $C run --rm ots-explain-ci python3 tools/live_check.py "$@" ;;
  record)    ci; mkdir -p vectors/explorer; $C run --rm -v "$PWD/vectors/explorer:/app/vectors/explorer:Z" ots-explain-ci python3 tools/record_explorer.py "$@" ;;
  wild)      ci; $C run --rm ots-explain-ci python3 tools/wild_diff.py "$@" ;;
  repo)      [ -n "${GH_TOKEN:-}" ] || { echo "set GH_TOKEN (a GitHub token with repo scope) first" >&2; exit 2; }
             $C run --rm -e GH_TOKEN -v "$PWD:/src:Z" -w /src docker.io/library/alpine:3 sh -c 'apk add --no-cache -q git github-cli && git config --global user.name "${GIT_AUTHOR_NAME:-ots-explain}" && git config --global user.email "${GIT_AUTHOR_EMAIL:-noreply@example.invalid}" && git config --global --add safe.directory /src && sh tools/create_github_repo.sh "$@"' sh "$@" ;;
  clean)     $C rmi -f ots-explain-ci ots-explain 2>/dev/null || true ;;
  help|--help|-h|*) sed -n '2,19p' "$0" ;;
esac

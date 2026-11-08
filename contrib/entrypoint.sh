#!/bin/sh
# ots-explain container entrypoint. Usage: podman run --rm -v "$PWD":/work ots-explain <command> [args]
set -eu
cmd="${1:-help}"; [ $# -gt 0 ] && shift
case "$cmd" in
  verify)  exec python3 /app/python/verify_ots.py "$@" ;;
  stamp|upgrade|watch) exec python3 /app/python/ots_stamp.py "$cmd" "$@" ;;
  serve)   echo "serving the static page on http://localhost:8080/ (Ctrl-C to stop)"; exec python3 -m http.server 8080 --bind 0.0.0.0 --directory /app/dist ;;
  api)
    # Publish with: -p 127.0.0.1:8787:8787 -e OTS_API_TOKEN=... (a non-loopback bind needs a token). Add --allow-network etc. as args.
    exec python3 /app/python/ots_api.py --host 0.0.0.0 --port 8787 "$@" ;;
  demo)    exec python3 /app/tools/demo.py "$@" ;;
  test)    cd /app && npm test && python3 -m unittest discover -s test -p 'test_*.py' ;;
  help|--help|-h) echo "commands: verify FILE PROOF | stamp FILE | upgrade PROOF | watch DIR | serve | api [--allow-network ...] | demo | test (test image only)" ;;
  *) echo "unknown command: $cmd (try help)" >&2; exit 2 ;;
esac

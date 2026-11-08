#!/bin/sh
# Real end-to-end run on this machine, everything inside Podman: the test suite, the page build, the `test` and
# `runtime` images, a real stamp of a dummy file on the public calendars, the pending check, an early upgrade, and
# the live explorer and wild-proof checks.
#   sh tools/e2e_real.sh          writes only under ./e2e/ (git-ignored) and, through `build`, ./dist
# Running it is the consent to use the network: the public OpenTimestamps calendars (stamp, upgrade),
# blockstream.info and mempool.space (live-check) and GitHub (wild, only if GH_TOKEN is set: its code search refuses anonymous calls). Each command still lists its URLs first.
# Every step runs even if an earlier one failed; the summary at the end gives each exit status.
set -u
cd "$(dirname "$0")/.."
C="${CONTAINER:-podman}"
mkdir -p e2e/logs
STAMP_DAY="$(date -u +%Y-%m-%d)"
DUMMY="e2e/dummy-$STAMP_DAY.txt"
RUN="$(date -u +%Y%m%dT%H%M%SZ)"
LOG="e2e/logs/e2e-$RUN.log"
SUMMARY="e2e/logs/summary-$RUN.txt"
: > "$SUMMARY"

step() {
  name="$1"; shift
  echo; echo "== $name ($(date -u +%H:%M:%SZ)): $*"
  "$@"; rc=$?
  echo "== $name: exit $rc"
  echo "$name $rc" >> "$SUMMARY"
}

{
  echo "ots-explain end-to-end run $RUN on $(uname -sm)"
  printf 'Is the empty private repo github.com/carlok/ots-explain created (no README, licence or .gitignore)? [y/N] '
  read -r answer
  echo "repo-created: ${answer:-n}"

  if ! $C info >/dev/null 2>&1 && [ "$C" = podman ] && [ "$(uname -s)" = Darwin ]; then
    echo "starting the Podman machine"; podman machine start
  fi
  $C info >/dev/null 2>&1 || { echo "Podman is not reachable (run 'podman machine init' once, then retry)"; echo "podman 2" >> "$SUMMARY"; exit 2; }
  $C --version

  [ -f "$DUMMY" ] || printf 'ots-explain end-to-end test file, created %s\n' "$(date -u +%Y-%m-%dT%H:%M:%SZ)" > "$DUMMY"

  step test         ./podman.sh test
  step build        ./podman.sh build
  step image-test   sh -c "$C build -q --target test -t ots-explain-test . >/dev/null && $C run --rm ots-explain-test test"
  step demo         $C run --rm ots-explain-test demo
  step stamp        ./podman.sh cli stamp "$DUMMY" --yes
  step pending      ./podman.sh cli verify "$DUMMY" "$DUMMY.ots"
  step pending-json ./podman.sh cli verify "$DUMMY" "$DUMMY.ots" --json
  step upgrade-now  ./podman.sh cli upgrade "$DUMMY.ots"
  step live-check   ./podman.sh live-check --yes
  if [ -n "${GH_TOKEN:-}" ]; then step wild ./podman.sh wild
  else echo; echo "== wild: skipped (GitHub's code search needs a token; run  GH_TOKEN=... sh tools/e2e_real.sh  to include it)"; echo "wild skipped" >> "$SUMMARY"; fi

  echo; echo "== summary (exit statuses; pending/upgrade-now are expected to say 'not proven yet' for a few hours)"
  cat "$SUMMARY"
  echo "dummy: $DUMMY  proof: $DUMMY.ots  log: $LOG"
  echo "finished $(date -u +%Y-%m-%dT%H:%M:%SZ)"
} 2>&1 | tee "$LOG"
touch "e2e/logs/DONE-$RUN"

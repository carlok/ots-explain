#!/bin/sh
# Create the private GitHub repo with About text and topics, then push. Run it yourself where `gh auth login` works.
#   tools/create_github_repo.sh [owner/name]        (default: ots-explain under your account)
set -eu
NAME="${1:-ots-explain}"
DESC="Check, understand and create OpenTimestamps proofs: every hop from file to Bitcoin block, stamp and upgrade, REST API. One static page (nothing uploaded) and a stdlib-only Python script, two independent implementations of one spec."
TOPICS="opentimestamps bitcoin timestamping verification privacy-first static-site typescript python podman"
cd "$(dirname "$0")/.."
command -v gh >/dev/null || { echo "gh (GitHub CLI) is required" >&2; exit 2; }
gh auth status >/dev/null 2>&1 || { echo "run 'gh auth login' first" >&2; exit 2; }
[ -d .git ] || git init -q -b main
git rev-parse HEAD >/dev/null 2>&1 || { git add -A && git commit -q -m "ots-explain: initial import"; }
gh repo create "$NAME" --private --description "$DESC" --source . --remote origin --push
for t in $TOPICS; do gh repo edit "$NAME" --add-topic "$t"; done
echo "created (private): $(gh repo view "$NAME" --json url -q .url)"
echo "make it public later with:  gh repo edit $NAME --visibility public --accept-visibility-change-consequences"

# Going online: what only you can check

The author built this in a sandbox with no route to real explorers, real calendars or Podman. These five steps turn
"tested against synthetic and mock data" into "tested against the real world". Do them in this order, on a machine with a
network (everything can run through `./podman.sh`, so nothing is installed on the host), before making the repository public or announcing the page.

1. **Real explorers, 2 minutes.** `./podman.sh live-check --yes` (or `python3 tools/live_check.py --yes`). Expect six `PASS` and `bad-stamp` `FAIL`.
   Anything else usually means an Esplora response shape the code did not expect: keep the output.
2. **Record the real responses** so the tests can use them forever: `./podman.sh record --yes` (or `python3 tools/record_explorer.py --yes`); commit
   `vectors/explorer/recorded-*`. (The recorder is the only code that talks to the real explorers apart from
   `--yes` runs of the verifier.)
3. **Real calendar from the terminal.** `python3 python/ots_stamp.py stamp some-file` (shows the URLs, asks first), then
   in a few hours `python3 python/ots_stamp.py upgrade some-file.ots`, then `python3 python/verify_ots.py some-file some-file.ots --yes`.
   Keep that proof: replace one of the imported vectors with your own (see `vectors/PROVENANCE.md`).
4. **Real calendar from the page (CORS).** Open `dist/index.html` from a web server (`podman run -p 8080:8080 ots-explain serve`
   or any static host), "Stamp a file", leave the default calendars checked. If it says every calendar failed with
   "Failed to fetch", the calendars do not send CORS headers: say so in the README and keep the terminal route.
5. **Podman.** `./podman.sh test` (builds the `ci` image and runs everything), then `./podman.sh serve` and `./podman.sh build`.

Then: run `tools/create_github_repo.sh`; enable private vulnerability reporting, branch protection on `main`, and
GitHub Pages (source: GitHub Actions) if you want the hosted page; tag `v0.1.0` to run the release workflow (build twice,
checksums, provenance attestation). The actions in `.github/workflows/` are already pinned to commit SHAs (Dependabot keeps them current). Read `docs/THREAT-MODEL.md` once more and make sure the README says the same.

Remaining items, ranked: `docs/BACKLOG.md`. Optional: `python3 tools/wild_diff.py` diffs both implementations on real-world proofs fetched from GitHub.

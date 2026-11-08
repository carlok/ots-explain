# What a green verdict means, and what it does not

**PASS** means: the file you gave (or the hash you pasted) is the one the proof names; every hash operation from that
digest to the attestation was recomputed here and matches; and each Bitcoin attestation was confirmed by every
explorer you asked: the block header hashes to the block hash the server gave, meets the proof of work its own
`nBits` declares, has the proof's final digest as merkle root, contains the proof's transaction (witness data
removed), and an output of that transaction carries the commitment. So, *if the explorers are telling the truth about
the Bitcoin chain*, the file existed no later than that block's header time (miners' clocks are only roughly right).

It does **not** mean:

* **That the explorers are honest.** This is not SPV. A server that lies consistently, or two colluding ones, can
  show a fake block whose proof of work is valid at a low difficulty the attacker picked. Defences: add a server you
  run; compare the block hash with your own node or another source; use `--esplora` against a node you trust.
* **That the file is authentic or that its content is true**; only that these bytes existed by then.
* **That the stamper was who they say.** A timestamp has no identity.
* **Anything about proofs that are only pending.** A pending proof is a calendar's promise, not a proof of time. The
  page never shows green for one.

## What the page and scripts trust

| Component | Trusted for | Not trusted for |
|---|---|---|
| Your browser / Python | running the code honestly | n/a |
| The page's own bytes | being the build you meant to run | check `SHA256SUMS` of a release and the attestation |
| Calendar servers | answering `timestamp/<commitment>` | content: every answer is parsed with strict limits and checked by replaying the hashes |
| Explorers | telling the truth about the chain | anything checked locally (hashes, proof of work, merkle root, transaction contents) |
| The `.ots` file | nothing | it is untrusted input: size and depth limits, no eval, markup shown as text only |

## Privacy

Stamping sends a calendar `SHA-256(file hash ‖ random)` and nothing else. Checking the ledger sends an explorer a
block height, a block hash and a transaction id. Both see your IP address. Nothing else leaves your machine; the
page's CSP forbids every other kind of request.

## Hostile inputs

Proofs, file names, `?proof=` URLs and server URLs are all attacker-controlled in some scenario. They are only ever
inserted as text; the browser test feeds markup through each of them. Proof parsing has hard limits (4096-byte
messages, 255 operations deep, 16 MiB files) and is fuzzed against a second implementation.

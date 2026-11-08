# ots-explain specification, version 1

Two independent programs implement this document: `web/src/core/*.ts` (browser, plus a
Node wrapper) and `python/verify_ots.py` (standard library only). They must produce
**byte-identical canonical JSON** for the same inputs. This file is the only contract
between them. Where the reference client disagrees with a sentence here, the reference
wins and this file is fixed (see "Reference decisions" at the end).

Reference: `python-opentimestamps` 0.5.0 / `opentimestamps-client` 0.8.0 source,
files `core/timestamp.py`, `core/op.py`, `core/notary.py`, `core/serialize.py`.

## 1. Inputs and modes

| input | mode | meaning |
|---|---|---|
| a file (bytes) and a proof | `file` | the tool hashes the file with the proof's header algorithm |
| a hex digest and a proof | `digest` | the tool trusts the digest as given |
| a proof only | `none` | no comparison with a file is possible |

Digest hex: even length, characters `0-9a-fA-F`, case-folded to lower case. Its byte
length must equal the digest length of the proof's header algorithm (sha256 32, sha1 20,
ripemd160 20), else step 1 fails with `bad_digest`.

## 2. The five steps

Ids and titles are fixed (also in `steps.json`). Statuses: `PASS`, `FAIL`, `SKIP`.

| # | id | title |
|---|---|---|
| 1 | `file_hash` | File to hash |
| 2 | `structure` | Proof structure |
| 3 | `hash_steps` | Hash steps |
| 4 | `ledger` | The ledger |
| 5 | `verdict` | Verdict |

Step codes (closed list; `steps[i].code`):

* `file_hash` (precedence: `no_proof` first, whatever the input; then `no_input`, `bad_digest`, `alg_unsupported`, then `ok`/`mismatch`): `ok` PASS (digest equals the digest in the proof) · `mismatch` FAIL ·
  `bad_digest` FAIL · `no_input` SKIP (mode `none`) · `no_proof` SKIP (proof did not parse,
  algorithm unknown) · `alg_unsupported` SKIP (mode `file` and header algorithm is
  `ripemd160`: this tool hashes files with SHA-256 and SHA-1 only; "hash-only mode": the
  proof is still parsed and replayed from its own digest, and the user may pass the digest
  by hand).
* `structure`: `ok` PASS, otherwise FAIL with one parse error code from section 4.
* `hash_steps`: `ok` PASS (replay started from the digest the user's input produced, and
  every operation was computed) · `not_tied` SKIP (step 1 was not PASS, so the replay is
  shown but starts from the digest inside the proof, not from the user's file) · `no_proof` SKIP.
* `ledger`: `ok` PASS · `not_requested` SKIP · `no_bitcoin` SKIP (no Bitcoin attestation)
  · `no_proof` SKIP · `check_failed` FAIL · `disagree` FAIL · `incomplete` SKIP (nothing
  failed, but some check was SKIP).
* `verdict`: `proved` PASS · `failed` FAIL · `incomplete` SKIP.

Rule for step 4 over all Bitcoin attestations A and servers S: FAIL if any check is FAIL
or any attestation has `agree == false`; else SKIP if any check is SKIP; else PASS.

Verdict: `FAIL` if any of steps 1-4 is FAIL; else `SKIP` if any is SKIP; else `PASS`.
Never green when something was skipped. On PASS the verdict carries `block` (the lowest
height among the Bitcoin attestations) and `time` (the header time, unix seconds, of that
block as read from the header). `unverified` lists indexes of attestations that are not
Bitcoin (pending, litecoin, ethereum, unknown): they are named, not checked, and do not
block a PASS.

## 3. Binary format (what the parser reads)

All multi-byte lengths are unsigned LEB128 `varuint` (low 7 bits first, high bit = more),
at most 9 bytes (`varuint_too_long`). `varbytes` = varuint length then that many bytes.

```
file      := MAGIC  uint8(version)  filehashop  digest  timestamp  EOF
MAGIC     := 00 4f 70 65 6e 54 69 6d 65 73 74 61 6d 70 73 00 00 50 72 6f 6f 66 00 bf 89 e2 e8 84 e8 92 94   (31 bytes)
version   := 01                      (anything else: unsupported_version)
filehashop:= 02 (sha1) | 03 (ripemd160) | 08 (sha256)   (anything else: unknown_file_hash_op)
digest    := 20 or 32 bytes according to filehashop
timestamp := { 0xff entry } entry          (all entries but the last are prefixed with 0xff)
entry     := 0x00 attestation | op timestamp
op        := f0 varbytes(arg) (append) | f1 varbytes(arg) (prepend)
           | 08 (sha256) | 02 (sha1) | 03 (ripemd160) | 67 (keccak256) | f2 (reverse) | f3 (hexlify)
attestation := tag(8 bytes) varbytes(payload)
```

Limits (from the reference): `arg` length 1..4096 (`arg_length`); the input message of an
op at most 4096 bytes, of hexlify at most 2048 (`msg_too_long`); an op result at most 4096
bytes (`result_too_long`); reverse and hexlify of an empty message (`empty_message`);
nesting: the reference starts the root timestamp with a recursion budget of 256, each op
below costs one, and a timestamp entered with a budget of 0 is rejected (`recursion_limit`): a
root-to-leaf chain of at most **255** ops is accepted, 256 ops are rejected (the attestation hanging
on the node at depth 256 is never read); attestation
payload at most 8192 bytes (`payload_too_long`); the same op with the same arg twice in
one node (`repeated_op`); bytes after the last timestamp (`trailing_garbage`); reading past the
end (`truncated`); bad magic (`bad_magic`); unknown op tag byte (`unknown_op`).

Attestations (tag hex → kind). The payload is parsed only for the known tags, and must be
consumed exactly (`bad_attestation_payload` otherwise):

| tag | kind | payload |
|---|---|---|
| `0588960d73d71901` | `bitcoin` | varuint height, at most 4294967295 (`height_too_large`) |
| `06869a0d73d71b45` | `litecoin` | same |
| `30fe8087b5c7ead7` | `ethereum` | same |
| `83dfe30d2ef90c8e` | `pending` | varbytes(uri), uri at most 1000 bytes, characters only `A-Za-z0-9-._/:` (`bad_uri`; checked before the payload is checked to be fully consumed, as the reference does) |
| anything else | `unknown` | kept as raw hex |

Operations on a message `m`: `append a` = `m‖a`; `prepend a` = `a‖m`; `sha256`, `sha1`,
`ripemd160`, `keccak256` (the original Keccak padding 0x01, not NIST SHA-3) = the digest;
`reverse` = bytes reversed; `hexlify` = lower-case hex ASCII of `m`.

The parser computes every message while it parses (the limits depend on the results).
The root message is the digest stored in the file.

## 4. Parse error codes

`bad_magic unsupported_version unknown_file_hash_op truncated trailing_garbage unknown_op
repeated_op arg_length msg_too_long result_too_long empty_message varuint_too_long
payload_too_long bad_attestation_payload bad_uri height_too_large recursion_limit`.
When several apply, the first one met while reading left to right wins. A reader that
cannot decide between two codes must follow the order of the checks in the reference
source: tag → (varuint, varbytes limits) → op application → recursion.

## 5. Tree, ids, attestations

Nodes are numbered in the order they are created while reading the file: the root is
node 0; every op creates the next node (depth-first, file order). An attestation is numbered
(`index`) in file order across the whole file and records the node it hangs on. Nothing is
sorted or de-duplicated (the reference sorts when it prints; official proofs are already in
sorted order). `max_depth` is the largest number of ops on a root-to-node path. `ops` is
the number of op edges (= nodes − 1), `nodes` the number of nodes.

## 6. Phases of a Bitcoin attestation

For an attestation on node `A`, let the path be the node ids from the root to `A` and
`m_i` the message after `i` ops (`m_0` is the root digest, `m_K` the message on `A`,
`K = len(path) - 1`).

1. **Transaction found.** `t` = the smallest `i ≥ 1` such that `m_i` is a legacy Bitcoin
   transaction: version (4 bytes LE), varint input count ≥ 1, each input (32-byte hash, 4
   bytes, varint script length, script, 4 bytes), varint output count ≥ 1, each output (8
   bytes, varint script length, script), locktime (4 bytes), consuming exactly all bytes.
   If none: `phases = null`, `phases_code = "no_transaction"`.
2. **Commitment.** `c` = `t`, then while `c > 0` and op `c` (the op between `m_{c-1}` and
   `m_c`) is `append` or `prepend`: `c := c − 1`. Commitment = `m_c`. (Its ops `c+1..t` are
   the ones that build the transaction around it.) `c = 0` is legal: the digest itself is placed in the
   transaction with no hash in between (the 2025 `gdp2q25` vector does exactly that), and then the
   calendar tree phase is empty. If `c == t` (the transaction was not built by append/prepend ops):
   `phases = null`.
3. **Txid hash.** Ops `t+1` and `t+2` must both exist and both be `sha256`, else
   `phases = null`, `phases_code = "no_txid_hash"`. `txid` = `m_{t+2}` reversed, as lower-case hex.
4. **Phases by op number:** `calendar_tree` = ops `1..c`, `transaction` = ops `c+1..t+2`,
   `block_merkle_path` = ops `t+3..K` (empty when `K = t+2`). The message `m_K` is the
   block's merkle root in internal byte order.
5. **Output.** The first output (in order) whose script contains `m_c` as a contiguous
   byte string. `kind`: `op_return` if script[0] = 0x6a; `p2sh` if the script is
   `a9 14 <20 bytes> 87`; `p2pkh` if it is `76 a9 14 <20 bytes> 88 ac`; otherwise `other`.
   No such output: `output = null`.

Reported object (null for non-Bitcoin attestations and when no transaction was found):
`{ "path": [node ids], "commitment_index": c, "transaction_index": t, "txid_index": t+2,
"root_index": K, "commitment": hex, "txid": hex, "output": null | {"index", "kind", "script": hex} }`.

## 7. The ledger (step 4)

Only when the user asked. Before any request the plan is shown. Servers: by default
`blockstream.info` = `https://blockstream.info/api` and `mempool.space` =
`https://mempool.space/api`, in that order; user-supplied Esplora base URLs replace the
defaults and are named by their URL (no trailing slash). Only `GET`. For each Bitcoin
attestation (file order) at height `h` with `phases`, for each server, in this order,
stopping at the first non-PASS (the rest get status SKIP, code `not_run`):

| id | request | PASS when |
|---|---|---|
| `block_hash` | `GET {base}/block-height/{h}` | body (trimmed) is 64 hex chars |
| `header` | `GET {base}/block/{hash}/header` | body (trimmed) is 160 hex chars, `sha256d(header)` reversed equals `hash`, and that hash is ≤ the target of header's `nBits` (compact encoding, bytes 72..76 LE; "bad nBits" is FAIL) |
| `merkle_root` | none | header bytes 36..68 equal `m_K` |
| `txids` | `GET {base}/block/{hash}/txids` | body is a JSON array of strings and contains `txid` |
| `raw_tx` | `GET {base}/tx/{txid}/hex` | body (trimmed) is hex; after removing witness data (if the marker bytes `00 01` follow the version) it equals `m_t`, byte for byte |
| `output` | none | `phases.output` is not null, computed on the server's transaction (stripped); equal to the proof's by `raw_tx` |

Block time `time` = header bytes 68..72, LE, unix seconds.
If `phases` is null the checks `txids`, `raw_tx`, `output` get status SKIP, code `no_transaction`
(`block_hash`, `header`, `merkle_root` still run).
Codes: `ok` (PASS); FAIL: `bad_response`, `bad_hash`, `bad_pow`, `mismatch`, `not_in_block`,
`not_found` (HTTP 404), `no_output`; SKIP: `unreachable` (network error, timeout, any HTTP
status other than 200 and 404), `no_transaction`, `not_run`.
Per attestation `agree` is `true` when at least two servers produced a header and all
produced headers are equal, `false` when two differ, `null` otherwise.
The plan lists, per attestation and server, the four URLs in order; the three that depend on
the block hash use the literal text `{block_hash}` (known only after the first answer).

`where_to_look` per Bitcoin attestation with a txid (both default servers always, in this order):
`{"kind":"block","server":"blockstream.info","url":"https://blockstream.info/block-height/{h}"}`,
`{"kind":"tx","server":"blockstream.info","url":"https://blockstream.info/tx/{txid}"}`,
`{"kind":"raw_hex","server":"blockstream.info","url":"https://blockstream.info/api/tx/{txid}/hex"}`, then the same
three for `mempool.space` (`https://mempool.space/block/{h}`, `https://mempool.space/tx/{txid}`,
`https://mempool.space/api/tx/{txid}/hex`). When `phases` is null: empty list. (The block
and tx page URLs are not verified against the live sites; the raw hex URLs are Esplora API paths.)

## 8. Canonical JSON

UTF-8, no byte-order mark, no whitespace, object keys sorted by Unicode code point, no
floating point, no `NaN`, strings escaped only as `\"`, `\\`, `\n`, `\r`, `\t` and `\u00XX`
for other control characters; all strings in a report are ASCII by construction. The
command-line `--json` prints this plus one `\n`; comparisons ignore that newline.
The report schema is `report.schema.json`. The whole report is compared, not just the offline
half. It never contains clocks, durations, host names of the machine or random values.

Report top level keys: `spec` (`"ots-explain-report/1"`), `input`, `error`, `proof`,
`steps`, `ledger`, `verdict`. `input` = `{mode, size, digest, digest_alg}` (`size`: file
size in bytes or null; `digest`: lower-case hex of the digest that will be compared, or null;
`digest_alg`: the proof's header algorithm name or null). `error` = null or `{code}`.
`proof` = null or `{size, version, hash_op, digest, nodes, ops, max_depth, tree, attestations}`;
each tree entry `{id, parent, op, arg, digest}` (`parent` −1 and `op`/`arg` null for the root;
`arg` null for unary ops); each attestation `{index, node, kind, height, uri, tag, payload,
phases, where_to_look}`.
`ledger` = null when not requested, else `{servers:[{name,base}], plan:[{attestation,server,url}],
attestations:[{attestation, agree, servers:[{server, status, block_hash, header, time,
checks:[{id,status,code}]}]}]}` where `server` is the server name and `status` the
conjunction of its checks (FAIL > SKIP > PASS).

Exit codes: `0` verdict PASS · `1` verdict FAIL · `3` verdict SKIP (nothing failed, something not checked) · `2` usage or
input error (unreadable file, bad arguments, no report produced).

## 9. Permalink

`BASE[?proof=URL][#h=HEX][&ots=B64]` where `HEX` is the lower-case digest, `B64` is the .ots
file in unpadded base64url (RFC 4648 section 5), and `URL` is percent-encoded (everything
except `A-Za-z0-9-._~`). Fragment parts appear in the order `h`, `ots`; the `#` is omitted when
both are absent. A fragment is never sent to a server. `?proof=` is only fetched after an explicit
click. Decoding ignores unknown fragment keys and is case-sensitive for keys.

## 10. Reference decisions (checked against the reference source)

* Header hash `keccak256` (0x67) is **not** a legal file hash op in the reference (`CryptOp`
  has only sha1, ripemd160, sha256 and the error is "Unknown unary op tag"): it is
  `unknown_file_hash_op`, a parse error, not "not supported". RIPEMD-160 is legal and read;
  only hashing a *file* with it is declined (step 1 `alg_unsupported`), although the RIPEMD-160 op
  is computed in the tree because 2015 proofs use it.
* Tags `f2` and `f3`: in 0.5.0 `f2` is `reverse` and `f3` is `hexlify`.
* A parse of `incomplete.txt.ots` and every vector must match the structure printed by `ots info`.

## 11. Clarifications (normative)

* The tree is always computed from the digest stored in the proof. When step 1 is PASS that
  digest equals the user's; otherwise the tree is still shown and step 3 is `SKIP`/`not_tied`.
* `input.digest`: mode `file` with header sha256/sha1 = the computed digest (also when it
  mismatches); mode `file` with ripemd160 or with an unparsable proof = null; mode `digest` =
  the user's digest, lower-cased (null if it was not valid hex); mode `none` = null.
  `input.size` = file length in bytes in mode `file`, else null. `input.digest_alg` = the
  proof's header op name when the proof parsed, else null.
* `proof` is null exactly when `error` is not null; `error` is `{code}` with a code from section 4.
* `ledger` is null unless the ledger was requested **and** at least one Bitcoin attestation exists
  in a parsed proof; in the other cases step 4 carries `not_requested`, `no_bitcoin` or `no_proof`
  (checked in that order of preference: `no_proof`, then `not_requested`, then `no_bitcoin`).
* `verdict.block` and `verdict.time` are non-null only when the verdict is PASS.
  `verdict.unverified` lists the indexes of the non-Bitcoin attestations of a parsed proof,
  in index order, whatever the verdict (empty when the proof did not parse).
* A ledger server entry's `status` is FAIL if any of its checks is FAIL, else SKIP if any is SKIP, else PASS.
  `time` and `block_hash` are filled as soon as they are known (for `time`: once `header` passed).
  `header` holds the header hex once it was received and well formed (160 hex characters), even if a later
  check failed; null before.
* Attestations of the Bitcoin kind with `phases == null` still get `block_hash`, `header`, `merkle_root`
  checks, then `txids`, `raw_tx`, `output` SKIP `no_transaction`. Their step-4 contribution is SKIP.
* Step 4 code precedence: if any attestation has `agree == false` the code is `disagree` (even
  if some check also failed); else `check_failed` if any check is FAIL; else `incomplete` if any is SKIP.
* The ledger `plan` lists, per Bitcoin attestation and per server, the requests that can happen: when
  `phases` is null only `block-height` and `header`; otherwise the four URLs (`block-height`, `header`, `txids`,
  `tx/{txid}/hex`), in that order; attestations in file order, servers in server order.
* Step 4 considers only Bitcoin attestations. In `where_to_look`, `{h}` is the attestation height.
* Hash steps: SHA-1, SHA-256, RIPEMD-160 and Keccak-256 are computed with the program's own code or the platform;
  each program must pass the standard vectors in `vectors/hash-vectors.json`.

## 12. Stamping and upgrading (the write half)

Two operations, defined here so that two implementations produce the same bytes and the same log lines.
Neither is part of the report (sections 1-11); they produce or change `.ots` files. Both take their network
access as an injected function `call(url, body?) -> (status, bytes)` that may fail (an I/O error, a timeout);
a failure is the *call* raising, never a status. A body present means POST, absent means GET, and the request
carries `Accept: application/vnd.opentimestamps.v1`.

### 12.1 Constants

* `MAX_CALENDAR_RESPONSE` = 10000 bytes.
* Default calendars (in this order): `https://alice.btc.calendar.opentimestamps.org`,
  `https://bob.btc.calendar.opentimestamps.org`, `https://finney.calendar.eternitywall.com`.
* Known calendars (the only ones `upgrade` may contact unless the person adds one): the three above plus
  `https://btc.calendar.catallaxy.com` and `https://ots.btc.catallaxy.com`.
* `join(base, path)` = `base` with trailing `/` characters removed, then `/`, then `path`.

### 12.2 The commitment

Given the file's SHA-256 `d` (32 bytes) and 16 random bytes `n` (the nonce, injected by the caller):

    m1 = d || n                  (the message after the `append n` op)
    c  = SHA-256(m1)             (the commitment; the ONLY value sent to a calendar)

### 12.3 stamp(d, calendars, call, n) -> .ots bytes

1. Build a timestamp tree: root message `d`; one edge `append n` to a node with message `m1`; one edge `sha256`
   from there to the node `tip` with message `c`.
2. For each calendar in the given order, in sequence:
   a. `call(join(cal, "digest"), c)`. A call failure, a status other than 200, a body longer than
      `MAX_CALENDAR_RESPONSE`, or a body that does not parse as a timestamp (12.5) makes this calendar *fail*:
      log `calendar <cal> failed: <reason>` and go on. `<reason>` is `HTTP <status>` for a bad status, the parse error
      code (section 4) for an unreadable body (`payload_too_long` for a body that is too long), and the failure's
      message text for a call failure.
   b. Otherwise merge (12.4) the parsed timestamp into `tip`, and log `calendar <cal> accepted the commitment`.
3. If no calendar was accepted, fail with the message `no calendar accepted the commitment` (nothing is written).
4. Return the serialization (12.6) of the tree with header operation SHA-256 and digest `d`.

### 12.4 Merge

`merge(into, frag)` adds `frag`'s attestations and edges to the node `into`:

* an attestation is added unless `into` already has one with the same tag and the same payload bytes;
* an edge of `frag` whose operation and argument (both equal; no argument equals no argument) already exist on `into`
  is merged recursively into that edge's node; any other edge is appended.

A proof must not contain the same operation twice at one node (section 4, `repeated_op`), which is why the merge is
not a concatenation: two calendars may use the same nonce.

### 12.5 Parsing a calendar's answer ("fragment")

A body longer than `MAX_CALENDAR_RESPONSE` is rejected with `payload_too_long`, in `stamp` and in `upgrade` alike.
A calendar answers with a bare timestamp (the bytes that follow the digest in an `.ots` file) over the message it was
asked about, `msg`. Parse it exactly as section 3 parses the tree of a proof whose root message is `msg`, with the same
limits and error codes, and with no byte left over (`trailing_garbage`). `msg` may be any length a node can have
(1 to 4096 bytes: real calendar proofs hang their pending attestation on a 44-byte node, a SHA-256 output with a
4-byte prefix and an 8-byte suffix); otherwise the fragment is rejected with `arg_length`.

### 12.6 Serialization

The inverse of section 3. A node is written as its entries joined as follows: every entry except the last is preceded
by `0xff`. Entries are: first the attestations, then the edges.

* Attestations are sorted by (tag bytes, height with null as 0, then the URI bytes if the attestation has a URI,
  otherwise its payload), each compared bytewise / numerically, ascending.
* Edges are sorted by (operation byte, argument bytes with no argument as empty), ascending.
* An attestation entry is `0x00`, the 8-byte tag, then the payload as varbytes. An edge entry is the operation
  byte, then the argument as varbytes if the operation has one, then the child node.
* A node with no entries is an error.

The file is: the 31-byte magic, version byte `0x01`, the header operation byte, the digest bytes, then the root node.

### 12.7 upgrade(proof, call, allowed) -> (bytes, changed, status)

`allowed` is a list of calendar base URLs; a URL is on the list if it is equal to one of them after trailing `/`
characters are removed from both.

1. Parse the proof (a parse failure is raised to the caller with its code).
2. If the proof has a Bitcoin attestation anywhere and no pending attestation anywhere: return the input unchanged,
   `changed = false`, `status = "nothing_to_do"`.
3. For every pending attestation, in tree order (depth first, children in the order the parser created them), with
   `node` the node it hangs on and `uri` its URI:
   a. if `uri` is not on the allowed list: log `not asking <uri>: not on the allowed list (use --allow)`; continue;
   b. `call(join(uri, "timestamp/" + lowercase hex of the node's message))`; a call failure logs
      `<uri> unreachable: <message text>`; continue;
   c. status 404: log `<uri>: not confirmed yet`; continue. Any other status but 200: log `<uri>: HTTP <status>`; continue;
   d. parse the body as a fragment (12.5) over the node's message; a failure logs
      `<uri> sent an unreadable answer: <code>`; continue;
   e. if the fragment has no Bitcoin attestation anywhere: log `<uri>: answer has no Bitcoin attestation yet`; continue;
   f. otherwise remove from the node the pending attestations with that URI, merge the fragment into the node
      (12.4), and remember that something changed.
4. If nothing changed: return the input unchanged, `changed = false`, `status = "pending"`.
5. Otherwise serialize (12.6) with the proof's header operation and digest, check that the result parses (a failure is
   raised), and return it with `changed = true`, `status = "complete"`.

### 12.8 What leaves the machine

`stamp` sends only `c` (12.2) to the calendars that were chosen. `upgrade` sends only a GET whose path contains a
commitment already inside the proof, to a calendar named in the proof that is on the allowed list. The file, its
digest and the nonce are never sent.

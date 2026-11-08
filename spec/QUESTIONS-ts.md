# Questions and choices from the TypeScript implementation

Each entry: section, what is unclear, what the TypeScript side chose. Items marked (resolved) were
answered by a later SPEC revision and are kept for the record. SPEC.md was not edited.

1. Section 3, recursion limit (resolved). First read as 256 ops accepted; corrected to 255 accepted /
   256 rejected. Implemented as the reference does (budget 256, `recursion_limit` when a node is entered with
   budget 0, checked after the op's result is computed, so `result_too_long` of the 256th op wins).
2. Section 3 / 4, short file. "Bad magic (bad_magic)" and "reading past the end (truncated)" both fit a file
   shorter than 31 bytes. Chose `bad_magic` (the reference reads len(MAGIC) bytes and compares). An empty file is `bad_magic`.
3. Section 3, errors inside a known attestation payload (resolved by the coordinator's rule: truncation or
   oversized varuint inside the payload is `bad_attestation_payload`; `bad_uri` for uri length > 1000 or bad
   characters; `height_too_large`). The uri length is checked before the uri bytes are required, so a payload
   `[0xe9 0x07]` (length 1001, no bytes) is `bad_uri`, not `bad_attestation_payload`.
4. Section 3, `empty_message` is unreachable: the root digest is 20/32 bytes and no op returns an empty result,
   so reverse/hexlify never see an empty message. Implemented, but there is no vector that can trigger it.
   `msg_too_long` is reachable only through hexlify (input over 2048); other ops cannot receive more than 4096
   bytes because results are capped at 4096.
5. Section 3, order inside one op entry: tag -> arg varuint/limits -> arg bytes -> `repeated_op` -> op
   application (`msg_too_long`, `empty_message`, `result_too_long`) -> recursion. Same as the reference.
6. Section 5, attestation fields. `height` is filled for bitcoin, litecoin and ethereum (all three carry a
   height payload); `uri` only for pending; `payload` is the raw payload hex for every kind (including known kinds).
   The spec does not say whether litecoin/ethereum heights are reported.
7. Section 6, `phases_code` appears in the text but not in the report (schema has no such field). It is kept
   as an internal value of `computePhases` only. `c == 0` legal, `c == t` -> null (resolved by the coordinator).
8. Section 6, "legacy Bitcoin transaction": version is any 4 bytes; compact sizes are accepted in non-canonical
   encodings (fd/fe/ff forms with small values); sizes above 2^32 are rejected as "not a transaction".
   Input and output counts must be at least 1. The search for `t` only covers `m_1..m_K` of the path.
9. Section 7, plan (resolved). The text said "four URLs, three depend on the block hash", but only header and
   txids do. Implemented per the later clarification: block-height, header (`{block_hash}`), txids
   (`{block_hash}`), `tx/{txid}/hex` (real txid); only the first two when phases is null.
10. Section 7, `not_run` vs `no_transaction`. If phases is null and an earlier check (block_hash, header,
    merkle_root) was not PASS, the three tx checks are `not_run`; only when the earlier checks all passed are
    they `no_transaction`. Both sentences of the spec apply; the stopping rule was taken as the more general one.
11. Section 7, response parsing: "trimmed" = ASCII whitespace (space, \t, \r, \n, \f, \v). Hex bodies (block
    hash, header, tx) are accepted in either case and reported lower-case. The `txids` array must parse as JSON
    (surrounding whitespace allowed), all elements strings, and the txid is matched case-sensitively as the
    lower-case hex string.
12. Section 7, `raw_tx`: if the marker bytes `00 01` follow the version but the witness structure does not
    parse exactly (or the body is not hex), the code is `bad_response` (not `mismatch`).
13. Section 7, `header` check: "bad nBits" = sign bit set, zero mantissa, or a target that overflows 256 bits
    (Bitcoin Core `SetCompact` rules); all give `bad_pow`. `bad_hash` (hash of the header differs from the
    announced block hash) is tested before `bad_pow`. No proof-of-work limit is applied (the synthetic fixtures use nBits 0x207fffff).
14. Section 7, `agree`: "produced a header" = the server entry's `header` field is non-null (well-formed 160 hex),
    even if a later check failed or `bad_hash`/`bad_pow` was raised on it.
15. Section 7, server entries: `time` is set once `header` PASSed (so not after `bad_hash`/`bad_pow`);
    `block_hash` as soon as the block-height body is a valid hash. `base` in `ledger.servers` has trailing slashes
    removed (the spec only says names have none); names are used exactly as the caller passes them.
16. Section 2, verdict `time`/`block`: `block` = lowest height among Bitcoin attestations (first in file order on
    ties); `time` = the first server entry of that attestation with a non-null `time`.
17. Section 2/11, `file_hash` code precedence when the proof does not parse: `no_proof` wins over `no_input`
    (mode none). The spec lists both for that situation; the ledger rule in section 11 puts `no_proof` first, so the same order is used.
18. Section 1/11, option handling: if both a file and a digest are given, the file wins (mode `file`). A
    digest of `""` is mode `digest` with `bad_digest` and `input.digest = null`. Whitespace around a digest is not trimmed
    (callers trim). `proof: null` is treated like an empty file (`bad_magic`).
19. Section 8, canonical JSON: `\u00xx` uses lower-case hex; `\b` and `\f` are written `\u0008`, `\u000c` (only
    `\" \\ \n \r \t` have short forms); DEL (0x7f) and non-ASCII are emitted raw; numbers must be safe integers
    (anything else throws); keys are ordered by code point.
20. Section 9, permalink. When only `ots` is present the fragment is `#ots=B64` (the grammar `[#h=HEX][&ots=B64]`
    read literally would give a bare `&ots=`); parts are joined by `&` after one `#`. Decoding: first occurrence of a key
    wins; `h` must be even-length hex else it decodes to null (lower-cased otherwise); `ots` must be strict unpadded
    base64url (padding, bad characters or non-zero trailing bits give null); `proof` is percent-decoded as strict UTF-8
    (invalid gives null); an empty `proofUrl` or digest is omitted on encoding.
21. Section 2, `hash_steps` can only be `ok`, `not_tied` or `no_proof` in this implementation: every op is
    computed during parsing, so it never FAILs.

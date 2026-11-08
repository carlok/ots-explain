# Questions and choices from the TypeScript stamp/upgrade implementation (SPEC section 12)

Each entry: section, the ambiguity, what `web/src/core/stamp.ts` chose, what the other reading would change.
SPEC.md was not edited. Written from the spec only.

1. 12.7 step 3a versus real proofs (likely a spec bug). In every official vector with a pending attestation
   (`two-calendars`, `incomplete`) the node the attestation hangs on holds a 44-byte message (sha256 output, then a
   4-byte prepend and an 8-byte append added by the calendar), not 32. Step 3a skips such nodes ("the commitment is not
   32 bytes"), so `upgrade` would refuse every real calendar proof and only ever ask about the proofs `stamp` itself
   makes (where the calendar answer is a bare attestation on `c`). Chose: literal (skip). The other reading (no 32-byte
   rule, or a rule for the commitment of the calendar rather than of the node) would let real proofs be upgraded.
   Pinned by the test "upgrade refuses the pending attestations of official proofs".

2. 12.7 step 3, "tree order". "Depth first, children in the order the parser created them" does not say where a
   node's own attestations come in relation to its children, nor whether the order is the file order of attestations
   (which can interleave with edges in a non-canonical file). Chose: a node's own pending attestations first (in file
   order), then its children in creation order, recursively. The other reading (the parser's global attestation order
   = file order) differs only for files whose entries are not attestations-first, and then changes the order of calls
   and log lines.

3. 12.7 step 3, snapshot. Chose: the list of pending attestations is taken once before any request; pending
   attestations that arrive inside a merged answer are not asked in the same run. Also two identical pending
   attestations on one node are both asked (the second answer merges as a no-op). The other reading (re-scan after each
   merge) would make extra calls.

4. 12.5 / 12.3 / 12.7, the 10000-byte limit. `MAX_CALENDAR_RESPONSE` is stated only in 12.3 step 2a. Chose: apply it
   in `stamp` only; in `upgrade` step e a longer body is parsed without a length limit (so a valid answer of 12000
   bytes is accepted by `upgrade` and refused by `stamp`). The other reading (it belongs to "parsing a calendar's
   answer", 12.5) would add `<uri> sent an unreadable answer: payload_too_long` in `upgrade`.

5. 12.3 step 2a, order of checks. Chose: HTTP status first, then length, then parse (a 502 with a 20000-byte body is
   `HTTP 502`). The sentence lists them in that order but does not say which wins.

6. 12.3 failure reason for a call failure: "the failure's message text". In JavaScript this is `error.message`
   for an Error and `String(x)` for anything else. Python's `str(exception)` and the platform's own texts
   (e.g. "fetch failed", "The operation was aborted") will differ between implementations; byte-identical logs for
   real network failures are not achievable, only with injected failures that carry the same text.

7. 12.2 / 12.3, preconditions. The spec says "the file's SHA-256 d (32 bytes)" and "16 random bytes n" but not what
   happens otherwise. Chose: `stampDigest` throws `Error("the digest must be 32 bytes")` / `Error("the nonce must be 16
   bytes")` before any call. The other reading (no check) would send a commitment over other lengths and, for a digest
   not 32 bytes, write a file that does not parse. `commitmentFor` does not check.

8. 12.3 step 3, an empty calendar list. Same outcome as "no calendar accepted": throws `no calendar accepted the commitment`.

9. 12.3 step 2a, the `<cal>` in the log line is the string as passed (not normalised); only the URL used for the
   request has trailing `/` removed. Same for `<uri>` in the upgrade log lines (the URI as stored in the proof).

10. 12.4, appended edges. "Any other edge is appended" is read as appended as it is, with its whole subtree,
    without de-duplicating attestations inside that subtree (only attestations merged into an existing node are
    de-duplicated). The other reading (merge into a fresh empty node, which de-duplicates everywhere) differs only when
    one calendar answer contains the same attestation twice on one node below a new edge. Such a duplicate is then
    written twice.

11. 12.4, the attestation identity is (tag, payload bytes). Two Bitcoin attestations for the same height with different
    varuint spellings are different attestations and both kept.

12. 12.6, attestation sort key. "(tag bytes, height with null as 0, then the URI bytes if the attestation has a URI,
    otherwise its payload)". Chose: bytewise lexicographic (a prefix sorts first) for tag, URI and payload; numeric
    for height; "has a URI" = kind pending. Ties on the whole key (e.g. two pending attestations with the same URI but
    different payload spellings) keep their insertion order (stable sort); the spec says nothing about them.

13. 12.6, a node with no entries is "an error": chose `Error("a timestamp node has no entries")`; the spec names no
    message. It cannot happen through `stamp` or `upgrade` (a merged answer always carries an entry).

14. 12.6 vs section 3 wording. Section 3 writes `{ 0xff entry } entry`; 12.6 writes "every entry except the last is
    preceded by 0xff". Same bytes (`ff e1 ff e2 e3`); noted because "joined as follows" in 12.6 reads like a separator
    and a first implementation of this file wrote the `ff` after each entry, which the section-3 parser rejects.

15. 12.7 step 2. A proof with neither a Bitcoin nor a pending attestation (only unknown/litecoin/ethereum ones) is not
    `nothing_to_do`: it goes on, finds nothing to ask, and returns `status = "pending"`, `changed = false`. The other
    reading would return `nothing_to_do`.

16. 12.7 step 3g. "Remove the pending attestations with that URI": URI compared as the stored string, exactly (no
    trailing-slash normalisation, unlike the allow-list). Removal is on that node only. Removal happens before the merge,
    so a pending attestation of the same URI in the answer (which is accepted if the answer also has a Bitcoin one) is
    merged back in.

17. 12.7 step 5. "Check that the result parses (a failure is raised)": raised as the parse error itself (`ParseError`,
    message = code), as for step 1. This is reachable: merging a deep answer under a node that is already deep exceeds
    255 ops (`recursion_limit`). `stamp` does not re-check its output the same way, so a 255-op answer (accepted as a
    fragment) yields a 257-op file that does not parse; 12.3 does not ask for the check.

18. 12.5, "msg must be 32 bytes, otherwise rejected with arg_length". Implemented as the first check in the fragment parser.
    Not reachable from `stamp` (c is 32 bytes) nor from `upgrade` (step 3a skips other lengths first).

19. 12.1 `join(base, path)` is applied to the URL for requests only; `allowed` entries and proof URIs are
    compared after removing trailing `/` from both sides (so `https://x//` equals `https://x`), never anything else
    (no case folding, no scheme or default-port normalisation).

20. 12 intro: the `Accept: application/vnd.opentimestamps.v1` header is the responsibility of the injected `call` (the
    TypeScript functions never see headers); the tests do not check it.

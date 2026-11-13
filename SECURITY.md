# Security policy

## What this project is, security-wise

A verifier that explains a timestamp proof. A wrong **PASS** (saying a file was proved when it was not) is the
serious bug class here; so is any way to make the page or the scripts send data they should not.

In scope:
* a proof, file name or server response that makes either implementation print PASS wrongly, crash, hang or use unbounded memory;
* the page making a network request the person did not approve, or loosening its CSP;
* the Python or TypeScript implementation disagreeing with the other on a valid input (that is a conformance bug, report it too).

Out of scope: "not SPV" (documented in the README), and the trust you place in the explorers you choose.

## Reporting

Please report privately through GitHub's "Report a vulnerability" (Security tab → Advisories), or contact the
maintainer on GitHub at [@carlok](https://github.com/carlok) for coordination if advisories are not yet enabled. Do
not open a public issue for a wrong-PASS bug before it is fixed. Expect an acknowledgement within a week; this is a
one-person project.

## Supported versions

Only the latest release.

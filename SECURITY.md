# Security policy

## What this project is, security-wise

A verifier that explains a timestamp proof. A wrong **PASS** (saying a file was proved when it was not) is the
serious bug class here; so is any way to make the page or the scripts send data they should not.

In scope:
* a proof, file name or server response that makes either implementation print PASS wrongly, crash, hang or use unbounded memory;
* the page making a network request the person did not approve, or loosening its CSP;
* the Python or TypeScript implementation disagreeing with the other on a valid input (that is a conformance bug, report it too).

Out of scope: "not SPV" (documented in the README), and the trust you place in the explorers you choose.

## Reporting vulnerabilities

Report security issues **privately**. Do **not** open a public GitHub issue for a vulnerability.

Use GitHub private vulnerability reporting:

1. Open the repository **Security** tab.
2. Choose **Report a vulnerability**, or go directly to
   [https://github.com/carlok/ots-explain/security/advisories/new](https://github.com/carlok/ots-explain/security/advisories/new).

Expect an acknowledgement within a week; this is a one-person project.

## Supported versions

Only the latest release.
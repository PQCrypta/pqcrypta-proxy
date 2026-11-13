# Security policy

## Reporting a vulnerability

Report it privately, through GitHub's
[private vulnerability reporting](https://github.com/PQCrypta/pqcrypta-proxy/security/advisories/new)
for this repository, or by email to contact@pqcrypta.com. Please do not open a
public issue for it: a report in the open reaches everyone running the proxy
before a fix does.

A useful report names the version or commit, the configuration the finding
needs (or that it needs none), what a client sends, and what the proxy does
with it. A reproduction against a local build is welcome; please do not test
against hosts you do not operate.

## What happens next

- An acknowledgement within three days.
- The finding reproduced and assessed, and a fix developed in private.
- A release carrying the fix, and a GitHub security advisory that names the
  affected and fixed versions and credits the reporter (unless they would
  rather not be named).

## Supported versions

Fixes are made on `main` and released as the next version; the latest release
is the supported one. Releases are tagged `v<version>` and listed under
[Releases](https://github.com/PQCrypta/pqcrypta-proxy/releases), with the
binary and container image they publish.

# zentinel-modsec, vendored

A pure-Rust SecLang engine that runs the OWASP Core Rule Set.

Base: <https://github.com/zentinelproxy/zentinel-modsec> at `8ba8099`
(2026-11-20, "Keep TX score variables set by rules when a phase ends (#81)"),
version 0.6.0 unreleased.

The changes from that commit:
- **`src/libinjection/`**: the operators `@detectSQLi` and `@detectXSS` call
  libinjection itself, through `barbacane-libinjection` 0.1.3 (a memory-safe
  port of the C library), in place of this crate's simplified detector. That
  detector called ordinary crawler User-Agents SQL injection. Replaying
  109,983 requests pqcrypta.com served, CRS rule 942100 would have blocked
  48,676 of them on the User-Agent alone. C libinjection v4.0.2 flags none of
  those User-Agents, and the port matches it on every input checked: 34,293
  (CRS's regression payloads and the replayed requests), with no verdict and
  no fingerprint differing.
- **`Transaction::remove_rules_by_id`**: `ctl:ruleRemoveById` for the
  embedding application, which excludes rules per request from what it knows
  and the rules do not. The proxy lifts CRS's scanner detection (913) where it
  lifts its own user-agent rules: its own monitoring's addresses, crawler
  paths, routes that serve tools.
- **`ctl:ruleRemoveTargetByTag`**: CRS's 941010 removes REQUEST_FILENAME
  from its XSS rules (tag `xss-perf-disable`) when the path holds only
  characters no XSS needs; the directive was reported as unsupported on
  nearly every request and the path inspected anyway.
- **Request bodies as ModSecurity reads them**: an XML body fills the XML
  collection (what `XML:/*` and `XML://@*` read), not ARGS; `REQUEST_BODY`
  holds the raw body after the URLENCODED or JSON processor or when
  `ctl:forceRequestBodyVariable=On` (implemented here; CRS's 901340 sets it
  for a body no processor parses), not an XML or multipart one;
  `REQBODY_PROCESSOR` is known from the request's head, so phase 1 reads it
  (901340 decides there), and is present, empty, when no processor applies.
  XML element names in ARGS_NAMES and raw XML in REQUEST_BODY were what CRS's
  944 tests (a payload in an element's name) failed on: 30 false positives.
- **`ctl:ruleRemoveByTag`** (CRS's 905100 and 905110), and **`UNIQUE_ID`**,
  the embedding application's request ID when it sets one
  (`Transaction::set_unique_id`). A multipart body whose Content-Type names
  no boundary is a body error (REQBODY_ERROR), as in ModSecurity, rather
  than a warning per request.
- **Regular-expression selections compare keys case-insensitively**
  (`TX:/.../`, `ARGS:/.../`, and in exclusions), as a key selection does and
  as ModSecurity does: TX keys are stored lowercased, so CRS's 922110 never
  found the multipart content types its 922150 recorded.
- **The multipart processor** (`src/variables/multipart.rs`) is
  libmodsecurity v3's: the boundary checked in the Content-Type, the body
  read as bytes line by line, part headers and Content-Disposition parsed as
  strictly (quoting, `filename*`, duplicates, folding), and the flags
  behind `MULTIPART_STRICT_ERROR` and the other `MULTIPART_*` variables,
  which resolved to nothing before (a rule like 200003 could never fire),
  with `FILES_SIZES` and `FILES_COMBINED_SIZE`. Two departures: an empty
  boundary is an error, where v3 stops silently and leaves the body
  uninspected; and the file limit is never reached, since v3 checks it only
  when writing uploads to disk, which this engine never does.
- **md-5, sha1, sha2 0.11**, the RustCrypto release the proxy builds with,
  in place of 0.10: one copy of each in the build.
- **`benches/`** removed, with the bench target, its feature and `criterion`:
  they compared against libmodsecurity through FFI and were this crate's only
  `unsafe` code.

`tests/crs_conformance.rs` gates the engine on CRS's own regression corpus
(CRS 30cb436): 5019 of 5184 cases pass here, 4947 upstream, and no case
upstream passes fails here. The proxy's CI runs this crate's tests and that
gate (`zentinel-modsec fork tests`).

To move to a newer upstream commit: copy it over this directory (`git archive
<commit> | tar -x`), keep `src/libinjection/` and every change listed above, and this file, drop `benches/`
again, and rerun `tests/crs_regression.rs` in the proxy.

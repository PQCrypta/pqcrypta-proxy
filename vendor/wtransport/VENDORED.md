# wtransport (vendored fork, with ../wtransport-proto)

Upstream: [BiagioFesta/wtransport](https://github.com/BiagioFesta/wtransport),
`master` at b16674e (2026-09-22: 0.7.2 and its driver fix, "stop the SETTINGS
handshake when the driver is dropped"), with this proxy's changes merged in.
Kept: the `wtransport` and `wtransport-proto` crates, each a standalone
manifest (no upstream workspace).

## What is this fork's own

- QUIC from `vendor/noq` instead of quinn: `quinn = { package = "noq", ... }`,
  with the few call sites noq's API differs at (a path's address and RTT by
  `PathId::ZERO`; no `ReadError::IllegalOrderedRead`).
- A rejected WebTransport request ends both halves of its stream; the
  oversized field-section test sizes past the client's own limit;
  `StreamBiRemoteH3::stop`, unused since `reject()`, dropped.
- `SessionRequest::quic_connection()` (the handshake's outcome before a
  session is accepted) and `SessionRequest::misdirected_request()` (421),
  with `SessionResponseProto::misdirected_request()`.
- `[patch.crates-io] rustls = ../rustls-fixed/rustls` in its own manifest, so
  `cargo test --manifest-path vendor/wtransport/Cargo.toml` builds against the
  rustls the proxy uses; Cargo ignores it when the proxy builds wtransport.

The race upstream fixed in `close_reason()` (b024c08) the fork had also
patched; upstream's version is the one kept.

## Updating it

Taken at 0.6.1 (2026-01-22), carried to 0.7.0, and moved onto b16674e on
2026-11-11 by a three-way merge in a clone of upstream: branch at the base
(b16674e now), commit these two directories over it, merge upstream's newer
`master` or tag, resolve, copy back, and run
`cargo test --manifest-path vendor/wtransport/Cargo.toml --lib`.

# noq (vendored fork)

Upstream: [n0-computer/noq](https://github.com/n0-computer/noq), `main` at
2f3ba68 (2026-11-09; the workspace says 1.5.0, after the 1.4.0 release), with
this proxy's changes merged in. Kept: the `noq`, `noq-proto` and `noq-udp`
crates, the workspace manifest and the licences. Not kept: upstream's book,
CI, benches, fuzzing and perf tools (the workspace's `members` name the three
crates only).

The proxy aliases it as `quinn` / `quinn_proto`, and `vendor/h3-noq` and
`vendor/wtransport` run on it. The workspace manifest patches rustls to
`../rustls-fixed/rustls` so `cargo test --manifest-path vendor/noq/Cargo.toml`
builds the fork against the rustls it is written for; Cargo ignores that patch
when the proxy builds noq as a dependency.

## What is this fork's own

- QUIC version 2 (RFC 9369), with v1 and v2 both offered.
- What the proxy reads off a connection: the ClientHello as sent and whether
  ECH was accepted (rustls-fixed's additions), for fingerprinting.
- Hooks the HTTP/3 conformance suite drives: an unknown frame type once the
  handshake is established, an invalid transport parameter, a PATH_CHALLENGE
  probe, the peer's per-stream limit (`SendStream::peer_max_data`), 0-RTT
  counted per connection.
- `Connection::is_settled`: nothing queued or unacknowledged, so a stream-level
  signal (a STOP_SENDING) reaches the peer before a close.
- A client that rejects the server's handshake says so with CONNECTION_CLOSE.
- 1-RTT frames sent as 0.5-RTT data right behind the server's Handshake flight
  (an HTTP/3 server's SETTINGS arrive with the handshake), and no stall after a
  HelloRetryRequest.
- Owed ACKs ride on packets that leave anyway; a lone request is acknowledged
  at once; runs of PADDING decoded in one step; transmits coalesced.
- ECN given up where UDP GRO is on.
- A NEW_TOKEN for a client's new address after it migrates.
- Before the first RTT sample, the pacer's burst may be the initial window
  (RFC 9002 section 7.7), so a two-datagram post-quantum ClientHello and a
  server's first flight are not split by the initial RTT. (The handshake
  snapshot test counts one more server packet than upstream for this: the
  NEW_CONNECTION_IDs leave as 0.5-RTT data instead of waiting for
  HANDSHAKE_DONE's packet.)
- BBRv3 told when the sender runs dry (`Controller::on_app_limited`), so a flow
  of small packets is not read as the path's bandwidth.
- Event streams that end with their connection; `PathId::get`; a seeded test
  pair.
- An Initial whose Retry token differs from the connection's is logged at
  debug, not warn: the packet is the peer's (or a spoofer's) to send, one line
  each.

## Updating it

The fork was taken at upstream 5cf07f4 (1.1.0 and four commits) on 2026-07-24
and moved onto 2f3ba68 on 2026-11-11 by a three-way merge rather than a patch
replay: the fork's changes came in through merged pull requests, so
`git format-patch` over this repository's history skips the merges and
reorders what was developed in parallel. In a clone of upstream:

1. Branch at the base this copy was merged onto (2f3ba68 now) and commit this
   directory's three crates and manifest over it.
2. `git merge` upstream's newer `main` (or release tag) into that branch; each
   conflicting region comes up once.
3. Where the fork carries a backport of an upstream change (BBRv3 pacing,
   #785, was one), take upstream's version and re-apply only what is the
   fork's own on top.
4. Copy the three crates and the manifest back here, run noq's own tests
   (`cargo test --manifest-path vendor/noq/Cargo.toml -p noq-proto -p noq --lib`)
   and update this file's base.

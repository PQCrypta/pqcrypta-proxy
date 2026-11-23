# Media over QUIC

pqcrypta-proxy includes a Media over QUIC relay (MOQT,
[draft-ietf-moq-transport](https://datatracker.ietf.org/doc/draft-ietf-moq-transport/)).
Publishers send tracks to it, and subscribers receive them in real time or
fetch what was already published. It runs on the QUIC listener beside HTTP/3
and DNS over QUIC. Configuration: [`[moq]` in CONFIG.md](CONFIG.md#media-over-quic).

## Versions

The relay keeps the two newest drafts working at once:

| Version | ALPN / WebTransport protocol |
|---------|------------------------------|
| draft-ietf-moq-transport-23 | `moqt-23` |
| draft-ietf-moq-transport-22 | `moqt-22` |

The table is `src/moq/version.rs`. Nothing else in the proxy names a draft
number: the QUIC listener's ALPN list, WebTransport negotiation, `/moq` and
`/metrics` all read it. When a draft is published, it becomes a new entry
with its wire differences in the codec, and the oldest entry is retired. A
session uses the newest version both sides offer.

The differences between 22 and 23 that the codec handles:

- control message lengths (16 bits in 22, a varint in 23);
- FETCH_OK in 22, REQUEST_OK in 23;
- FORWARD in 22, PAUSED in 23;
- the encoding of FILL_PARAMETERS;
- REQUEST_ERROR's Redirect (22) versus its Error Details (23);
- NAMESPACE's parameters;
- the FETCH stream's End of Range encoding, Object ID deltas, and the Gone,
  End of Group and End of Track indicators;
- MAX_CONTROL_MESSAGE_SIZE;
- SUBSCRIBE_TRACKS_ID;
- the session error codes 23 adds (draft 22 closes with PROTOCOL_VIOLATION
  instead).

## Entrances

A client reaches the relay by protocol negotiation, never by port:

| Entrance | How the version is chosen |
|----------|---------------------------|
| Native QUIC on the QUIC listener's port | The client offers `moqt-23` and/or `moqt-22` in ALPN |
| WebTransport on the HTTP/3 port | Extended CONNECT to `[moq] path` (`/moq`), with `WT-Available-Protocols: "moqt-23", "moqt-22"`; the answer's `WT-Protocol` names the one chosen |
| WebTransport on the WebTransport server's port | The same |

- **QUIC listener:** a client that offers only versions the relay does not
  speak gets `no_application_protocol` in the handshake. A native session
  starts once the handshake completes, so nothing replayed in 0-RTT data
  starts an upstream subscription (section 6.3.1).
- **WebTransport:** a CONNECT that offers no shared version is answered 400.
  These sessions pass the same checks as any WebTransport session: rate
  limits, WAF, blocklist, route gates and Origin validation.
- **Native QUIC PATH and AUTHORITY:** a client may name `[moq] path` or one
  of `extra_paths` in PATH, and any host (or one of `authorities`) in
  AUTHORITY. Anything else closes the session with INVALID_PATH or
  INVALID_AUTHORITY, and a malformed value with MALFORMED_PATH or
  MALFORMED_AUTHORITY.

## What the relay does

### Sessions

Each session opens one control stream with SETUP. The relay's SETUP sends:

- MOQT_IMPLEMENTATION (`pqcrypta-proxy/<version>`);
- MAX_REQUEST_UPDATES, MAX_FILTER_RANGES and MAX_AUTH_TOKEN_CACHE_SIZE;
- in draft 23, MAX_CONTROL_MESSAGE_SIZE when it is configured above 65535.

Unknown Setup Options are ignored. A request or data stream that arrives
before SETUP waits for it (section 6.3). With no SETUP within 10 seconds, the
session closes with CONTROL_MESSAGE_TIMEOUT. Closing either control stream
closes the session with CLOSED_CONTROL_STREAM. On shutdown the relay sends
GOAWAY and refuses new requests with GOING_AWAY. After `goaway_timeout_ms` it
closes with GOAWAY_TIMEOUT.

A WebTransport session ends with its CONNECT stream, with WT_CLOSE_SESSION
from either end, or with its connection. However it ends, its namespaces are
withdrawn, its tracks lose it as a publisher and it leaves `/moq/sessions`
and `sessions_open`.

### Requests

Each request is one bidirectional stream, and every request type is served:

- SUBSCRIBE;
- FETCH (both standalone and as a subscription's fill);
- TRACK_STATUS;
- PUBLISH;
- PUBLISH_NAMESPACE;
- SUBSCRIBE_NAMESPACE;
- SUBSCRIBE_TRACKS;
- REQUEST_UPDATE on each request it applies to.

Request IDs are checked for parity and reuse (INVALID_REQUEST_ID). Parameters
are checked against what each message allows (INVALID_PARAMETER). Range
Filters are checked against MAX_FILTER_RANGES and their own rules, and a
failure is the request's own error (INVALID_FILTER), not the session's.

Some namespaces are refused with DOES_NOT_EXIST:

- the reserved `.` namespace (section 2.4.3);
- session-level `.session` namespaces, since the relay defines none
  (section 6.5).

### Tracks and the cache

The relay holds one cache and one set of subscribers per track. A track's
objects arrive once, from however many publishers, and are deduplicated by
Location (section 7.3). They then go out to every subscription whose filters
they pass:

- objects that arrived on a subgroup stream go out on subgroup streams;
- datagram objects go out as datagrams.

Payloads and Object Properties are forwarded unchanged (section 7.9).
An object is sent on an open downstream stream only when it is the next
object of that subgroup (section 11.3.2); otherwise the stream is reset and a
new one opened. Stream priorities follow section 5.1:

1. subscriber priority;
2. publisher priority;
3. group order.

The cache is bounded in bytes across all tracks, oldest first, and honours
MAX_CACHE_DURATION (section 10.3). A copy of a cached object with a
different payload, priority or delivery mode makes the track malformed. So
does an object past its group's or track's end. The track's subscribers are
then ended with MALFORMED_TRACK, and nothing of it is cached (section 12.1).

### Reaching a publisher

A SUBSCRIBE for a track with no publisher is sent upstream to every
publisher whose PUBLISH_NAMESPACE matches the namespace (section 7.7). The
relay answers SUBSCRIBE_OK only once an upstream subscription is established.
With no matching publisher, a SUBSCRIBE is refused with DOES_NOT_EXIST, or,
when it carries RENDEZVOUS_TIMEOUT, held up to that time (capped at
`rendezvous_max_ms`) for one to arrive. An upstream subscription that nobody
downstream has used for 30 seconds is cancelled.

### Relay to relay

With `[moq] upstream = "moqt://host[:port]/path"`, the relay asks another
relay for every namespace no local publisher advertises. It opens a client
session over native QUIC on the first request that needs one, offering every
version it speaks, with AUTHORITY and PATH from the URI in its SETUP. Through
that session it SUBSCRIBEs and FETCHes exactly as through a local publisher.
A set of relays configured this way behaves as one relay (section 7): an edge
holds one upstream subscription per track for all of its subscribers.

### FETCH

A FETCH is answered from the cache in the requested group order. Objects the
cache lacks are first fetched from a publisher, within FILL_TIMEOUT (capped
at `fill_timeout_ms`), and cached. The FETCH stream then marks what still
cannot be vouched for:

- Unknown;
- Timed-Out (draft 23);
- Gone, where a publisher said so.

Draft 23 responses also carry End of Group and End of Track where they are
known. A relative Location Filter in a FETCH is refused with INVALID_RANGE
(section 3.2).

## Publishing

Subscribing is open, held to the per-address rate limits. Publishing is not:
PUBLISH and PUBLISH_NAMESPACE need an AUTHORIZATION_TOKEN, in the request or
in SETUP. Its value names a namespace prefix and an expiry, signed with
`[moq] publish_key` (HMAC-SHA-384):

```text
v1.<prefix>.<expiry, Unix seconds>.<HMAC-SHA-384 of "v1.<prefix>.<expiry>", hex>
```

`<prefix>` is the namespace in section 8.8's serialized form. A token
authorizes that prefix and every namespace under it, and nothing else
(section 7.7). Use Token Type 0 (out of band), Alias Type USE_VALUE, or
REGISTER to reuse it by alias. Issue a token with the configuration's key:

```bash
pqcrypta-proxy --config /etc/pqcrypta/proxy-config.toml --moq-token music-radio --moq-token-days 30
```

A refused publish is answered UNAUTHORIZED, EXPIRED_AUTH_TOKEN or
MALFORMED_AUTH_TOKEN. The token cache follows section 8.9: REGISTER, DELETE,
USE_ALIAS and USE_VALUE are supported, with these errors:

- AUTH_TOKEN_CACHE_OVERFLOW past MAX_AUTH_TOKEN_CACHE_SIZE (in SETUP, a
  registration over the limit is used as a value instead);
- DUPLICATE_AUTH_TOKEN_ALIAS;
- UNKNOWN_AUTH_TOKEN_ALIAS;
- ROLE_VIOLATION for DELETE or USE_ALIAS in a client's SETUP.

## Observing it

| Where | What |
|-------|------|
| `GET /moq` (admin) | Versions, open sessions, tracks, namespaces, cached bytes, counters |
| `GET /moq/sessions` | Each session: peer, transport (`quic`/`webtransport`), version, the peer's MOQT_IMPLEMENTATION, path |
| `GET /moq/tracks` | Each track: Largest Object, publishers, subscribers, cached bytes, malformed |
| `GET /moq/namespaces` | Advertised namespaces |
| `/metrics` | `pqcrypta_moq_*` counters and gauges, `pqcrypta_moq_version_info{version}`, and native MOQT connections under `pqcrypta_connections_by_protocol{protocol="moqt"}` |
| `/metrics/json` | The same figures under `moq` |
| The log (INFO) | One line per session as it ends: its transport and version, how far SETUP got each way, the requests it opened by type, and what ended it (the relay's session error, the peer, or the transport) |

## WebTransport details

- **Error codes:** stream error codes on WebTransport are carried in HTTP/3's
  WT_APPLICATION_ERROR range (draft-ietf-webtrans-http3 section 4.4) on both
  WebTransport ports.
- **Ending a session:** a session ends with a WT_CLOSE_SESSION capsule and
  the CONNECT stream's FIN, never by closing the QUIC connection under other
  sessions.
- **Resetting a stream:** a data stream the relay opened is reset with
  RESET_STREAM_AT (draft-ietf-quic-reliable-stream-reset), its reliable size
  the WebTransport stream header (section 4.4), so the peer can still tell
  which session the stream belonged to. If the peer does not support
  RESET_STREAM_AT, RESET_STREAM is used instead. The proxy advertises the
  `reset_stream_at` transport parameter on every connection.

## Conformance

Every normative statement (MUST, SHOULD, MAY) of the drafts this relay
implements is tracked in a requirements matrix generated from the drafts'
XML. Each row is covered by a test here, by an external check, or recorded as
not observable. The relay's tests are in `src/moq/` (codec, message, data,
relay and session unit tests, and `e2e.rs`, which runs publishers and
subscribers against the relay over real QUIC connections in both drafts).

## Known limits

- **WebTransport over HTTP/2:** not offered; MOQT runs over QUIC only.

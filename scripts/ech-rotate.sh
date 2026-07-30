#!/usr/bin/env bash
# ech-rotate.sh — Rotate the server-side Encrypted Client Hello (ECH) keypair
#
# Runs `ech-keygen` (built from this same crate, `src/bin/ech-keygen.rs`) to
# generate a fresh HPKE keypair + ECHConfig, prune expired ones, and
# reassemble the ECHConfigList to publish via DNS.
#
# The QUIC/HTTP3 listener picks up the new config automatically, with zero
# downtime, via the proxy's existing certificate-reload poller (which now
# also watches the ECH configs directory — see `TlsProvider::needs_reload`
# in src/tls.rs). The plain TCP+TLS (HTTP/1.1, HTTP/2) listeners built in
# src/http_listener.rs currently only pick up a new ECH config when they are
# next (re)built — in practice, on proxy restart. Pass --restart-proxy to
# have this script trigger that restart itself; left off by default so a
# routine rotation never causes a connection-dropping restart on its own.
#
# Setup:
#   1. cp ech-rotate.sh /usr/local/bin/pqcrypta-ech-rotate
#   2. chmod +x /usr/local/bin/pqcrypta-ech-rotate
#   3. cp ech-rotate.service ech-rotate.timer /etc/systemd/system/
#   4. systemctl enable --now pqcrypta-ech-rotate.timer
#
# Does NOT publish the resulting ECHConfigList to DNS itself, and on GoDaddy
# it cannot: their DNS API has no HTTPS/SVCB record type at all. Verified
# 2026-07-29 against api.godaddy.com/v1/domains/pqcrypta.com/records/:
#
#   HTTPS | SVCB | TYPE65  ->  422 INVALID_VALUE_ENUM
#     "type not any of: A, AAAA, CAA, CNAME, MX, NS, SOA, SRV, TXT"
#   A (control)            ->  200
#
# So the `ech=` SvcParam can only be edited by hand in GoDaddy's web UI —
# which is also what corrupts commas in multi-value SvcParams (the reason
# our alpn= lists h3 only; see public/http3-quic/DNS_HTTPS_RECORDS.md for
# the RFC 9460 §7.1.1 `key1="\002h3\002h2"` comma-free workaround).
#
# This is why ech-rotate.timer is deliberately NOT installed: rotating a key
# that cannot be published to DNS breaks ECH instead of strengthening it.
# After each manual run, copy ech-config-list.b64 into the record by hand.
#
# To make rotation automatic, move DNS hosting to a provider whose API
# supports type 65 (deSEC, Cloudflare, Route 53, Bunny, DNSimple, Gandi
# LiveDNS) — repointing NS is enough, no domain transfer — then publish
# ech-config-list.b64 from here and enable the timer.

set -euo pipefail

OUT_DIR="${ECH_CONFIG_DIR:-/etc/pqcrypta/ech-configs}"
BIN="${ECH_KEYGEN_BIN:-/usr/local/bin/pqcrypta-ech-keygen}"
LOG_FILE="${LOG_FILE:-/var/log/pqcrypta/ech-rotate.log}"
RESTART_PROXY=0

for arg in "$@"; do
    case "$arg" in
        --restart-proxy) RESTART_PROXY=1 ;;
        *) echo "unknown argument: $arg" >&2; exit 1 ;;
    esac
done

log() { echo "$(date -u '+%Y-%m-%dT%H:%M:%SZ') $*" | tee -a "$LOG_FILE"; }

mkdir -p "$OUT_DIR" "$(dirname "$LOG_FILE")"

if [[ ! -x "$BIN" ]]; then
    log "ERROR: $BIN not found or not executable. Build with: cargo build --release --bin ech-keygen && install -m755 target/release/ech-keygen $BIN"
    exit 1
fi

log "Rotating ECH config in $OUT_DIR"
"$BIN" --out-dir "$OUT_DIR" --public-name pqcrypta.com --max-name-length 32 --retain 3 >>"$LOG_FILE" 2>&1

if [[ "$RESTART_PROXY" == "1" ]]; then
    log "Restarting pqcrypta-proxy so the TCP+TLS listeners pick up the rotated config"
    systemctl restart pqcrypta-proxy
fi

log "ECH rotation complete"

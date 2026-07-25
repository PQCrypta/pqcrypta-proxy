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
# Does NOT publish the resulting ECHConfigList to DNS itself — GoDaddy API
# support for HTTPS/SVCB (TYPE65) records was not confirmed working at the
# time this was written (see ech-config generation research notes). Until
# that's resolved, publish scripts/ech-configs/ech-config-list.b64 to the
# `ech=` SvcParam of pqcrypta.com's HTTPS DNS record by hand, or wire in
# automated publishing here once GoDaddy support is verified.

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

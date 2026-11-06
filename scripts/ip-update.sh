#!/usr/bin/env bash
# ip-update.sh — a node's public address for the speedtest location list
#
# Records the node's public address and heartbeats the site that lists it, so
# the speedtest location stays marked available. DNS is not updated here: the
# DNS host reads the node's address over the tunnel and publishes it on its
# own name servers.
#
# Setup:
#   1. Create /etc/pqcrypta/ip-update.conf (see template below)
#   2. Install: cp ip-update.sh /usr/local/bin/pqcrypta-ip-update
#   3. chmod +x /usr/local/bin/pqcrypta-ip-update
#   4. cp ip-update.service ip-update.timer /etc/systemd/system/ (as
#      pqcrypta-ip-update.service/.timer), then
#      systemctl enable --now pqcrypta-ip-update.timer
#
# The unit runs it as a dynamic account: the config reaches it as a credential
# (IP_UPDATE_CONF), the address it last saw is its state directory's, and it
# logs to the journal.
#
# /etc/pqcrypta/ip-update.conf template:
# ----------------------------------------
# NOTIFY_URL="https://pqcrypta.com/speedtest/locations.php"
# NOTIFY_TOKEN="<shared-token-from-pqcrypta.com-config>"
# LOCATION_ID="us-midwest"

set -euo pipefail

CONF="${IP_UPDATE_CONF:-/etc/pqcrypta/ip-update.conf}"

if [[ ! -r "$CONF" ]]; then
    echo "ERROR: $CONF not found. See script header for setup instructions." >&2
    exit 1
fi

# shellcheck source=/dev/null
source "$CONF"

: "${NOTIFY_URL:?NOTIFY_URL not set in $CONF}"
: "${NOTIFY_TOKEN:?NOTIFY_TOKEN not set in $CONF}"
: "${LOCATION_ID:=us-midwest}"
IP_FILE="${STATE_DIRECTORY:-/var/lib/pqcrypta-ip-update}/current-ip"

log() { echo "$(date -u '+%Y-%m-%dT%H:%M:%SZ') $*"; }

mkdir -p "$(dirname "$IP_FILE")"

# ── Detect current public IP ──────────────────────────────────────────────
CURRENT_IP=""
for probe in "https://api.ipify.org" "https://ipv4.icanhazip.com" "https://checkip.amazonaws.com"; do
    CURRENT_IP=$(curl -sf --max-time 5 "$probe" | tr -d '[:space:]' || true)
    if [[ "$CURRENT_IP" =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
        break
    fi
done

if [[ ! "$CURRENT_IP" =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
    log "ERROR: Could not determine public IP"
    exit 1
fi

# ── Compare to stored IP ──────────────────────────────────────────────────
STORED_IP=$(cat "$IP_FILE" 2>/dev/null || echo "")
if [[ "$CURRENT_IP" != "$STORED_IP" ]]; then
    log "IP changed: ${STORED_IP:-none} -> $CURRENT_IP"
    echo "$CURRENT_IP" > "$IP_FILE.new"
    mv -f "$IP_FILE.new" "$IP_FILE"
fi

# ── Always heartbeat (keeps the location marked available) ────────────────
# The body, token included, goes to curl on stdin, never on a command line.
# A failed heartbeat fails the run: the location drops off the list until one
# succeeds, and the failure is the unit's to report.
NOTIFY_STATUS=$(printf '{"action":"update_ip","location_id":"%s","ip":"%s","token":"%s"}' \
        "$LOCATION_ID" "$CURRENT_IP" "$NOTIFY_TOKEN" \
    | curl -s -o /dev/null -w "%{http_code}" --max-time 20 \
        -X POST "$NOTIFY_URL" \
        -A "pqcrypta-ip-update/1.1 ($LOCATION_ID heartbeat)" \
        -H "X-Health-Check-Bypass: 1" \
        -H "Content-Type: application/json" \
        --data-binary @- || true)

if [[ "$NOTIFY_STATUS" != "200" ]]; then
    log "ERROR: heartbeat failed (HTTP $NOTIFY_STATUS)"
    exit 1
fi

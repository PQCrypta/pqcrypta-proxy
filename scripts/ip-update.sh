#!/usr/bin/env bash
# ip-update.sh — Dynamic IP updater for tcp2.pqcrypta.com
#
# Runs on remotellm. Detects public IP changes, updates GoDaddy DNS, then
# notifies pqcrypta.com so the speedtest location list stays accurate.
#
# Setup:
#   1. Create /etc/pqcrypta/ip-update.conf (see template below)
#   2. Install: cp ip-update.sh /usr/local/bin/pqcrypta-ip-update
#   3. chmod +x /usr/local/bin/pqcrypta-ip-update
#   4. Enable timer: systemctl enable --now pqcrypta-ip-update.timer
#
# /etc/pqcrypta/ip-update.conf template:
# ----------------------------------------
# GODADDY_KEY="<your-godaddy-api-key>"
# GODADDY_SECRET="<your-godaddy-api-secret>"
# GODADDY_DOMAIN="pqcrypta.com"
# GODADDY_RECORD="tcp2"
# GODADDY_TTL="1800"
# NOTIFY_URL="https://pqcrypta.com/speedtest/locations.php"
# NOTIFY_TOKEN="<shared-token-from-pqcrypta.com-config>"
# LOCATION_ID="us-midwest"
# IP_FILE="/etc/pqcrypta/current-ip"
# LOG_FILE="/var/log/pqcrypta/ip-update.log"

set -euo pipefail

CONF="/etc/pqcrypta/ip-update.conf"

if [[ ! -f "$CONF" ]]; then
    echo "ERROR: $CONF not found. See script header for setup instructions." >&2
    exit 1
fi

# shellcheck source=/dev/null
source "$CONF"

: "${GODADDY_KEY:?GODADDY_KEY not set in $CONF}"
: "${GODADDY_SECRET:?GODADDY_SECRET not set in $CONF}"
: "${GODADDY_DOMAIN:=pqcrypta.com}"
: "${GODADDY_RECORD:=tcp2}"
: "${GODADDY_TTL:=1800}"
: "${NOTIFY_URL:?NOTIFY_URL not set in $CONF}"
: "${NOTIFY_TOKEN:?NOTIFY_TOKEN not set in $CONF}"
: "${LOCATION_ID:=us-midwest}"
: "${IP_FILE:=/etc/pqcrypta/current-ip}"
: "${LOG_FILE:=/var/log/pqcrypta/ip-update.log}"

log() { echo "$(date -u '+%Y-%m-%dT%H:%M:%SZ') $*" >> "$LOG_FILE"; }

mkdir -p "$(dirname "$IP_FILE")" "$(dirname "$LOG_FILE")"

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

if [[ "$CURRENT_IP" == "$STORED_IP" ]]; then
    exit 0  # No change — nothing to do
fi

log "IP changed: $STORED_IP -> $CURRENT_IP"

# ── Update GoDaddy DNS ────────────────────────────────────────────────────
GODADDY_URL="https://api.godaddy.com/v1/domains/${GODADDY_DOMAIN}/records/A/${GODADDY_RECORD}"

HTTP_STATUS=$(curl -sf -o /dev/null -w "%{http_code}" \
    -X PUT "$GODADDY_URL" \
    -H "Authorization: sso-key ${GODADDY_KEY}:${GODADDY_SECRET}" \
    -H "Content-Type: application/json" \
    -d "[{\"data\": \"${CURRENT_IP}\", \"ttl\": ${GODADDY_TTL}}]" || echo "000")

if [[ "$HTTP_STATUS" == "200" ]]; then
    log "GoDaddy DNS updated: ${GODADDY_RECORD}.${GODADDY_DOMAIN} -> $CURRENT_IP"
else
    log "ERROR: GoDaddy update failed (HTTP $HTTP_STATUS)"
    exit 1
fi

# ── Notify pqcrypta.com ───────────────────────────────────────────────────
NOTIFY_STATUS=$(curl -sf -o /dev/null -w "%{http_code}" \
    -X POST "$NOTIFY_URL" \
    -H "Content-Type: application/json" \
    -d "{\"action\":\"update_ip\",\"location_id\":\"${LOCATION_ID}\",\"ip\":\"${CURRENT_IP}\",\"token\":\"${NOTIFY_TOKEN}\"}" || echo "000")

if [[ "$NOTIFY_STATUS" == "200" ]]; then
    log "pqcrypta.com notified of new IP"
else
    log "WARNING: pqcrypta.com notification failed (HTTP $NOTIFY_STATUS) — DNS was updated"
fi

# ── Save current IP ───────────────────────────────────────────────────────
echo "$CURRENT_IP" > "$IP_FILE"
log "Done. Stored IP: $CURRENT_IP"

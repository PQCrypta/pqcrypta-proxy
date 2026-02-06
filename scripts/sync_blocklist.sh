#!/bin/bash
# Blocklist Sync Script for pqcrypta-proxy
# Syncs blocklists from PostgreSQL database to JSON files for proxy hot-reload
# Run via cron: */1 * * * * /var/www/html/pqcrypta-proxy/scripts/sync_blocklist.sh

set -e

# Configuration
PROXY_DIR="/var/www/html/pqcrypta-proxy"
BLOCKLIST_DIR="${PROXY_DIR}/data/blocklists"
DB_NAME="pqcrypta"
DB_USER="pqcrypta_user"
LOG_FILE="/var/log/pqcrypta-proxy/blocklist_sync.log"

# Ensure directories exist
mkdir -p "${BLOCKLIST_DIR}"
mkdir -p "$(dirname "${LOG_FILE}")"

# Timestamp
TS=$(date '+%Y-%m-%d %H:%M:%S')

log() {
    echo "[${TS}] $1" >> "${LOG_FILE}"
}

log "Starting blocklist sync..."

# Sync blocked IPs
IP_QUERY="SELECT json_agg(json_build_object(
    'ip', ip_address::text,
    'reason', reason,
    'threat_level', threat_level,
    'expires_at', expires_at
)) FROM bot_blocklist WHERE is_active = true AND (expires_at IS NULL OR expires_at > NOW())"

sudo -u postgres psql -d "${DB_NAME}" -t -A -c "${IP_QUERY}" | \
    jq -r '.' > "${BLOCKLIST_DIR}/blocked_ips.json.tmp" 2>/dev/null || echo "[]" > "${BLOCKLIST_DIR}/blocked_ips.json.tmp"

# Handle null result
if [ "$(cat ${BLOCKLIST_DIR}/blocked_ips.json.tmp)" == "null" ] || [ -z "$(cat ${BLOCKLIST_DIR}/blocked_ips.json.tmp)" ]; then
    echo "[]" > "${BLOCKLIST_DIR}/blocked_ips.json.tmp"
fi

mv "${BLOCKLIST_DIR}/blocked_ips.json.tmp" "${BLOCKLIST_DIR}/blocked_ips.json"
IP_COUNT=$(jq 'length' "${BLOCKLIST_DIR}/blocked_ips.json" 2>/dev/null || echo "0")
log "Synced ${IP_COUNT} blocked IPs"

# Sync blocked fingerprints
FP_QUERY="SELECT json_agg(json_build_object(
    'fingerprint', fingerprint,
    'type', fingerprint_type,
    'reason', reason,
    'known_tool', known_tool
)) FROM fingerprint_blocklist WHERE is_active = true AND (expires_at IS NULL OR expires_at > NOW())"

sudo -u postgres psql -d "${DB_NAME}" -t -A -c "${FP_QUERY}" | \
    jq -r '.' > "${BLOCKLIST_DIR}/blocked_fingerprints.json.tmp" 2>/dev/null || echo "[]" > "${BLOCKLIST_DIR}/blocked_fingerprints.json.tmp"

if [ "$(cat ${BLOCKLIST_DIR}/blocked_fingerprints.json.tmp)" == "null" ] || [ -z "$(cat ${BLOCKLIST_DIR}/blocked_fingerprints.json.tmp)" ]; then
    echo "[]" > "${BLOCKLIST_DIR}/blocked_fingerprints.json.tmp"
fi

mv "${BLOCKLIST_DIR}/blocked_fingerprints.json.tmp" "${BLOCKLIST_DIR}/blocked_fingerprints.json"
FP_COUNT=$(jq 'length' "${BLOCKLIST_DIR}/blocked_fingerprints.json" 2>/dev/null || echo "0")
log "Synced ${FP_COUNT} blocked fingerprints"

# Sync blocked countries
COUNTRY_QUERY="SELECT json_agg(json_build_object(
    'code', country_code,
    'name', country_name,
    'reason', reason
)) FROM country_blocklist WHERE is_active = true"

sudo -u postgres psql -d "${DB_NAME}" -t -A -c "${COUNTRY_QUERY}" | \
    jq -r '.' > "${BLOCKLIST_DIR}/blocked_countries.json.tmp" 2>/dev/null || echo "[]" > "${BLOCKLIST_DIR}/blocked_countries.json.tmp"

if [ "$(cat ${BLOCKLIST_DIR}/blocked_countries.json.tmp)" == "null" ] || [ -z "$(cat ${BLOCKLIST_DIR}/blocked_countries.json.tmp)" ]; then
    echo "[]" > "${BLOCKLIST_DIR}/blocked_countries.json.tmp"
fi

mv "${BLOCKLIST_DIR}/blocked_countries.json.tmp" "${BLOCKLIST_DIR}/blocked_countries.json"
COUNTRY_COUNT=$(jq 'length' "${BLOCKLIST_DIR}/blocked_countries.json" 2>/dev/null || echo "0")
log "Synced ${COUNTRY_COUNT} blocked countries"

# Create combined blocklist status
cat > "${BLOCKLIST_DIR}/sync_status.json" << EOF
{
    "last_sync": "${TS}",
    "blocked_ips": ${IP_COUNT},
    "blocked_fingerprints": ${FP_COUNT},
    "blocked_countries": ${COUNTRY_COUNT},
    "total_blocked": $((IP_COUNT + FP_COUNT + COUNTRY_COUNT))
}
EOF

log "Sync complete: ${IP_COUNT} IPs, ${FP_COUNT} fingerprints, ${COUNTRY_COUNT} countries"

# Cleanup expired entries (run every hour)
MINUTE=$(date '+%M')
if [ "$MINUTE" == "00" ]; then
    log "Running hourly cleanup..."
    sudo -u postgres psql -d "${DB_NAME}" -c "SELECT cleanup_expired_blocklist_entries()" >> "${LOG_FILE}" 2>&1
fi

exit 0

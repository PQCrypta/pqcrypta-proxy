#!/bin/bash
# Blocklist Sync Script for pqcrypta-proxy
# Syncs blocklists from PostgreSQL database to JSON files for proxy hot-reload.
# Blocklist files are stored OUTSIDE the web root to prevent direct HTTP access.
#
# Run via cron: */1 * * * * /var/www/html/pqcrypta-proxy/scripts/sync_blocklist.sh

set -euo pipefail

# Configuration
BLOCKLIST_DIR="/var/lib/pqcrypta-proxy/blocklists"
PROXY_USER="pqcrypta"
DB_NAME="pqcrypta"
DB_USER="pqcrypta_user"
LOG_FILE="/var/log/pqcrypta-proxy/blocklist_sync.log"

# Ensure log directory exists
mkdir -p "$(dirname "${LOG_FILE}")"

# Timestamp
TS=$(date '+%Y-%m-%d %H:%M:%S')

log() {
    echo "[${TS}] $1" >> "${LOG_FILE}"
}

log "Starting blocklist sync..."

# Ensure blocklist directory exists with strict permissions (outside web root).
# Owner = pqcrypta service user, mode = 0700 (no world/group access).
if [ ! -d "${BLOCKLIST_DIR}" ]; then
    mkdir -p "${BLOCKLIST_DIR}"
    log "Created blocklist directory: ${BLOCKLIST_DIR}"
fi
chown "${PROXY_USER}:${PROXY_USER}" "${BLOCKLIST_DIR}" 2>/dev/null || true
chmod 0700 "${BLOCKLIST_DIR}"

# ---------------------------------------------------------------------------
# Helper: run a DB query and write the result to a JSON file ONLY if the
# query succeeds and returns non-empty / non-null output.
# Usage: sync_table QUERY DEST_FILE LABEL
# ---------------------------------------------------------------------------
sync_table() {
    local QUERY="$1"
    local DEST_FILE="$2"
    local LABEL="$3"
    local TMP_FILE="${DEST_FILE}.tmp"

    # Run query; capture output and exit code separately so set -e does not
    # fire before we can inspect the result.
    local DB_OUTPUT
    if ! DB_OUTPUT=$(sudo -u postgres psql -d "${DB_NAME}" -t -A -c "${QUERY}" 2>&1); then
        log "WARNING: DB query failed for ${LABEL} (psql exited non-zero) - preserving existing blocklist"
        return 0
    fi

    # Process through jq to validate JSON
    local JSON_OUTPUT
    if ! JSON_OUTPUT=$(echo "${DB_OUTPUT}" | jq -r '.' 2>&1); then
        log "WARNING: jq processing failed for ${LABEL} - preserving existing blocklist"
        return 0
    fi

    # Treat SQL NULL (empty table) as an empty array, not as a deletion signal
    if [ "${JSON_OUTPUT}" = "null" ] || [ -z "${JSON_OUTPUT}" ]; then
        JSON_OUTPUT="[]"
    fi

    # Atomic write: write to tmp then rename
    printf '%s\n' "${JSON_OUTPUT}" > "${TMP_FILE}"
    mv "${TMP_FILE}" "${DEST_FILE}"
    chmod 0600 "${DEST_FILE}"

    local COUNT
    COUNT=$(jq 'length' "${DEST_FILE}" 2>/dev/null || echo "0")
    log "Synced ${COUNT} ${LABEL}"
    echo "${COUNT}"
}

# ---------------------------------------------------------------------------
# Sync blocked IPs
# ---------------------------------------------------------------------------
IP_QUERY="SELECT json_agg(json_build_object(
    'ip', ip_address::text,
    'reason', reason,
    'threat_level', threat_level,
    'expires_at', expires_at
)) FROM bot_blocklist WHERE is_active = true AND (expires_at IS NULL OR expires_at > NOW())"

IP_COUNT=$(sync_table "${IP_QUERY}" "${BLOCKLIST_DIR}/blocked_ips.json" "blocked IPs")
IP_COUNT="${IP_COUNT:-0}"

# ---------------------------------------------------------------------------
# Sync blocked fingerprints
# ---------------------------------------------------------------------------
FP_QUERY="SELECT json_agg(json_build_object(
    'fingerprint', fingerprint,
    'type', fingerprint_type,
    'reason', reason,
    'known_tool', known_tool
)) FROM fingerprint_blocklist WHERE is_active = true AND (expires_at IS NULL OR expires_at > NOW())"

FP_COUNT=$(sync_table "${FP_QUERY}" "${BLOCKLIST_DIR}/blocked_fingerprints.json" "blocked fingerprints")
FP_COUNT="${FP_COUNT:-0}"

# ---------------------------------------------------------------------------
# Sync blocked countries
# ---------------------------------------------------------------------------
COUNTRY_QUERY="SELECT json_agg(json_build_object(
    'code', country_code,
    'name', country_name,
    'reason', reason
)) FROM country_blocklist WHERE is_active = true"

COUNTRY_COUNT=$(sync_table "${COUNTRY_QUERY}" "${BLOCKLIST_DIR}/blocked_countries.json" "blocked countries")
COUNTRY_COUNT="${COUNTRY_COUNT:-0}"

# ---------------------------------------------------------------------------
# Write sync status (informational, not used for blocking decisions)
# ---------------------------------------------------------------------------
STATUS_TMP="${BLOCKLIST_DIR}/sync_status.json.tmp"
cat > "${STATUS_TMP}" << EOF
{
    "last_sync": "${TS}",
    "blocked_ips": ${IP_COUNT},
    "blocked_fingerprints": ${FP_COUNT},
    "blocked_countries": ${COUNTRY_COUNT},
    "total_blocked": $((IP_COUNT + FP_COUNT + COUNTRY_COUNT))
}
EOF
mv "${STATUS_TMP}" "${BLOCKLIST_DIR}/sync_status.json"
chmod 0600 "${BLOCKLIST_DIR}/sync_status.json"

log "Sync complete: ${IP_COUNT} IPs, ${FP_COUNT} fingerprints, ${COUNTRY_COUNT} countries"

# ---------------------------------------------------------------------------
# Hourly cleanup of expired entries in the database
# ---------------------------------------------------------------------------
MINUTE=$(date '+%M')
if [ "${MINUTE}" = "00" ]; then
    log "Running hourly cleanup..."
    sudo -u postgres psql -d "${DB_NAME}" -c "SELECT cleanup_expired_blocklist_entries()" >> "${LOG_FILE}" 2>&1 || \
        log "WARNING: hourly cleanup query failed"
fi

exit 0

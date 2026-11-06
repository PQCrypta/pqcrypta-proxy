#!/bin/bash
# Blocklist Sync Script for pqcrypta-proxy
# Syncs blocklists from PostgreSQL database to JSON files for proxy hot-reload.
# Blocklist files are stored OUTSIDE the web root to prevent direct HTTP access.
#
# Run every minute by pqcrypta-blocklist-sync.timer (pqcrypta-configs) as the
# account pqcrypta-proxydata, which owns the blocklist directory (the proxy
# reads it through its group) and signs in to the database as the role of its
# name by peer authentication, with SELECT on the four lists and nothing else.
# What it says goes to stdout (the unit appends it to
# /var/log/pqcrypta/blocklist_sync.log).

set -euo pipefail

# Configuration
# The blocklist directory (outside the web root): this account's, set-group-ID
# to the proxy's group, which reads it (tmpfiles.d/pqcrypta-proxy.conf)
BLOCKLIST_DIR="/var/lib/pqcrypta-proxy/blocklists"
DB_NAME="pqcrypta"
DB_USER="pqcrypta-proxydata"

# Timestamp
TS=$(date '+%Y-%m-%d %H:%M:%S')

# To stderr: sync_table answers its count on stdout (the unit sends both to
# the log)
log() {
    echo "[${TS}] $1" >&2
}

log "Starting blocklist sync..."
[ -d "${BLOCKLIST_DIR}" ] || { log "ERROR: no ${BLOCKLIST_DIR}"; exit 1; }

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
    # AUD-05: a role with SELECT on the lists alone, by peer authentication
    # over the local socket (no password), never the superuser.
    local DB_OUTPUT
    if ! DB_OUTPUT=$(psql -U "${DB_USER}" -d "${DB_NAME}" -v ON_ERROR_STOP=1 -t -A -c "${QUERY}" 2>&1); then
        log "WARNING: DB query failed for ${LABEL} - preserving existing blocklist: $(printf '%s' "${DB_OUTPUT}" | head -1)"
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

    # Atomic write: write to tmp then rename, the mode set before the rename
    # (the directory's set-group-ID gives the file the proxy's group)
    (umask 0027 && printf '%s\n' "${JSON_OUTPUT}" > "${TMP_FILE}")
    chmod 0640 "${TMP_FILE}"
    mv "${TMP_FILE}" "${DEST_FILE}"

    local COUNT
    COUNT=$(jq 'length' "${DEST_FILE}" 2>/dev/null || echo "0")
    log "Synced ${COUNT} ${LABEL}"
    echo "${COUNT}"
}

# ---------------------------------------------------------------------------
# Sync blocked IPs
# Merges security_blocklist (API-detected threats) and waf_blocked_ips (WAF blocks).
# bot_blocklist is legacy — the active detection systems write to these two tables.
# ---------------------------------------------------------------------------
IP_QUERY="SELECT json_agg(sub.*) FROM (
    SELECT DISTINCT ON (ip) ip, reason, threat_level, expires_at FROM (
        SELECT
            CASE WHEN masklen(ip_address) = 32 OR family(ip_address) = 6 AND masklen(ip_address) = 128
                THEN host(ip_address)
                ELSE ip_address::text
            END AS ip,
            reason,
            risk_level AS threat_level,
            expires_at,
            1 AS priority
        FROM security_blocklist
        WHERE is_active = true
          AND ip_address IS NOT NULL
          AND whitelist_override IS NOT TRUE
          AND (expires_at IS NULL OR expires_at > NOW())
        UNION ALL
        SELECT
            ip_address AS ip,
            block_reason AS reason,
            highest_severity AS threat_level,
            expires_at,
            2 AS priority
        FROM waf_blocked_ips
        WHERE is_active = true
          AND (expires_at IS NULL OR expires_at > NOW())
    ) combined
    ORDER BY ip, priority
) sub"

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
# Write sync status (informational, not used for blocking decisions), with the
# lists' mode: a deployment may give readers of the lists a POSIX ACL on the
# directory, which a mode without group bits would mask
# ---------------------------------------------------------------------------
STATUS_TMP="${BLOCKLIST_DIR}/sync_status.json.tmp"
(umask 0027 && cat > "${STATUS_TMP}") << EOF
{
    "last_sync": "${TS}",
    "blocked_ips": ${IP_COUNT},
    "blocked_fingerprints": ${FP_COUNT},
    "blocked_countries": ${COUNTRY_COUNT},
    "total_blocked": $((IP_COUNT + FP_COUNT + COUNTRY_COUNT))
}
EOF
chmod 0640 "${STATUS_TMP}"
mv "${STATUS_TMP}" "${BLOCKLIST_DIR}/sync_status.json"

log "Sync complete: ${IP_COUNT} IPs, ${FP_COUNT} fingerprints, ${COUNTRY_COUNT} countries"

# Expired entries leave the database hourly by a job of their own
# (pqcrypta-pg-blocklist-expiry.timer): this account only reads the lists.
exit 0

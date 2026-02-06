#!/bin/bash
# Bot Detection from Proxy Access Logs
# Processes ALL unprocessed log entries and adds detected bots to database
# Tracks position with state file to avoid reprocessing
# Run via cron: */5 * * * * /var/www/html/pqcrypta-proxy/scripts/detect_bots_from_logs.sh

ACCESS_LOG="/var/log/pqcrypta-proxy/access.log"
DB_NAME="pqcrypta"
LOG_FILE="/var/log/pqcrypta-proxy/bot_detection.log"
STATE_FILE="/var/www/html/pqcrypta-proxy/data/.last_processed_byte"
TEMP_DIR="/tmp/pqcrypta-bot-detect"

mkdir -p "$(dirname "${STATE_FILE}")" "${TEMP_DIR}"

TS=$(date '+%Y-%m-%d %H:%M:%S')
log() { echo "[${TS}] $1" >> "${LOG_FILE}"; }

# Suspicious path patterns
PATTERNS='wp-admin|wp-login|wp-content|wp-includes|\.git|\.env|\.sql|\.bak|\.old|backup|admin\.php|phpmyadmin|xmlrpc\.php|eval-stdin|shell|config\.php|\.zip|\.tar|\.gz|setup\.php|install\.php|filemanager|wp_filemanager|rip\.php|c99|r57|wso|alfa|filesman|webshell|\.htaccess|\.htpasswd|passwd|shadow|boot\.ini|win\.ini|phpinfo|adminer|\.svn|\.hg|\.DS_Store|Thumbs\.db|\.idea|\.vscode|node_modules|vendor/|composer\.(json|lock)|package\.json|\.npmrc|id_rsa|id_dsa|\.pem|\.key|credentials|secrets|token'

[ ! -f "${ACCESS_LOG}" ] && { log "Access log not found"; exit 0; }

# Get last processed byte position
LAST_BYTE=0
[ -f "${STATE_FILE}" ] && LAST_BYTE=$(cat "${STATE_FILE}" 2>/dev/null || echo "0")

# Current file size
CURRENT_SIZE=$(stat -c%s "${ACCESS_LOG}" 2>/dev/null || echo "0")

# Handle log rotation
[ "${CURRENT_SIZE}" -lt "${LAST_BYTE}" ] && LAST_BYTE=0

BYTES_TO_PROCESS=$((CURRENT_SIZE - LAST_BYTE))
[ "${BYTES_TO_PROCESS}" -le 0 ] && { log "No new data to process"; exit 0; }

log "Processing ${BYTES_TO_PROCESS} bytes (from byte ${LAST_BYTE} to ${CURRENT_SIZE})"

# Extract new data and find suspicious entries
tail -c "+$((LAST_BYTE + 1))" "${ACCESS_LOG}" | grep -iE "${PATTERNS}" > "${TEMP_DIR}/suspicious.txt" 2>/dev/null || true

SUSPICIOUS_COUNT=$(wc -l < "${TEMP_DIR}/suspicious.txt" 2>/dev/null || echo "0")
log "Found ${SUSPICIOUS_COUNT} suspicious entries"

if [ "${SUSPICIOUS_COUNT}" -gt 0 ]; then
    # Extract unique IPs with counts
    awk '{print $1}' "${TEMP_DIR}/suspicious.txt" | \
        grep -E '^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$' | \
        sort | uniq -c | sort -rn > "${TEMP_DIR}/ip_counts.txt"

    # Process each IP
    while read -r count ip; do
        [ -z "$ip" ] && continue

        # Get sample path for this IP
        SAMPLE_PATH=$(grep "^${ip} " "${TEMP_DIR}/suspicious.txt" | head -1 | grep -oE '"(GET|POST|HEAD|PUT|DELETE) [^"]+' | awk '{print $2}' | head -1 | cut -c1-200 | sed "s/'/''/g")

        # Insert detection record
        sudo -u postgres psql -d "${DB_NAME}" -q -c "
            INSERT INTO proxy_detections (ip_address, path, method, detection_type, blocked, request_count, timestamp)
            VALUES ('${ip}', '${SAMPLE_PATH:-/unknown}', 'GET', 'suspicious_path', true, ${count}, NOW())
        " 2>/dev/null || true

        # If 5+ suspicious requests, add to blocklist
        if [ "${count}" -ge 5 ]; then
            THREAT_LEVEL="medium"
            [ "${count}" -ge 20 ] && THREAT_LEVEL="high"
            [ "${count}" -ge 50 ] && THREAT_LEVEL="critical"

            sudo -u postgres psql -d "${DB_NAME}" -q -c "
                INSERT INTO bot_blocklist (ip_address, reason, detection_source, threat_level, request_count, expires_at)
                VALUES ('${ip}', 'Proxy: ${count} suspicious requests', 'proxy', '${THREAT_LEVEL}', ${count}, NOW() + INTERVAL '24 hours')
                ON CONFLICT (ip_address) DO UPDATE
                SET request_count = bot_blocklist.request_count + ${count},
                    last_seen_at = NOW(),
                    threat_level = CASE
                        WHEN bot_blocklist.request_count + ${count} >= 50 THEN 'critical'
                        WHEN bot_blocklist.request_count + ${count} >= 20 THEN 'high'
                        ELSE bot_blocklist.threat_level
                    END,
                    expires_at = NOW() + INTERVAL '24 hours',
                    updated_at = NOW()
            " 2>/dev/null || true
            log "Blocked ${ip} (${count} suspicious requests, threat: ${THREAT_LEVEL})"
        fi
    done < "${TEMP_DIR}/ip_counts.txt"

    UNIQUE_IPS=$(wc -l < "${TEMP_DIR}/ip_counts.txt")
    BLOCKED_IPS=$(awk '$1 >= 5 {count++} END {print count+0}' "${TEMP_DIR}/ip_counts.txt")
    log "Processed ${UNIQUE_IPS} unique IPs, blocked ${BLOCKED_IPS}"
fi

# Update state file
echo "${CURRENT_SIZE}" > "${STATE_FILE}"

# Cleanup
rm -f "${TEMP_DIR}/suspicious.txt" "${TEMP_DIR}/ip_counts.txt"

log "Bot detection complete"

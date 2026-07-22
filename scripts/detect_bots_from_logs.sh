#!/bin/bash
# Bot Detection from Proxy Access Logs
# Processes ALL unprocessed log entries and adds detected bots to database
# Tracks position with state file to avoid reprocessing
# Run via cron: */5 * * * * /var/www/html/pqcrypta-proxy/scripts/detect_bots_from_logs.sh
#
# SEC-A01: All SQL executed via parameterised psql -v variables (:'name' quoted literals)
#          rather than string interpolation, preventing SQL injection through attacker-
#          controlled request paths in the access log.
# SEC-A09: Runs as pqcrypta_user (least-privilege) instead of the postgres superuser.

ACCESS_LOG="/var/log/pqcrypta-proxy/access.log"
DB_NAME="pqcrypta"
DB_USER="pqcrypta_user"
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

# Extract new data once; both the suspicious-pattern pass and the honeypot
# feed below consume the same slice
tail -c "+$((LAST_BYTE + 1))" "${ACCESS_LOG}" > "${TEMP_DIR}/new_lines.txt" 2>/dev/null || true
grep -iE "${PATTERNS}" "${TEMP_DIR}/new_lines.txt" > "${TEMP_DIR}/suspicious.txt" 2>/dev/null || true

SUSPICIOUS_COUNT=$(wc -l < "${TEMP_DIR}/suspicious.txt" 2>/dev/null || echo "0")
log "Found ${SUSPICIOUS_COUNT} suspicious entries"

# ---------------------------------------------------------------------------
# Honeypot feed: the proxy WAF blocks scanner probes at the edge, so they never
# reach the API's honeypot middleware anymore. Match every new request against
# the honeypot_endpoints catalog and record hits in honeypot_interactions
# (dashboard intelligence) + security_blocklist (persistent enforcement),
# skipping whitelisted IPs.
# ---------------------------------------------------------------------------
# Parse combined log format into TAB-separated: ip method path query ua host
awk '
BEGIN { FS = "\"" }
{
    n = split($1, pre, " ");
    ip = pre[1];
    if (ip !~ /^([0-9]{1,3}\.){3}[0-9]{1,3}$/ && ip !~ /^[0-9a-fA-F:]+$/) next;
    if (ip == "127.0.0.1" || ip == "::1") next;

    split($2, req, " ");
    method = req[1]; path = req[2];
    if (method !~ /^[A-Z]+$/ || path !~ /^\//) next;

    qs = "";
    qpos = index(path, "?");
    if (qpos > 0) { qs = substr(path, qpos + 1); path = substr(path, 1, qpos - 1); }

    # Paths every legitimate crawler/browser requests blindly — a 404 on these
    # is normal traffic, not a probe, even though they sit in the honeypot catalog
    if (path == "/robots.txt" || path == "/favicon.ico" || path == "/sitemap.xml") next;

    # Only failed requests are probe candidates — a 2xx/3xx means the path
    # legitimately exists on that host (e.g. /images/... on the main site)
    split($3, st, " ");
    status = st[1] + 0;
    if (status < 400) next;

    ua = (NF >= 6) ? $6 : "";
    host = "";
    if (match($0, /host="[^"]*"/)) host = substr($0, RSTART + 6, RLENGTH - 7);

    # Escape for COPY text format
    gsub(/\\/, "\\\\", path); gsub(/\\/, "\\\\", qs); gsub(/\\/, "\\\\", ua);
    gsub(/\t/, " ", path); gsub(/\t/, " ", qs); gsub(/\t/, " ", ua); gsub(/\t/, " ", host);

    print ip "\t" method "\t" substr(path, 1, 500) "\t" substr(qs, 1, 500) "\t" substr(ua, 1, 500) "\t" host;
}' "${TEMP_DIR}/new_lines.txt" > "${TEMP_DIR}/probes.tsv" 2>/dev/null || true

PROBE_LINES=$(wc -l < "${TEMP_DIR}/probes.tsv" 2>/dev/null || echo "0")
if [ "${PROBE_LINES}" -gt 0 ]; then
    # NOTE: \copy performs no psql variable interpolation, so the TSV path is
    # the literal TEMP_DIR value (constant defined at the top of this script)
    HONEYPOT_HITS=$(psql -U "${DB_USER}" -d "${DB_NAME}" -q -t -A << 'ENDSQL' 2>>"${LOG_FILE}" || echo "0"
CREATE TEMP TABLE edge_probes (ip text, method text, path text, qs text, ua text, host text);
\copy edge_probes FROM '/tmp/pqcrypta-bot-detect/probes.tsv' WITH (FORMAT text)

WITH matched AS (
    -- Exact-path matches count on every host (/.env, /wp-config.php are never
    -- legitimate anywhere). Trailing-slash PREFIX entries (/images/, /css/,
    -- /api/v1/, ...) describe directories that exist for real on the web
    -- hosts, so those only count against the API hosts where any such
    -- request is a probe by definition.
    SELECT p.ip, p.method, p.path, p.qs, p.ua, p.host,
           h.endpoint_path, h.threat_level, h.category, h.attack_vector
    FROM edge_probes p
    CROSS JOIN LATERAL (
        SELECT endpoint_path, threat_level, category, attack_vector
        FROM honeypot_endpoints
        WHERE is_active = true
          AND (p.path = endpoint_path
               OR (p.host ~ '^api[0-9]*\.pqcrypta\.com$'
                   AND p.path LIKE endpoint_path || '%'
                   AND endpoint_path LIKE '%/'))
        LIMIT 1
    ) h
    WHERE NOT EXISTS (
        SELECT 1 FROM security_whitelist w
        WHERE w.is_active = true
          AND (w.ip_address = p.ip::inet
               OR (w.ip_range IS NOT NULL AND w.ip_range >>= p.ip::inet))
    )
),
logged AS (
    INSERT INTO honeypot_interactions
        (ip_address, endpoint, threat_level, category, attack_vector, user_agent,
         request_method, query_params, target_domain, detection_confidence,
         honeypot_type, created_at)
    SELECT ip::inet, endpoint_path, threat_level, category, attack_vector,
           NULLIF(ua, '-'), method, NULLIF(qs, ''), NULLIF(host, ''),
           CASE threat_level WHEN 'critical' THEN 0.95 WHEN 'high' THEN 0.85
                             WHEN 'medium' THEN 0.70 ELSE 0.50 END,
           'edge_waf', NOW()
    FROM matched
    RETURNING 1
),
blocked AS (
    -- Only critical/high probes escalate to a persistent block; medium/low
    -- hits are logged for intelligence but a stray 404 must never block a
    -- real user
    INSERT INTO security_blocklist
        (ip_address, risk_level, block_type, reason, confidence_score,
         expires_at, created_at, evidence, is_active)
    SELECT DISTINCT ON (ip) ip::inet, threat_level, 'honeypot_trigger',
           'Honeypot triggered (edge): ' || endpoint_path || ' (' || attack_vector || ')',
           1.0,
           NOW() + (CASE threat_level WHEN 'critical' THEN 168
                                      ELSE 72 END || ' hours')::interval,
           NOW(), '{}'::jsonb, true
    FROM matched
    WHERE threat_level IN ('critical', 'high')
    ORDER BY ip, CASE threat_level WHEN 'critical' THEN 0 WHEN 'high' THEN 1
                                   WHEN 'medium' THEN 2 ELSE 3 END
    ON CONFLICT (ip_address) DO UPDATE
    SET blocked_requests = COALESCE(security_blocklist.blocked_requests, 0) + 1,
        last_seen = NOW(),
        is_active = (security_blocklist.whitelist_override IS NOT TRUE),
        expires_at = CASE
            WHEN security_blocklist.expires_at IS NULL THEN NULL
            ELSE GREATEST(security_blocklist.expires_at, EXCLUDED.expires_at)
        END
    RETURNING 1
)
SELECT COUNT(*) FROM logged;
ENDSQL
)
    HONEYPOT_HITS=$(printf '%s' "${HONEYPOT_HITS}" | tr -dc '0-9')
    [ -n "${HONEYPOT_HITS}" ] && [ "${HONEYPOT_HITS}" -gt 0 ] && \
        log "Honeypot feed: recorded ${HONEYPOT_HITS} edge-blocked probe(s)"

    # -----------------------------------------------------------------------
    # bot_ip_tracking feed: the threat dashboard's stats / top-threats /
    # patterns / clients / threat-actors / countries panels all read
    # bot_ip_tracking, which was historically fed by parse_nginx_logs.php from
    # the (now dead) nginx access log. Live traffic is on the proxy, so those
    # panels went stale. Replay the malicious subset of proxy probes through
    # /bot-threat/log-request, which does GeoIP+ASN enrichment and threat
    # scoring server-side (crawler-safe: it only scores real attack patterns
    # and never auto-blocks). Capped per run so the cron stays quick.
    # -----------------------------------------------------------------------
    INGEST_KEY=$(grep -E '^BOT_THREAT_INGEST_KEY=' /var/www/html/.env 2>/dev/null | head -1 | cut -d= -f2- | tr -d '"'"'"' ')
    if [ -n "${INGEST_KEY}" ]; then
        INGEST_COUNT=$(BOT_INGEST_KEY="${INGEST_KEY}" python3 - <<'PYEOF' 2>>"${LOG_FILE}" || echo 0
import os, re, json, urllib.request

TSV = "/tmp/pqcrypta-bot-detect/probes.tsv"
KEY = os.environ["BOT_INGEST_KEY"]
URL = "http://127.0.0.1:3003/bot-threat/log-request"
# Only replay requests that look like probing/attacks — keeps bot_ip_tracking
# threat-focused instead of logging every benign 404.
PAT = re.compile(r"wp-admin|wp-login|wp-content|wp-includes|xmlrpc|\.env|\.git|\.sql|\.bak|"
                 r"config\.php|phpmyadmin|adminer|shell|backup|\.aws|\.ssh|setup\.php|"
                 r"install\.php|/admin|/manager|actuator|jolokia|eval-stdin|/\.\.|passwd|"
                 r"union.*select|/vendor/|composer\.|\.htaccess|id_rsa|/cgi-bin|/boaform", re.I)

sent = 0
cap = 300
try:
    with open(TSV, encoding="utf-8", errors="replace") as fh:
        for line in fh:
            if sent >= cap:
                break
            parts = line.rstrip("\n").split("\t")
            if len(parts) < 6:
                continue
            ip, method, path, qs, ua, host = parts[:6]
            if not PAT.search(path):
                continue
            payload = json.dumps({
                "ip_address": ip,
                "user_agent": ua or "-",
                "request_path": path[:500],
                "request_method": (method or "GET")[:10],
                "query_string": (qs or None),
                "referer": None,
                "target_domain": host or "",
            }).encode()
            req = urllib.request.Request(URL, data=payload, method="POST", headers={
                "Content-Type": "application/json",
                "X-API-Key": KEY,
                "Host": "api.pqcrypta.com",
            })
            try:
                urllib.request.urlopen(req, timeout=5).read()
                sent += 1
            except Exception:
                pass
except FileNotFoundError:
    pass
print(sent)
PYEOF
)
        INGEST_COUNT=$(printf '%s' "${INGEST_COUNT}" | tr -dc '0-9')
        [ -n "${INGEST_COUNT}" ] && [ "${INGEST_COUNT}" -gt 0 ] && \
            log "bot_ip_tracking feed: ingested ${INGEST_COUNT} probe(s) via log-request"
    fi
fi

# SEC-A01: Sanitize SAMPLE_PATH to a strict whitelist before using it as a
# psql variable.  Only printable ASCII characters that are safe in URL paths
# are kept; everything else is replaced with '_'.  This is a defence-in-depth
# layer on top of psql's :'var' quoted-literal parameterisation.
sanitize_path() {
    local raw="$1"
    # Keep only: alphanumeric, / . - _ ~ % + = & ? # @
    # Truncate to 200 chars, replace disallowed chars with _
    printf '%s' "${raw}" | tr -dc 'A-Za-z0-9/._~%+=&?#@:-' | cut -c1-200
}

if [ "${SUSPICIOUS_COUNT}" -gt 0 ]; then
    # Extract unique IPs with counts
    awk '{print $1}' "${TEMP_DIR}/suspicious.txt" | \
        grep -E '^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$' | \
        sort | uniq -c | sort -rn > "${TEMP_DIR}/ip_counts.txt"

    # Process each IP
    while read -r count ip; do
        [ -z "$ip" ] && continue

        # Get sample path for this IP — sanitized before any SQL context
        RAW_PATH=$(grep "^${ip} " "${TEMP_DIR}/suspicious.txt" | head -1 | grep -oE '"(GET|POST|HEAD|PUT|DELETE) [^"]+' | awk '{print $2}' | head -1)
        SAMPLE_PATH=$(sanitize_path "${RAW_PATH:-/unknown}")
        [ -z "${SAMPLE_PATH}" ] && SAMPLE_PATH="/unknown"

        # SEC-A01: Use psql :'variable' quoted literals for SAMPLE_PATH (string)
        # and :count::int cast for the integer — no raw shell expansion in SQL.
        # SEC-A09: Connect as pqcrypta_user, not the postgres superuser.
        psql -U "${DB_USER}" -d "${DB_NAME}" -q \
            -v "ip=${ip}" \
            -v "path=${SAMPLE_PATH}" \
            -v "count=${count}" \
            << 'ENDSQL' 2>/dev/null || true
INSERT INTO proxy_detections (ip_address, path, method, detection_type, blocked, request_count, timestamp)
VALUES (:'ip', :'path', 'GET', 'suspicious_path', true, :count::int, NOW());
ENDSQL

        # If 5+ suspicious requests, add to blocklist
        if [ "${count}" -ge 5 ]; then
            THREAT_LEVEL="medium"
            [ "${count}" -ge 20 ] && THREAT_LEVEL="high"
            [ "${count}" -ge 50 ] && THREAT_LEVEL="critical"

            REASON="Proxy: ${count} suspicious requests"

            psql -U "${DB_USER}" -d "${DB_NAME}" -q \
                -v "ip=${ip}" \
                -v "reason=${REASON}" \
                -v "threat=${THREAT_LEVEL}" \
                -v "count=${count}" \
                << 'ENDSQL' 2>/dev/null || true
INSERT INTO bot_blocklist (ip_address, reason, detection_source, threat_level, request_count, expires_at)
VALUES (:'ip', :'reason', 'proxy', :'threat', :count::int, NOW() + INTERVAL '24 hours')
ON CONFLICT (ip_address) DO UPDATE
SET request_count = bot_blocklist.request_count + :count::int,
    last_seen_at = NOW(),
    threat_level = CASE
        WHEN bot_blocklist.request_count + :count::int >= 50 THEN 'critical'
        WHEN bot_blocklist.request_count + :count::int >= 20 THEN 'high'
        ELSE bot_blocklist.threat_level
    END,
    expires_at = NOW() + INTERVAL '24 hours',
    updated_at = NOW();
ENDSQL
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

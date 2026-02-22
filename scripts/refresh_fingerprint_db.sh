#!/bin/bash
# Weekly cron refresh of the JA3/JA4 fingerprint database.
# Downloads the latest Salesforce JA3 list, converts it to JSON, and atomically
# replaces the existing database ONLY if the download and conversion succeed.
# Restarts pqcrypta-proxy only when the content actually changed.
#
# Cron (weekly, Sunday 03:15):
#   15 3 * * 0 root /var/www/html/pqcrypta-proxy/scripts/refresh_fingerprint_db.sh

DEST_DIR="/var/lib/pqcrypta-proxy/fingerprints"
DEST_FILE="${DEST_DIR}/ja3.json"
LOG_FILE="/var/log/pqcrypta-proxy/fingerprint_db_refresh.log"
SOURCE_URL="https://raw.githubusercontent.com/salesforce/ja3/master/lists/osx-nix-ja3.csv"

mkdir -p "$(dirname "${LOG_FILE}")"
TS=$(date '+%Y-%m-%d %H:%M:%S')

log() { echo "[${TS}] $1" >> "${LOG_FILE}"; }

log "Starting JA3 fingerprint database refresh..."

# Bail out cleanly on any unexpected error — never touch the live DB
set +e

TMP_CSV=$(mktemp /tmp/ja3_refresh_XXXXXX.csv)
TMP_JSON=$(mktemp /tmp/ja3_refresh_XXXXXX.json)

cleanup() {
    rm -f "${TMP_CSV}" "${TMP_JSON}"
}
trap cleanup EXIT

# Download
curl -fsSL --max-time 30 "${SOURCE_URL}" -o "${TMP_CSV}" 2>&1
CURL_EXIT=$?
if [ "${CURL_EXIT}" -ne 0 ]; then
    log "ERROR: curl failed (exit ${CURL_EXIT}) — existing database preserved"
    exit 0
fi

if [ ! -s "${TMP_CSV}" ]; then
    log "ERROR: downloaded file is empty — existing database preserved"
    exit 0
fi

# Convert CSV → JSON
python3 - "${TMP_CSV}" "${TMP_JSON}" << 'PYEOF'
import json, sys

src, dst = sys.argv[1], sys.argv[2]

with open(src) as f:
    content = f.read()

entries = []
for line in content.strip().split('\n'):
    line = line.strip()
    if not line:
        continue
    parts = line.split(',', 1)
    if len(parts) != 2:
        continue
    h = parts[0].strip().strip('"').lower()
    desc = parts[1].strip().strip('"')
    if len(h) != 32 or not all(c in '0123456789abcdef' for c in h):
        continue
    dl = desc.lower()
    cls = "api_client"
    if any(x in dl for x in ["chrome", "firefox", "safari", "edge", "webkit"]):
        cls = "browser"
    elif any(x in dl for x in ["bot", "crawler", "googlebot", "bingbot", "spider"]):
        cls = "bot"
    elif any(x in dl for x in ["scanner", "nikto", "nmap", "burp", "masscan", "zap", "shodan"]):
        cls = "scanner"
    elif any(x in dl for x in ["malware", "ransomware", "trojan", "mirai", "exploit", "metasploit"]):
        cls = "malicious"
    entries.append({"hash": h, "classification": cls, "description": desc})

with open(dst, "w") as f:
    json.dump(entries, f, indent=2)

print(len(entries))
PYEOF

PY_EXIT=$?
if [ "${PY_EXIT}" -ne 0 ]; then
    log "ERROR: JSON conversion failed (exit ${PY_EXIT}) — existing database preserved"
    exit 0
fi

if [ ! -s "${TMP_JSON}" ]; then
    log "ERROR: converted JSON is empty — existing database preserved"
    exit 0
fi

ENTRY_COUNT=$(python3 -c "import json; d=json.load(open('${TMP_JSON}')); print(len(d))" 2>/dev/null)
if [ -z "${ENTRY_COUNT}" ] || [ "${ENTRY_COUNT}" -lt 10 ]; then
    log "ERROR: converted DB has only ${ENTRY_COUNT} entries (minimum 10 required) — existing database preserved"
    exit 0
fi

# Compare checksums — skip restart if nothing changed
NEW_SUM=$(sha256sum "${TMP_JSON}" | awk '{print $1}')
OLD_SUM=""
if [ -f "${DEST_FILE}" ]; then
    OLD_SUM=$(sha256sum "${DEST_FILE}" | awk '{print $1}')
fi

if [ "${NEW_SUM}" = "${OLD_SUM}" ]; then
    log "Database unchanged (${ENTRY_COUNT} entries) — no restart needed"
    exit 0
fi

# Atomic replace
chmod 0600 "${TMP_JSON}"
mv "${TMP_JSON}" "${DEST_FILE}"
log "Updated JA3 database: ${ENTRY_COUNT} entries (was: $([ -n "${OLD_SUM}" ] && echo 'different' || echo 'new'))"

# Reload service to pick up new DB (fast: proxy starts in < 2s)
systemctl restart pqcrypta-proxy 2>&1
RESTART_EXIT=$?
if [ "${RESTART_EXIT}" -eq 0 ]; then
    log "pqcrypta-proxy restarted successfully"
else
    log "WARNING: restart failed (exit ${RESTART_EXIT}) — new DB will be loaded on next restart"
fi

log "Refresh complete"
exit 0

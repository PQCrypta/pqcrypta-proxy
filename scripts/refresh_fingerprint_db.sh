#!/bin/bash
# Weekly cron refresh of the JA3/JA4 fingerprint database.
# Downloads the latest Salesforce JA3 list, converts it to JSON, merges the
# locally curated overlay on top, and atomically replaces the existing database
# ONLY if the download and conversion succeed.
# Restarts pqcrypta-proxy only when the content actually changed, then pushes
# the merged database to the other proxy nodes.
#
# The overlay exists because the upstream list is the ONLY input: on 2026-08-02
# this refresh silently replaced a database that had 22 hand-added fingerprints
# (19 of them `scanner`, observed live on 2026-07-31) with the 157-entry
# upstream list, leaving the main node with no scanner fingerprints at all.
# Anything hand-classified belongs in CURATED_FILE, never in ja3.json directly.
#
# Cron (weekly, Sunday 03:15):
#   15 3 * * 0 root /var/www/html/pqcrypta-proxy/scripts/refresh_fingerprint_db.sh

DEST_DIR="/var/lib/pqcrypta-proxy/fingerprints"
DEST_FILE="${DEST_DIR}/ja3.json"
CURATED_FILE="${DEST_DIR}/ja3-curated.json"
LOG_FILE="/var/log/pqcrypta-proxy/fingerprint_db_refresh.log"
SOURCE_URL="https://raw.githubusercontent.com/salesforce/ja3/master/lists/osx-nix-ja3.csv"

# Other pqcrypta-proxy nodes: "<ssh-target>|<ssh-opts>" (see feedback_proxy_deploy_both).
# The refresh cron only runs here, so every other node gets the merged DB pushed.
# Use `-o Port=` and not `-p`: ssh reads `-p` as the port but scp reads it as
# "preserve times" and then swallows the number as a source path. This host's
# ssh_config defaults outbound to 1707, so the port must be stated explicitly.
FLEET_NODES=(
    "root@10.10.0.2|-o Port=22"
    "root@209.46.123.222|-o Port=22"
    "root@74.208.108.89|-o Port=22 -i /root/.ssh/pentest_sync_rsa"
)

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

# Merge the curated overlay on top of upstream. Curated entries win on hash
# collision (they carry the locally observed classification), and a malformed
# overlay is a hard stop — shipping upstream alone is the exact regression this
# overlay exists to prevent.
if [ -s "${CURATED_FILE}" ]; then
    MERGE_OUT=$(python3 - "${TMP_JSON}" "${CURATED_FILE}" << 'PYEOF'
import json, sys

upstream_path, curated_path = sys.argv[1], sys.argv[2]

with open(upstream_path) as f:
    upstream = json.load(f)
with open(curated_path) as f:
    curated = json.load(f)

if not isinstance(curated, list) or not curated:
    raise SystemExit("curated overlay is not a non-empty list")

merged = {e["hash"]: e for e in upstream}
for entry in curated:
    if not all(k in entry for k in ("hash", "classification", "description")):
        raise SystemExit(f"curated entry missing required keys: {entry}")
    merged[entry["hash"]] = entry

with open(upstream_path, "w") as f:
    json.dump(list(merged.values()), f, indent=2)

print(f"{len(upstream)} upstream + {len(curated)} curated = {len(merged)}")
PYEOF
)
    MERGE_EXIT=$?
    if [ "${MERGE_EXIT}" -ne 0 ]; then
        log "ERROR: curated overlay merge failed (exit ${MERGE_EXIT}: ${MERGE_OUT}) — existing database preserved"
        exit 0
    fi
    log "Merged curated overlay: ${MERGE_OUT}"
else
    log "WARNING: no curated overlay at ${CURATED_FILE} — shipping upstream entries only"
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

# Sync the merged DB to the rest of the fleet. Runs whether or not the local DB
# changed: a node that was unreachable during an earlier refresh would otherwise
# stay behind forever, since the next run sees "unchanged" and exits. Each node
# is compared by checksum first, so an in-sync node is never restarted. A node
# that is unreachable is logged and skipped — it must never hold up the others
# or fail the refresh.
sync_fleet() {
    LOCAL_SUM=$(sha256sum "${DEST_FILE}" | awk '{print $1}')
    for NODE in "${FLEET_NODES[@]}"; do
        TARGET="${NODE%%|*}"
        SSH_OPTS="${NODE#*|}"
        # shellcheck disable=SC2086
        REMOTE_SUM=$(ssh ${SSH_OPTS} -o BatchMode=yes -o ConnectTimeout=15 "${TARGET}" \
            "sha256sum ${DEST_FILE} 2>/dev/null | awk '{print \$1}'" 2>/dev/null)
        if [ "${REMOTE_SUM}" = "${LOCAL_SUM}" ]; then
            log "${TARGET} already in sync — not restarted"
            continue
        fi
        # shellcheck disable=SC2086
        if ! scp -q -C ${SSH_OPTS} -o BatchMode=yes -o ConnectTimeout=15 \
                "${DEST_FILE}" "${TARGET}:${DEST_FILE}" 2>/dev/null; then
            log "WARNING: could not copy DB to ${TARGET} — node left on its previous DB"
            continue
        fi
        # shellcheck disable=SC2086
        NODE_OUT=$(ssh ${SSH_OPTS} -o BatchMode=yes -o ConnectTimeout=60 "${TARGET}" \
            'RUN_USER=$(systemctl show pqcrypta-proxy -p User --value); \
             if [ -n "$RUN_USER" ] && [ "$RUN_USER" != "root" ]; then \
                 chown "$RUN_USER:$RUN_USER" /var/lib/pqcrypta-proxy/fingerprints/ja3.json; \
                 chmod 640 /var/lib/pqcrypta-proxy/fingerprints/ja3.json; \
             else \
                 chmod 600 /var/lib/pqcrypta-proxy/fingerprints/ja3.json; \
             fi; \
             systemctl restart pqcrypta-proxy; \
             for i in $(seq 1 15); do \
                 S=$(systemctl is-active pqcrypta-proxy); \
                 [ "$S" = "active" ] && break; sleep 2; \
             done; echo "$S"' 2>&1)
        if [ "${NODE_OUT}" = "active" ]; then
            log "Pushed DB to ${TARGET} (proxy active)"
        else
            log "WARNING: ${TARGET} did not come back active (${NODE_OUT}) — DB copied, check that node"
        fi
    done
}

if [ "${NEW_SUM}" = "${OLD_SUM}" ]; then
    log "Database unchanged (${ENTRY_COUNT} entries) — no local restart needed"
    sync_fleet
    log "Refresh complete"
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

sync_fleet

log "Refresh complete"
exit 0

#!/bin/bash
# Weekly cron refresh of the JA3/JA4 fingerprint database, and the distribution
# point for every pqcrypta-proxy runtime data file across the fleet.
#
# Refresh: downloads the latest Salesforce JA3 list, converts it to JSON, merges
# the locally curated overlay on top, and atomically replaces the existing
# database ONLY if the download and conversion succeed, restarting the local
# proxy only when the content actually changed.
#
# Distribution: this host is the master for the runtime data files, and this is
# the only job that runs on a schedule, so it also replicates FLEET_DATA_FILES to
# the other nodes. That runs on EVERY path through the script — including a
# failed download — because a node's copy can be stale for reasons that have
# nothing to do with today's upstream fetch.
#
# The curated overlay exists because the upstream list was once the ONLY input:
# on 2026-08-02 this refresh silently replaced a database that had 22 hand-added
# fingerprints (19 of them `scanner`, observed live on 2026-07-31) with the
# 157-entry upstream list, leaving the main node with no scanner fingerprints at
# all. Anything hand-classified belongs in CURATED_FILE, never in ja3.json.
#
# Cron (weekly, Sunday 03:15):
#   15 3 * * 0 root /var/www/html/pqcrypta-proxy/scripts/refresh_fingerprint_db.sh

DEST_DIR="/var/lib/pqcrypta-proxy/fingerprints"
DEST_FILE="${DEST_DIR}/ja3.json"
CURATED_FILE="${DEST_DIR}/ja3-curated.json"
LOG_FILE="/var/log/pqcrypta-proxy/fingerprint_db_refresh.log"
SOURCE_URL="https://raw.githubusercontent.com/salesforce/ja3/master/lists/osx-nix-ja3.csv"

# MaxMind GeoLite2 refresh. geoipupdate downloads into GEOIP_STAGE (persistent,
# so its conditional GET makes an unchanged week free), each file is validated
# there, and only a valid file is promoted to the live path below. The masters
# had gone 7 months stale (2026-01-22) because nothing refreshed them at all.
#
# This job is the ONLY scheduler for geoipupdate: the Ubuntu package ships its
# own `geoipupdate.timer` (Wed+Sat) and /etc/cron.d/geoipupdate, which would be a
# second writer into the staging directory on a schedule that promotes nothing.
# The timer was disabled on 2026-08-15; the cron.d entry self-disables under
# systemd. If a package upgrade re-enables the timer, disable it again rather
# than letting two owners race.
GEOIP_DIR="/var/www/html/pqcrypta-proxy/data/geoip"
GEOIP_STAGE="/var/lib/pqcrypta-proxy/geoip-staging"
GEOIP_CONF="/etc/GeoIP.conf"
GEOIP_EDITIONS="GeoLite2-City GeoLite2-ASN"

# Other pqcrypta-proxy nodes: "<ssh-target>|<ssh-opts>" (see feedback_proxy_deploy_both).
# The refresh cron only runs here, so every other node gets its data files pushed.
# Use `-o Port=` and not `-p`: ssh reads `-p` as the port but scp reads it as
# "preserve times" and then swallows the number as a source path. This host's
# ssh_config defaults outbound to 1707, so the port must be stated explicitly.
FLEET_NODES=(
    "root@10.10.0.2|-o Port=22"
    "root@209.46.123.222|-o Port=22"
    "root@74.208.108.89|-o Port=22 -i /root/.ssh/pentest_sync_rsa"
)

# Runtime data files replicated to every node:
#   "<local path>|<mode>|<owner-sensitive>|<remote destination resolver>"
#
# The resolver is a command run ON the target node whose output is the
# destination path; empty means "same path as here". It exists because api3
# keeps the City database at /etc/pqcrypta/geoip/ via its own `geoip_db_path`,
# so a sync that assumed the local path wrote a file that node's proxy does not
# read — the copy would have looked successful while api3 quietly kept serving a
# stale database forever. Resolving per node also means a future path change on
# any node needs no edit here.
# These are the files whose absence the proxy survives with only a WARN and a
# silently disabled feature, which is exactly why drift here goes unnoticed:
# the mail host was found on 2026-08-15 with none of them and no directories at
# all, running with GeoIP off and an empty JA3 DB while its own config keyed rate
# limiting on ja3_fingerprint.
#
# owner-sensitive=yes → on a node whose proxy does not run as root the file is
# chowned to the run user and forced to 640; remotellm runs as `pqcrypta`, and a
# root-owned 600 file there loads as an EMPTY database with only a warning.
# "no" files are world-readable, so they need no chown.
#
# GeoLite2-Country.mmdb is deliberately NOT here: the proxy reads City (via
# config `geoip_db_path`) and ASN (hardcoded in speedtest.rs) and nothing reads
# Country.
GEOIP_PATH_RESOLVER="awk -F'\"' '/^geoip_db_path/ {print \$2}' /etc/pqcrypta/proxy-config.toml"
FLEET_DATA_FILES=(
    "${DEST_FILE}|600|yes|"
    "${GEOIP_DIR}/GeoLite2-City.mmdb|644|no|${GEOIP_PATH_RESOLVER}"
    "${GEOIP_DIR}/GeoLite2-ASN.mmdb|644|no|"
)

mkdir -p "$(dirname "${LOG_FILE}")"
TS=$(date '+%Y-%m-%d %H:%M:%S')

log() { echo "[${TS}] $1" >> "${LOG_FILE}"; }

LOCAL_RESTARTED=0
GEOIP_CHANGED=0

# Restart the local proxy at most once per run, however many databases changed.
restart_local() {
    [ "${LOCAL_RESTARTED}" -eq 1 ] && return
    LOCAL_RESTARTED=1
    systemctl restart pqcrypta-proxy 2>&1
    if [ "$?" -eq 0 ]; then
        log "pqcrypta-proxy restarted successfully"
    else
        log "WARNING: local restart failed — new data will be loaded on next restart"
    fi
}

# A MaxMind DB ends with the metadata marker \xab\xcd\xefMaxMind.com. Checking for
# it catches a truncated or error-page download, which would otherwise replace a
# good database with something the proxy silently fails to load.
valid_mmdb() {
    [ -s "$1" ] || return 1
    [ "$(stat -c %s "$1")" -gt 1000000 ] || return 1
    tail -c 131072 "$1" | grep -qa $'\xab\xcd\xefMaxMind.com'
}

# Refresh the GeoLite2 masters, then promote only what validates.
update_geoip() {
    if ! command -v geoipupdate >/dev/null 2>&1; then
        log "WARNING: geoipupdate not installed — GeoIP masters not refreshed (distribution still runs)"
        return
    fi
    # Anchored to the directives: an unanchored match also hits the comment in
    # GeoIP.conf that explains the placeholder, which silently disabled the
    # refresh even with real credentials in place.
    if [ ! -s "${GEOIP_CONF}" ] || grep -qE "^(AccountID|LicenseKey)[[:space:]]+REPLACE_WITH_" "${GEOIP_CONF}"; then
        log "WARNING: ${GEOIP_CONF} still holds placeholder credentials — GeoIP masters not refreshed (distribution still runs)"
        return
    fi

    mkdir -p "${GEOIP_STAGE}"
    GEOIP_OUT=$(geoipupdate -f "${GEOIP_CONF}" -d "${GEOIP_STAGE}" 2>&1)
    if [ "$?" -ne 0 ]; then
        log "ERROR: geoipupdate failed (${GEOIP_OUT}) — existing GeoIP masters preserved"
        return
    fi

    for EDITION in ${GEOIP_EDITIONS}; do
        STAGED="${GEOIP_STAGE}/${EDITION}.mmdb"
        LIVE="${GEOIP_DIR}/${EDITION}.mmdb"
        if [ ! -f "${STAGED}" ]; then
            log "WARNING: ${EDITION} missing from staging after update — ${LIVE} left as is"
            continue
        fi
        if ! valid_mmdb "${STAGED}"; then
            log "ERROR: staged ${EDITION} failed validation — ${LIVE} left as is"
            continue
        fi
        if [ -f "${LIVE}" ] && [ "$(sha256sum "${STAGED}" | awk '{print $1}')" = "$(sha256sum "${LIVE}" | awk '{print $1}')" ]; then
            continue
        fi
        # Copy then rename: a rename within the directory is atomic, so the proxy
        # never sees a half-written database even if it starts mid-promotion.
        if cp "${STAGED}" "${LIVE}.tmp" && chmod 644 "${LIVE}.tmp" && mv "${LIVE}.tmp" "${LIVE}"; then
            log "Updated ${EDITION} ($(stat -c %s "${LIVE}") bytes, built $(date -r "${LIVE}" '+%Y-%m-%d'))"
            GEOIP_CHANGED=1
        else
            rm -f "${LIVE}.tmp"
            log "ERROR: could not promote ${EDITION} into ${GEOIP_DIR}"
        fi
    done
}

# Replicate FLEET_DATA_FILES to every other node. Each file is compared by
# checksum first, so an in-sync node is never copied to and never restarted, and
# the ~72 MB of GeoIP data crosses the wire only when it actually changes. A node
# that is unreachable is logged and skipped — it must never hold up the others or
# fail the refresh.
sync_fleet() {
    SPECS=()
    for SPEC in "${FLEET_DATA_FILES[@]}"; do
        SRC="${SPEC%%|*}"
        if [ ! -s "${SRC}" ]; then
            log "WARNING: local master ${SRC} is missing or empty — not distributed"
            continue
        fi
        SPECS+=("${SPEC}")
    done
    if [ "${#SPECS[@]}" -eq 0 ]; then
        log "ERROR: no local data files available to distribute"
        return
    fi

    # Remote probe: resolve each file's destination on that node, create its
    # directory, and report its checksum — one line of "<index> <path> <sum>"
    # per file, in a single round trip.
    PROBE=""
    IDX=0
    for SPEC in "${SPECS[@]}"; do
        SRC="${SPEC%%|*}"
        RESOLVER="${SPEC##*|}"
        if [ -n "${RESOLVER}" ]; then
            PROBE="${PROBE} D=\$(${RESOLVER} 2>/dev/null); [ -z \"\$D\" ] && D=${SRC};"
        else
            PROBE="${PROBE} D=${SRC};"
        fi
        PROBE="${PROBE} mkdir -p \$(dirname \$D) 2>/dev/null; echo \"${IDX} \$D \$(sha256sum \$D 2>/dev/null | awk '{print \$1}')\";"
        IDX=$((IDX + 1))
    done

    for NODE in "${FLEET_NODES[@]}"; do
        TARGET="${NODE%%|*}"
        SSH_OPTS="${NODE#*|}"

        # The trailing `:` forces a zero exit so a missing FILE is not mistaken
        # for an unreachable NODE.
        # shellcheck disable=SC2086
        PROBE_OUT=$(ssh ${SSH_OPTS} -o BatchMode=yes -o ConnectTimeout=15 "${TARGET}" \
            "${PROBE} :" 2>/dev/null)
        if [ "$?" -ne 0 ]; then
            log "WARNING: ${TARGET} unreachable — left on its previous data files"
            continue
        fi

        CHANGED=""
        FIXUPS=""
        IDX=0
        for SPEC in "${SPECS[@]}"; do
            SRC="${SPEC%%|*}"
            REST="${SPEC#*|}"
            MODE="${REST%%|*}"
            REST="${REST#*|}"
            OWNED="${REST%%|*}"

            DEST=$(echo "${PROBE_OUT}" | awk -v k="${IDX}" '$1 == k { print $2 }')
            REMOTE_SUM=$(echo "${PROBE_OUT}" | awk -v k="${IDX}" '$1 == k { print $3 }')
            IDX=$((IDX + 1))
            if [ -z "${DEST}" ]; then
                log "WARNING: ${TARGET} did not resolve a destination for $(basename "${SRC}") — skipped"
                continue
            fi

            LOCAL_SUM=$(sha256sum "${SRC}" | awk '{print $1}')
            [ "${LOCAL_SUM}" = "${REMOTE_SUM}" ] && continue

            # shellcheck disable=SC2086
            if ! scp -q -C ${SSH_OPTS} -o BatchMode=yes -o ConnectTimeout=15 \
                    "${SRC}" "${TARGET}:${DEST}" 2>/dev/null; then
                log "WARNING: could not copy $(basename "${SRC}") to ${TARGET}:${DEST} — node left on its previous copy"
                continue
            fi
            CHANGED="${CHANGED} $(basename "${SRC}")"
            if [ "${OWNED}" = "yes" ]; then
                FIXUPS="${FIXUPS} if [ -n \"\$RU\" ] && [ \"\$RU\" != root ]; then chown \$RU:\$RU ${DEST} && chmod 640 ${DEST}; else chmod ${MODE} ${DEST}; fi;"
            else
                FIXUPS="${FIXUPS} chmod ${MODE} ${DEST};"
            fi
        done

        if [ -z "${CHANGED}" ]; then
            log "${TARGET} already in sync — not restarted"
            continue
        fi

        # shellcheck disable=SC2086
        NODE_OUT=$(ssh ${SSH_OPTS} -o BatchMode=yes -o ConnectTimeout=60 "${TARGET}" \
            "RU=\$(systemctl show pqcrypta-proxy -p User --value);${FIXUPS} \
             systemctl restart pqcrypta-proxy; \
             for i in \$(seq 1 15); do \
                 S=\$(systemctl is-active pqcrypta-proxy); \
                 [ \"\$S\" = active ] && break; sleep 2; \
             done; echo \"\$S\"" 2>&1)
        if [ "${NODE_OUT}" = "active" ]; then
            log "Pushed to ${TARGET}:${CHANGED} (proxy active)"
        else
            log "WARNING: ${TARGET} did not come back active (${NODE_OUT}) — files copied${CHANGED}, check that node"
        fi
    done
}

# Every exit path goes through here, so the GeoIP refresh and the fleet are
# reconciled even when the JA3 fetch failed and the local database was left
# untouched.
finish() {
    [ "${GEOIP_CHANGED}" -eq 1 ] && restart_local
    sync_fleet
    log "Refresh complete"
    exit 0
}

log "Starting proxy data refresh..."

# Bail out cleanly on any unexpected error — never touch the live DB
set +e

# GeoIP first: it is independent of the JA3 fetch, and every JA3 failure path
# routes through finish(), which needs the masters already updated.
update_geoip

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
    finish
fi

if [ ! -s "${TMP_CSV}" ]; then
    log "ERROR: downloaded file is empty — existing database preserved"
    finish
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
    finish
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
        finish
    fi
    log "Merged curated overlay: ${MERGE_OUT}"
else
    log "WARNING: no curated overlay at ${CURATED_FILE} — shipping upstream entries only"
fi

if [ ! -s "${TMP_JSON}" ]; then
    log "ERROR: converted JSON is empty — existing database preserved"
    finish
fi

ENTRY_COUNT=$(python3 -c "import json; d=json.load(open('${TMP_JSON}')); print(len(d))" 2>/dev/null)
if [ -z "${ENTRY_COUNT}" ] || [ "${ENTRY_COUNT}" -lt 10 ]; then
    log "ERROR: converted DB has only ${ENTRY_COUNT} entries (minimum 10 required) — existing database preserved"
    finish
fi

# Compare checksums — skip restart if nothing changed
NEW_SUM=$(sha256sum "${TMP_JSON}" | awk '{print $1}')
OLD_SUM=""
if [ -f "${DEST_FILE}" ]; then
    OLD_SUM=$(sha256sum "${DEST_FILE}" | awk '{print $1}')
fi

if [ "${NEW_SUM}" = "${OLD_SUM}" ]; then
    log "JA3 database unchanged (${ENTRY_COUNT} entries)"
    finish
fi

# Atomic replace
chmod 0600 "${TMP_JSON}"
mv "${TMP_JSON}" "${DEST_FILE}"
log "Updated JA3 database: ${ENTRY_COUNT} entries (was: $([ -n "${OLD_SUM}" ] && echo 'different' || echo 'new'))"

# Reload service to pick up new DB (fast: proxy starts in < 2s)
restart_local

finish

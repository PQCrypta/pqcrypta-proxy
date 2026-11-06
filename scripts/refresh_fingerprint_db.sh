#!/bin/bash
# Weekly refresh of the JA3/JA4 fingerprint database and the GeoLite2
# databases, the distribution point for every pqcrypta-proxy runtime data file
# across the fleet, and the check that each node's config is what
# pqcrypta-configs tracks.
#
# Runs as the fleet's data account, pqcrypta-fleet (pqcrypta-configs
# pqcrypta-fleet-refresh.service, Sundays 03:15): it owns the data directories
# it writes, and reaches the other nodes over ssh as the same account
# (/etc/pqcrypta/fleet/ssh_config), where a forced command
# (pqcrypta-fleet-endpoint) answers sums, put and config and nothing else. A
# proxy reloads its data files when they change (pqcrypta-proxy-data.path), so
# nothing here reloads one. It ran as root, over root's ssh to every node.
#
# Refresh: downloads the latest Salesforce JA3 list, converts it to JSON, merges
# the locally curated overlay on top, and atomically replaces the existing
# database ONLY if the download and conversion succeed.
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
# Exit status: 0, or 3 when a node's config has moved from what is tracked
# (the unit's failure is the alert; the drifted copy is in DRIFT_DIR).

DEST_DIR="/var/lib/pqcrypta-proxy/fingerprints"
DEST_FILE="${DEST_DIR}/ja3.json"
CURATED_FILE="${DEST_DIR}/ja3-curated.json"
SOURCE_URL="https://raw.githubusercontent.com/salesforce/ja3/master/lists/osx-nix-ja3.csv"
STATE="${STATE_DIRECTORY:-/var/lib/pqcrypta-fleet}"

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
# than letting two owners race. Its account and licence key are the unit's
# credential (/etc/GeoIP.conf is root's).
GEOIP_DIR="/var/lib/pqcrypta-proxy/geoip"
GEOIP_STAGE="${STATE}/geoip-staging"
GEOIP_CONF="${CREDENTIALS_DIRECTORY:-/nonexistent}/GeoIP.conf"
GEOIP_EDITIONS="GeoLite2-City GeoLite2-ASN"

# The other pqcrypta-proxy nodes, "<ssh host>|<tracked config dir>": each
# pqcrypta-configs pqcrypta/nodes/<dir>/ssh-host names its node as
# fleet/ssh_config knows it, by name. The list was a copy of the nodes'
# addresses; it is read from the one place that says which nodes there are.
CONFIG_REPO="/var/www/html/pqcrypta-configs/pqcrypta/nodes"
SSH_CONFIG="/etc/pqcrypta/fleet/ssh_config"
FLEET_NODES=()
for HOST_FILE in "${CONFIG_REPO}"/*/ssh-host; do
    [ -f "${HOST_FILE}" ] || continue
    FLEET_NODES+=("$(tr -d '[:space:]' < "${HOST_FILE}")|$(basename "$(dirname "${HOST_FILE}")")")
done

# The placeholder the repo commits in place of a real admin token. Deliberately
# 24 characters — under the 32 the proxy demands — so a config copied from the
# repo fails to start rather than running with a guessable token. The node's
# endpoint writes it in (pqcrypta-config-redact); it is checked again here.
TOKEN_PLACEHOLDER='auth_token = "REPLACE_WITH_ADMIN_TOKEN"  # live value lives only in /etc/pqcrypta/proxy-config.toml (0640) — never commit a real token'
DRIFT_DIR="${STATE}/drift"

# Runtime data files replicated to every node, at the same paths everywhere
# (each node's config names them: security.geoip_db_path and
# geoip_asn_db_path). These are the files whose absence the proxy survives with
# only a WARN and a silently disabled feature, which is exactly why drift here
# goes unnoticed: the mail host was found on 2026-08-15 with none of them and
# no directories at all, running with GeoIP off and an empty JA3 DB while its
# own config keyed rate limiting on ja3_fingerprint.
#
# GeoLite2-Country.mmdb is deliberately NOT here: the proxy reads City and ASN
# and nothing reads Country.
FLEET_DATA_FILES=(
    "${DEST_FILE}"
    "${GEOIP_DIR}/GeoLite2-City.mmdb"
    "${GEOIP_DIR}/GeoLite2-ASN.mmdb"
)

# Each line's own time. One timestamp taken at the start stamped every line
# with it, so a restart that ran from 03:15:04 to 03:15:38 was logged as done
# at 03:15:01, the second the script started.
# To stdout: the unit appends it to /var/log/pqcrypta/fingerprint_db_refresh.log
log() { echo "[$(date '+%Y-%m-%d %H:%M:%S')] $1"; }
fleet() { ssh -F "${SSH_CONFIG}" "$@"; }

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
        # GeoLite2 is MaxMind's published data: readable by all (the web
        # server's pages read it too).
        if cp "${STAGED}" "${LIVE}.tmp" && chmod 644 "${LIVE}.tmp" && mv "${LIVE}.tmp" "${LIVE}"; then
            log "Updated ${EDITION} ($(stat -c %s "${LIVE}") bytes, built $(date -r "${LIVE}" '+%Y-%m-%d'); the proxy reloads it)"
        else
            rm -f "${LIVE}.tmp"
            log "ERROR: could not promote ${EDITION} into ${GEOIP_DIR}"
        fi
    done
}

# Replicate FLEET_DATA_FILES to every other node. Each file is compared by
# checksum first (the endpoint's sums), so an in-sync node is never copied to,
# and the ~72 MB of GeoIP data crosses the wire only when it actually changes.
# The node checks what it receives against its checksum and its format before
# renaming it into place, and its proxy reloads it. A node that is unreachable
# is logged and skipped — it must never hold up the others or fail the refresh.
sync_fleet() {
    local NODE TARGET SUMS SRC NAME LOCAL_SUM REMOTE_SUM OUT CHANGED
    for NODE in "${FLEET_NODES[@]}"; do
        TARGET="${NODE%%|*}"
        if ! SUMS=$(fleet "${TARGET}" sums 2>&1); then
            log "WARNING: ${TARGET} unreachable (${SUMS}) — left on its previous data files"
            continue
        fi
        CHANGED=""
        for SRC in "${FLEET_DATA_FILES[@]}"; do
            NAME=$(basename "${SRC}")
            if [ ! -s "${SRC}" ]; then
                log "WARNING: local master ${SRC} is missing or empty — not distributed"
                continue
            fi
            LOCAL_SUM=$(sha256sum "${SRC}" | awk '{print $1}')
            REMOTE_SUM=$(python3 -c 'import json,sys; print(json.load(sys.stdin).get(sys.argv[1]) or "")' "${NAME}" <<< "${SUMS}" 2>/dev/null)
            [ "${LOCAL_SUM}" = "${REMOTE_SUM}" ] && continue
            if OUT=$(fleet "${TARGET}" put "${NAME}" "${LOCAL_SUM}" < "${SRC}" 2>&1); then
                CHANGED="${CHANGED} ${NAME}"
            else
                log "WARNING: ${TARGET} refused ${NAME} (${OUT}) — node left on its previous copy"
            fi
        done
        if [ -n "${CHANGED}" ]; then
            log "Pushed to ${TARGET}:${CHANGED} (its proxy reloads them)"
        else
            log "${TARGET} already in sync"
        fi
    done
}

# Report proxy configs that have drifted from what is tracked in
# pqcrypta-configs.
#
# Detection only: a node whose config moved has its copy (admin token replaced
# by the placeholder) kept in DRIFT_DIR for review, and the run fails, which is
# the alert. Nothing writes the repository's working tree, which is root's.
#
# The reason this exists: the tracked copy was found 474 lines behind the
# running node, still naming the obsolete x25519_kyber768 KEM. A rebuild from
# the repo would have deployed it. Nothing was watching, so nothing said so.
DRIFTED=0
check_config_drift() {
    [ -d "${CONFIG_REPO}" ] || { log "config drift: ${CONFIG_REPO} missing, skipped"; return; }
    rm -rf "${DRIFT_DIR}" && mkdir -p "${DRIFT_DIR}"
    local NODE TARGET NAME TRACKED COPY N
    # This node's own copy is written by pqcrypta-config-redact as this account
    for NODE in "local|local" "${FLEET_NODES[@]}"; do
        TARGET="${NODE%%|*}"
        NAME="${NODE#*|}"
        TRACKED="${CONFIG_REPO}/${NAME}/proxy-config.toml"
        COPY="${DRIFT_DIR}/${NAME}.proxy-config.toml"
        [ -f "${TRACKED}" ] || { log "config drift: ${NAME} not tracked yet"; DRIFTED=1; continue; }
        if [ "${TARGET}" = "local" ]; then
            cp "${STATE}/proxy-config.toml" "${COPY}" 2>/dev/null
        else
            fleet "${TARGET}" config > "${COPY}" 2>/dev/null
        fi
        if [ ! -s "${COPY}" ]; then
            log "config drift: could not read ${NAME}'s config — node unreachable?"
            rm -f "${COPY}"; continue
        fi
        # "A token line exists AND it is not the placeholder". Both halves are
        # needed: a node with no [admin] section (fortress) has no token line.
        if grep -qE '^auth_token' "${COPY}" \
           && ! grep -qxF "${TOKEN_PLACEHOLDER}" "${COPY}"; then
            log "config drift: ABORT on ${NAME} — its copy does not carry the placeholder, discarded"
            rm -f "${COPY}"; DRIFTED=1; continue
        fi
        N=$(diff "${TRACKED}" "${COPY}" 2>/dev/null | grep -c '^[<>]')
        if [ "${N}" -gt 0 ]; then
            log "config drift: ${NAME} moved ${N} lines — copy in ${COPY}, review and commit to pqcrypta-configs"
            DRIFTED=1
        else
            rm -f "${COPY}"
        fi
    done
    [ "${DRIFTED}" -eq 0 ] && log "config drift: every node's config matches what is tracked"
}

# Every exit path goes through here, so the GeoIP refresh and the fleet are
# reconciled even when the JA3 fetch failed and the local database was left
# untouched.
finish() {
    sync_fleet
    check_config_drift
    log "Refresh complete"
    [ "${DRIFTED}" -eq 0 ] || exit 3
    exit 0
}

log "Starting proxy data refresh..."

# Bail out cleanly on any unexpected error — never touch the live DB
set +e

# GeoIP first: it is independent of the JA3 fetch, and every JA3 failure path
# routes through finish(), which needs the masters already updated.
update_geoip

TMP_CSV=$(mktemp /tmp/ja3_refresh_XXXXXX.csv)
# Beside the database it replaces, so that the replacement is a rename within
# one file system: built in /tmp, it was copied across, and the proxy could
# load it half written
TMP_JSON=$(mktemp "${DEST_DIR}/.ja3_refresh_XXXXXX.json")

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

# Compare checksums — skip the reload if nothing changed
NEW_SUM=$(sha256sum "${TMP_JSON}" | awk '{print $1}')
OLD_SUM=""
if [ -f "${DEST_FILE}" ]; then
    OLD_SUM=$(sha256sum "${DEST_FILE}" | awk '{print $1}')
fi

if [ "${NEW_SUM}" = "${OLD_SUM}" ]; then
    log "JA3 database unchanged (${ENTRY_COUNT} entries)"
    finish
fi

# Atomic replace. Readable by the proxy's group (the directory's, set-group-ID),
# the fleet account's: 0640. The proxy reloads it (pqcrypta-proxy-data.path).
chmod 0640 "${TMP_JSON}"
mv "${TMP_JSON}" "${DEST_FILE}"
log "Updated JA3 database: ${ENTRY_COUNT} entries (was: $([ -n "${OLD_SUM}" ] && echo 'different' || echo 'new'))"

finish

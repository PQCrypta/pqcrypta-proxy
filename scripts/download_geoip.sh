#!/usr/bin/env bash
# F-11: Download MaxMind GeoLite2 databases.
#
# These files are excluded from version control because:
#   1. MaxMind updates them weekly — a committed copy goes stale silently.
#   2. The GeoLite2 license requires account registration and attribution.
#
# Usage:
#   export MAXMIND_ACCOUNT_ID=<your account ID>
#   export MAXMIND_LICENSE_KEY=<your license key>
#   scripts/download_geoip.sh
#
# Or pass account/key as arguments:
#   scripts/download_geoip.sh <account_id> <license_key>
#
# A MaxMind account can be created free at https://www.maxmind.com/en/geolite2/signup
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
DATA_DIR="${SCRIPT_DIR}/../data/geoip"
MAXMIND_BASE="https://download.maxmind.com/app/geoip_download"

ACCOUNT_ID="${1:-${MAXMIND_ACCOUNT_ID:-}}"
LICENSE_KEY="${2:-${MAXMIND_LICENSE_KEY:-}}"

if [[ -z "$ACCOUNT_ID" || -z "$LICENSE_KEY" ]]; then
    echo "ERROR: MaxMind account ID and license key are required." >&2
    echo "       Set MAXMIND_ACCOUNT_ID and MAXMIND_LICENSE_KEY, or pass them as arguments." >&2
    echo "       Register at: https://www.maxmind.com/en/geolite2/signup" >&2
    exit 1
fi

mkdir -p "$DATA_DIR"

download_db() {
    local edition="$1"
    local out_file="${DATA_DIR}/${edition}.mmdb"
    local tmp_tar="${DATA_DIR}/${edition}.tar.gz.tmp"

    echo "Downloading ${edition}..."
    # SEC-A08: Credentials are sent via HTTP Basic Auth (--user flag) only.
    # The license_key query parameter is redundant and was removed because URL
    # query strings are recorded in web-server logs, CDN logs, and shell history,
    # making the MaxMind credential easier to exfiltrate accidentally.
    curl --silent --show-error --fail \
        --user "${ACCOUNT_ID}:${LICENSE_KEY}" \
        "${MAXMIND_BASE}?edition_id=${edition}&suffix=tar.gz" \
        -o "$tmp_tar"

    # Extract the .mmdb from the tarball (it's nested in a dated directory)
    local extracted
    extracted="$(tar -tzf "$tmp_tar" | grep '\.mmdb$' | head -n1)"
    if [[ -z "$extracted" ]]; then
        echo "ERROR: No .mmdb file found in ${edition} tarball." >&2
        rm -f "$tmp_tar"
        exit 1
    fi

    tar -xzf "$tmp_tar" -C "$DATA_DIR" --strip-components=1 "$extracted"
    # tar writes to a directory-prefixed path; rename to flat file
    local extracted_name
    extracted_name="$(basename "$extracted")"
    if [[ "$extracted_name" != "${edition}.mmdb" ]]; then
        mv "${DATA_DIR}/${extracted_name}" "$out_file"
    fi
    rm -f "$tmp_tar"

    echo "  → ${out_file}"
}

download_db "GeoLite2-Country"
download_db "GeoLite2-City"
download_db "GeoLite2-ASN"

echo ""
echo "GeoIP databases updated in ${DATA_DIR}"
echo "Database age check: consider running this script weekly (Sunday) via cron."

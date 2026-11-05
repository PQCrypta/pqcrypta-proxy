#!/bin/bash
# Download and convert the Salesforce JA3 fingerprint database to pqcrypta-proxy format.
# Source: https://github.com/salesforce/ja3 (BSD 3-Clause)
#
# Usage: sudo ./scripts/setup_fingerprint_db.sh
# Creates: /var/lib/pqcrypta-proxy/fingerprints/ja3.json

set -euo pipefail

DEST_DIR="/var/lib/pqcrypta-proxy/fingerprints"
DEST_FILE="${DEST_DIR}/ja3.json"
# The directory and file are root's (root writes them, here and in
# refresh_fingerprint_db.sh); the proxy, running as its own account, reads
# them through its group.
PROXY_GROUP="root"
if getent group pqcrypta >/dev/null; then
    PROXY_GROUP="pqcrypta"
fi

# Create directory (set-group-ID: what is written here takes the group)
install -d -m 2750 -o root -g "${PROXY_GROUP}" "${DEST_DIR}"

echo "Downloading Salesforce JA3 fingerprint list..."
TMP_CSV=$(mktemp /tmp/ja3_XXXXXX.csv)
curl -fsSL \
  "https://raw.githubusercontent.com/salesforce/ja3/master/lists/osx-nix-ja3.csv" \
  -o "${TMP_CSV}"

echo "Converting to JSON..."
python3 << PYEOF
import json

with open("${TMP_CSV}", "r") as f:
    content = f.read()

lines = content.strip().split('\n')
entries = []
in_header = True

for line in lines:
    line = line.strip()
    if not line:
        continue
    parts = line.split(',', 1)
    if len(parts) != 2:
        continue
    candidate_hash = parts[0].strip().strip('"').lower()
    desc = parts[1].strip().strip('"')

    # Skip header lines (non-hex or wrong length)
    if len(candidate_hash) != 32 or not all(c in '0123456789abcdef' for c in candidate_hash):
        continue

    desc_lower = desc.lower()
    classification = "api_client"
    if any(x in desc_lower for x in ["chrome", "firefox", "safari", "edge", "webkit"]):
        classification = "browser"
    elif any(x in desc_lower for x in ["bot", "crawler", "googlebot", "bingbot", "spider"]):
        classification = "bot"
    elif any(x in desc_lower for x in ["scanner", "nikto", "nmap", "burp", "masscan", "zap", "shodan"]):
        classification = "scanner"
    elif any(x in desc_lower for x in ["malware", "ransomware", "trojan", "mirai", "exploit", "metasploit"]):
        classification = "malicious"

    entries.append({"hash": candidate_hash, "classification": classification, "description": desc})

with open("${DEST_FILE}", "w") as out:
    json.dump(entries, out, indent=2)

print(f"Wrote {len(entries)} fingerprints to ${DEST_FILE}")
PYEOF

chown "root:${PROXY_GROUP}" "${DEST_FILE}"
chmod 0640 "${DEST_FILE}"
rm -f "${TMP_CSV}"

echo "Done. Restart pqcrypta-proxy to load the new database:"
echo "  systemctl restart pqcrypta-proxy"

#!/bin/bash
# Setup cron jobs for pqcrypta-proxy blocklist sync

CRON_FILE="/etc/cron.d/pqcrypta-proxy-blocklist"

cat > "${CRON_FILE}" << 'EOF'
# PQCrypta Proxy Blocklist Automation
# Detect bots from access logs every 5 minutes
*/5 * * * * root /var/www/html/pqcrypta-proxy/scripts/detect_bots_from_logs.sh >/dev/null 2>&1

# Sync blocklist to proxy JSON files every minute
* * * * * root /var/www/html/pqcrypta-proxy/scripts/sync_blocklist.sh >/dev/null 2>&1

# Cleanup expired blocklist entries every hour
0 * * * * root sudo -u postgres psql -d pqcrypta -c "SELECT cleanup_expired_blocklist_entries()" >/dev/null 2>&1
EOF

chmod 644 "${CRON_FILE}"
echo "Cron jobs installed at ${CRON_FILE}"

# Verify
echo ""
echo "=== Installed Cron Jobs ==="
cat "${CRON_FILE}"

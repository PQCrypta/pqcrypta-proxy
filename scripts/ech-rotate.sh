#!/usr/bin/env bash
# ech-rotate.sh — Rotate the server-side Encrypted Client Hello (ECH) keypairs
# and publish the new ECHConfigList in DNS.
#
# 1. `ech-keygen` (built from this crate, `src/bin/ech-keygen.rs`) generates a
#    fresh HPKE keypair and ECHConfig per KEM, keeps the previous ones (so a
#    client holding a cached DNS record still completes), prunes older ones
#    and writes the list to publish, X-Wing first.
# 2. The proxy reloads its TLS material: QUIC and every TCP listener rebuild
#    their rustls configs with the new configs (`ech_config::reloads`), no
#    restart, no dropped connection. Asked for through the admin API when it
#    is enabled; otherwise the certificate-reload poller notices the changed
#    ECH directory within `tls.cert_reload_interval_secs`, and this waits that
#    long.
# 3. Only then is the list published: `pqcrypta-ech-publish` (pqcrypta-configs
#    dns/tools/ech-publish) writes the HTTPS records for every name that
#    carries this server's key, has the DNS signer sign them, and waits until
#    ns1, ns2 and ns3 all serve them. Publishing before the proxy holds the key
#    would send clients to a config it cannot open.
#
# Setup:
#   1. cp ech-rotate.sh /usr/local/bin/pqcrypta-ech-rotate
#   2. chmod +x /usr/local/bin/pqcrypta-ech-rotate
#   3. cp ech-rotate.service ech-rotate.timer /etc/systemd/system/
#   4. systemctl enable --now ech-rotate.timer
#
# The DNS side runs on the host with the DNS signer (web1). A proxy node whose
# names are not in the signer's https-records.conf rotates nothing here.

set -euo pipefail

OUT_DIR="${ECH_CONFIG_DIR:-/etc/pqcrypta/ech-configs}"
BIN="${ECH_KEYGEN_BIN:-/usr/local/bin/pqcrypta-ech-keygen}"
PUBLISH="${ECH_PUBLISH_BIN:-/usr/local/bin/pqcrypta-ech-publish}"
PROXY_CONFIG="${PROXY_CONFIG:-/etc/pqcrypta/proxy-config.toml}"
LOG_FILE="${LOG_FILE:-/var/log/pqcrypta/ech-rotate.log}"
# The configs' public_name, ECH's cover name: what a client sends in clear while
# the real name travels encrypted, and the name whose certificate it checks a
# rejection against before it retries (RFC 9849 6.1.6-6.1.7). A name of its
# own, so the outer ClientHello names no site; it has its records and
# certificate on web1 (pqcrypta-configs: dns/zones, [acme] domains).
PUBLIC_NAME="${ECH_PUBLIC_NAME:-ech.pqcrypta.com}"

log() { echo "$(date -u '+%Y-%m-%dT%H:%M:%SZ') $*" | tee -a "$LOG_FILE"; }

mkdir -p "$OUT_DIR" "$(dirname "$LOG_FILE")"

for tool in "$BIN" "$PUBLISH"; do
    if [[ ! -x "$tool" ]]; then
        log "ERROR: $tool not found or not executable"
        exit 1
    fi
done

# One generation per KEM: X-Wing, which a quantum computer cannot open, and
# X25519, which is all browsers implement today. ech-keygen keeps --retain of
# each and writes the list X-Wing first, so a client uses the post-quantum
# config when it can and the classical one otherwise. The X25519 run comes
# second so the list written last is the complete one.
for kem in x-wing x25519; do
    log "Rotating the $kem ECH config in $OUT_DIR"
    "$BIN" --out-dir "$OUT_DIR" --public-name "$PUBLIC_NAME" --max-name-length 32 --retain 3 --kem "$kem" >>"$LOG_FILE" 2>&1
done

# [admin] enabled / bind_address / port / auth_token, and the poller interval.
read -r admin_enabled admin_url poll_secs < <(python3 -I - "$PROXY_CONFIG" <<'EOF'
import sys, tomllib
c = tomllib.load(open(sys.argv[1], 'rb'))
a = c.get('admin', {})
print('yes' if a.get('enabled') and a.get('auth_token') else 'no',
      'http://%s:%s/reload' % (a.get('bind_address', '127.0.0.1'), a.get('port', 8082)),
      c.get('tls', {}).get('cert_reload_interval_secs', 300))
EOF
)
if [[ "$admin_enabled" == "yes" ]]; then
    # The token goes to curl on stdin (-K -), never on a command line.
    reply=$(python3 -I -c 'import sys, tomllib; print("header = \"Authorization: Bearer %s\"" % tomllib.load(open(sys.argv[1], "rb"))["admin"]["auth_token"])' "$PROXY_CONFIG" \
        | curl -sS --max-time 30 -K - -H 'Content-Type: application/json' -d '{"tls_only": true}' "$admin_url")
    if ! grep -q '"success":true' <<<"$reply"; then
        log "ERROR: the proxy did not reload its TLS material: $reply"
        exit 1
    fi
    log "Proxy reloaded its TLS material; every listener holds the new ECH configs"
else
    log "Admin API off: waiting ${poll_secs}s for the proxy's reload poller"
    sleep "$((poll_secs + 10))"
fi

log "Publishing the new ECHConfigList in DNS"
"$PUBLISH" 2>&1 | tee -a "$LOG_FILE"
log "ECH rotation complete"

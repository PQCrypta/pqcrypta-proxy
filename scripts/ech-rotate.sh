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
# 3. `pqcrypta-ech-check` (src/bin/ech-check.rs) offers each config of the
#    new list on its own to this proxy, over TCP and over QUIC, as a browser
#    does, and every handshake must be accepted. A reload is not a handshake:
#    on 2026-10-20 the proxy reloaded, QUIC kept the configs it started with,
#    and DNS published configs HTTP/3 refused. A refusal stops the rotation
#    here; DNS keeps the list it has, whose configs the proxy still holds
#    (`--retain 3`).
# 4. Only then is the list published: `pqcrypta-ech-publish` (pqcrypta-configs
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
# The DNS side runs on the host with the DNS signer (web1), which rotates the
# other nodes whose keys its https-records.conf names (api3) after itself:
# over ssh it runs this script there with ECH_PUBLISH=no (rotate, reload and
# check, and stop), collects the new list, offers each config to that node
# from here, over the network as a visitor reaches it, and publishes every
# node's records once. Those nodes get no timer of their own. Settings
# (ECH_PUBLIC_NAME, ECH_CHECK_NAME, ECH_REMOTE_NODES) come from
# /etc/default/pqcrypta-ech-rotate, read under systemd and over ssh alike.
#
# A node that fails keeps the configs DNS publishes for it, and the run exits
# non-zero after publishing the others.

set -euo pipefail

# shellcheck source=/dev/null
[[ -r /etc/default/pqcrypta-ech-rotate ]] && . /etc/default/pqcrypta-ech-rotate

OUT_DIR="${ECH_CONFIG_DIR:-/etc/pqcrypta/ech-configs}"
BIN="${ECH_KEYGEN_BIN:-/usr/local/bin/pqcrypta-ech-keygen}"
PUBLISH="${ECH_PUBLISH_BIN:-/usr/local/bin/pqcrypta-ech-publish}"
CHECK="${ECH_CHECK_BIN:-/usr/local/bin/pqcrypta-ech-check}"
# A name this proxy serves with this list, and where it listens (TCP and UDP)
CHECK_NAME="${ECH_CHECK_NAME:-pqcrypta.com}"
CHECK_ADDR="${ECH_CHECK_ADDR:-127.0.0.1:443}"
PROXY_CONFIG="${PROXY_CONFIG:-/etc/pqcrypta/proxy-config.toml}"
# "no" on a node the signer's host rotates: stop once the configs are checked
PUBLISH_HERE="${ECH_PUBLISH:-yes}"
# The nodes rotated from here, NODE=NAME: an ssh host, and a name it serves
# with its key ("api3=philibertsecurity.com")
REMOTE_NODES="${ECH_REMOTE_NODES:-}"
RECORDS_CONF="${ECH_RECORDS_CONF:-/etc/knot-signer/ech/https-records.conf}"
LOG_FILE="${LOG_FILE:-/var/log/pqcrypta/ech-rotate.log}"
# The configs' public_name, ECH's cover name: what a client sends in clear while
# the real name travels encrypted, and the name whose certificate it checks a
# rejection against before it retries (RFC 9849 6.1.6-6.1.7). A name of its
# own, so the outer ClientHello names no site; it has its records and
# certificate on web1 (pqcrypta-configs: dns/zones, [acme] domains). Another
# node names itself (api3.pqcrypta.com), which says no more than its address.
PUBLIC_NAME="${ECH_PUBLIC_NAME:-ech.pqcrypta.com}"

log() { echo "$(date -u '+%Y-%m-%dT%H:%M:%SZ') $*" | tee -a "$LOG_FILE"; }

mkdir -p "$OUT_DIR" "$(dirname "$LOG_FILE")"

tools=("$BIN" "$CHECK")
[[ "$PUBLISH_HERE" == "no" ]] || tools+=("$PUBLISH")
for tool in "${tools[@]}"; do
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
    log "Proxy reloaded its TLS material"
else
    log "Admin API off: waiting ${poll_secs}s for the proxy's reload poller"
    sleep "$((poll_secs + 10))"
fi

log "Offering each new config to the proxy over TCP and QUIC ($CHECK_NAME at $CHECK_ADDR)"
if ! "$CHECK" "$CHECK_NAME" --addr "$CHECK_ADDR" --list "$OUT_DIR/ech-config-list.bin" 2>&1 | tee -a "$LOG_FILE"; then
    log "ERROR: the proxy refused a new ECH config; not publishing (DNS keeps the configs it has, which the proxy still holds)"
    exit 1
fi

if [[ "$PUBLISH_HERE" == "no" ]]; then
    log "Rotated and checked; the DNS signer's host collects the list and publishes it"
    exit 0
fi

# The other nodes. Each one's list replaces the copy https-records.conf names
# for it only once every config opened from here.
remote_failed=0
for entry in $REMOTE_NODES; do
    node=${entry%%=*}
    name=${entry#*=}
    key_file=$(awk -v n="$node" '$1 == "key" && $2 == n { print $3 }' "$RECORDS_CONF")
    if [[ -z "$key_file" || "$name" == "$entry" ]]; then
        log "ERROR: $entry: no key line for $node in $RECORDS_CONF, or no name to check"
        remote_failed=1
        continue
    fi
    log "Rotating $node's ECH configs"
    # The name goes through as an argument to printf %q, never as shell text
    if ! ssh -o BatchMode=yes -o ConnectTimeout=15 "$node" \
        "ECH_PUBLISH=no ECH_CHECK_NAME=$(printf %q "$name") /usr/local/bin/pqcrypta-ech-rotate" 2>&1 | tee -a "$LOG_FILE"; then
        log "ERROR: $node's rotation failed; DNS keeps the configs it has for $node"
        remote_failed=1
        continue
    fi
    list=$(mktemp)
    addr=$(getent ahostsv4 "$name" | awk 'NR == 1 { print $1 }')
    if ssh -o BatchMode=yes -o ConnectTimeout=15 "$node" cat /etc/pqcrypta/ech-configs/ech-config-list.bin > "$list" \
        && [[ -n "$addr" ]] \
        && "$CHECK" "$name" --addr "$addr:443" --list "$list" 2>&1 | tee -a "$LOG_FILE"; then
        base64 -w0 "$list" > "$key_file.new"
        chmod --reference="$key_file" "$key_file.new"
        chown --reference="$key_file" "$key_file.new"
        mv "$key_file.new" "$key_file"
        log "$node's new configs open from here; publishing them"
    else
        log "ERROR: $node's new configs did not all open from here ($name at ${addr:-no address}); DNS keeps the configs it has for $node"
        remote_failed=1
    fi
    rm -f "$list"
done

log "Publishing the new ECHConfigLists in DNS"
"$PUBLISH" 2>&1 | tee -a "$LOG_FILE"
if ((remote_failed)); then
    log "ECH rotation complete here; a node above kept its configs"
    exit 1
fi
log "ECH rotation complete"

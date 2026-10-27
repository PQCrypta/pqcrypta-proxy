#!/usr/bin/env bash
# delegated-credential-cert.sh — The certificate this proxy delegates from
# (RFC 9345), for a host that serves delegated credentials to test against.
#
# The proxy mints delegated credentials only under a certificate with the
# DelegationUsage extension (1.3.6.1.4.1.44363.44) and the digitalSignature
# key usage (src/tls.rs, `delegation_validity`); clients refuse them under any
# other. No public CA issues that extension, so this issues the certificate
# from a private CA kept in CA_DIR, for DC_NAME, into the certificates
# directory the SNI resolver reads, and has the proxy reload it. The proxy
# then mints the credentials itself (ML-DSA-87, ML-DSA-65 and ECDSA P-256,
# each valid for a day and replaced every six hours) with delegated keys that
# never touch disk, and serves them to a client that offers the
# delegated_credential extension over QUIC.
#
# Renews the certificate when fewer than DC_RENEW_DAYS days of it remain, or
# when it was issued by another CA; otherwise changes nothing. Run by
# delegated-credential-cert.timer.
#
# Setup:
#   1. cp delegated-credential-cert.sh /usr/local/bin/pqcrypta-delegated-credential-cert
#   2. chmod +x /usr/local/bin/pqcrypta-delegated-credential-cert
#   3. cp delegated-credential-cert.service delegated-credential-cert.timer /etc/systemd/system/
#   4. systemctl enable --now delegated-credential-cert.timer
#
# DC_NAME must resolve to this host; delegated-credential.conformance.pqcrypta.com
# does through the conformance wildcard.

set -euo pipefail

DC_NAME=${DC_NAME:-delegated-credential.conformance.pqcrypta.com}
PROXY_CONFIG=${PROXY_CONFIG:-/etc/pqcrypta/proxy-config.toml}
CA_DIR=${CA_DIR:-/etc/pqcrypta/delegation-ca}
DC_LEAF_DAYS=${DC_LEAF_DAYS:-90}
DC_RENEW_DAYS=${DC_RENEW_DAYS:-30}
CA_DAYS=${CA_DAYS:-1825}
OPENSSL=${OPENSSL:-openssl}

log() { echo "$(date -u +%FT%TZ) delegated-credential-cert: $*"; }

# The directory the SNI resolver reads: that of [tls] cert_path.
CERTS_DIR=$(python3 -I - "$PROXY_CONFIG" <<'EOF'
import os, sys, tomllib
print(os.path.dirname(tomllib.load(open(sys.argv[1], 'rb'))['tls']['cert_path']))
EOF
)
CERT="$CERTS_DIR/$DC_NAME.crt"
KEY="$CERTS_DIR/$DC_NAME.key"

umask 077
install -d -m 700 "$CA_DIR"

# The private CA: ECDSA P-384, signing nothing but this certificate.
if [[ ! -s "$CA_DIR/ca.key" || ! -s "$CA_DIR/ca.crt" ]] \
    || ! "$OPENSSL" x509 -checkend $((DC_LEAF_DAYS * 86400)) -noout -in "$CA_DIR/ca.crt" >/dev/null; then
    log "Creating the delegation CA in $CA_DIR"
    "$OPENSSL" genpkey -algorithm EC -pkeyopt ec_paramgen_curve:P-384 -out "$CA_DIR/ca.key.new"
    "$OPENSSL" req -x509 -new -key "$CA_DIR/ca.key.new" -sha384 -days "$CA_DAYS" \
        -subj "/O=PQ Crypta/CN=PQ Crypta Delegated Credentials Test CA" \
        -addext "basicConstraints=critical,CA:TRUE,pathlen:0" \
        -addext "keyUsage=critical,keyCertSign,cRLSign" \
        -addext "subjectKeyIdentifier=hash" \
        -out "$CA_DIR/ca.crt.new"
    mv "$CA_DIR/ca.key.new" "$CA_DIR/ca.key"
    mv "$CA_DIR/ca.crt.new" "$CA_DIR/ca.crt"
fi

if [[ -s "$CERT" && -s "$KEY" ]] \
    && "$OPENSSL" x509 -checkend $((DC_RENEW_DAYS * 86400)) -noout -in "$CERT" >/dev/null \
    && "$OPENSSL" verify -CAfile "$CA_DIR/ca.crt" "$CERT" >/dev/null 2>&1; then
    log "$CERT is valid until $("$OPENSSL" x509 -enddate -noout -in "$CERT" | cut -d= -f2); nothing to do"
    exit 0
fi

log "Issuing $DC_NAME, valid for $DC_LEAF_DAYS days"
work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT
cat >"$work/ext.cnf" <<EOF
basicConstraints = critical, CA:FALSE
keyUsage = critical, digitalSignature
extendedKeyUsage = serverAuth
subjectAltName = DNS:$DC_NAME
subjectKeyIdentifier = hash
authorityKeyIdentifier = keyid
# DelegationUsage ::= NULL (RFC 9345 section 4.2)
1.3.6.1.4.1.44363.44 = DER:05:00
EOF
"$OPENSSL" genpkey -algorithm EC -pkeyopt ec_paramgen_curve:P-256 -out "$work/leaf.key"
"$OPENSSL" req -new -key "$work/leaf.key" -subj "/CN=$DC_NAME" -out "$work/leaf.csr"
"$OPENSSL" x509 -req -in "$work/leaf.csr" -CA "$CA_DIR/ca.crt" -CAkey "$CA_DIR/ca.key" \
    -CAcreateserial -sha384 -days "$DC_LEAF_DAYS" -extfile "$work/ext.cnf" -out "$work/leaf.crt"
cat "$work/leaf.crt" "$CA_DIR/ca.crt" >"$work/chain.crt"

# The key before the certificate: the resolver loads a domain by its .crt.
install -m 600 "$work/leaf.key" "$KEY.new"
install -m 644 "$work/chain.crt" "$CERT.new"
mv "$KEY.new" "$KEY"
mv "$CERT.new" "$CERT"
log "Wrote $CERT and $KEY"

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
    log "Admin API off: the proxy's reload poller takes the certificate within ${poll_secs}s"
fi

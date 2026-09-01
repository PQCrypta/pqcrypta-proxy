#!/bin/bash
# ============================================================================
# Build-and-deploy pqcrypta-proxy to all four proxy nodes, correctly.
#
# WHY THIS EXISTS: `cargo test` and `cargo clippy --release` do NOT build the
# release *binary*. Deploying with `cp target/release/pqcrypta-proxy` after only
# those commands ships a STALE binary — a real bug that once cost a debugging
# session chasing "live disagrees with the unit test". This script always builds
# the binary first, records its hash, and verifies each node is running THAT
# hash after restart. There is no path here that copies an unbuilt binary.
#
# Nodes (see the proxy-deploy memory): local web1, remotellm, api3, mail host.
#
# Usage:
#   scripts/deploy.sh                # build + deploy all four + verify
#   scripts/deploy.sh --local-only   # build + deploy this node only
#   scripts/deploy.sh --no-build     # deploy the existing binary (must exist)
#   scripts/deploy.sh --gate         # after deploy, run the post-deploy WAF gate
# ============================================================================
set -uo pipefail
cd "$(dirname "${BASH_SOURCE[0]}")/.."

BIN=target/release/pqcrypta-proxy
LOCAL_ONLY=0; NO_BUILD=0; GATE=0
for a in "$@"; do case "$a" in
  --local-only) LOCAL_ONLY=1 ;;
  --no-build)   NO_BUILD=1 ;;
  --gate)       GATE=1 ;;
  *) echo "unknown flag: $a" >&2; exit 2 ;;
esac; done

log() { printf '\n\033[1m==> %s\033[0m\n' "$*"; }
die() { printf '\n\033[31mDEPLOY FAILED: %s\033[0m\n' "$*" >&2; exit 1; }

# --- 1. Build (always, unless explicitly skipped) --------------------------
if [ "$NO_BUILD" -eq 0 ]; then
  log "cargo build --release --bin pqcrypta-proxy"
  cargo build --release --bin pqcrypta-proxy || die "build failed"
else
  log "skipping build (--no-build); using existing $BIN"
fi
[ -x "$BIN" ] || die "$BIN missing or not executable — cannot deploy"
WANT=$(sha256sum "$BIN" | cut -d' ' -f1)
log "binary sha256: $WANT"

# --- helpers ----------------------------------------------------------------
# Verify a node's live binary matches, and the service is active.
verify_remote() { # name  ssh-cmd
  local name="$1"; shift
  local active want_rc
  active=$($@ "systemctl is-active pqcrypta-proxy" 2>/dev/null)
  local got
  got=$($@ "sha256sum /usr/local/bin/pqcrypta-proxy 2>/dev/null | cut -d' ' -f1")
  if [ "$active" = active ] && [ "$got" = "$WANT" ]; then
    echo "  [OK]   $name active, hash matches"
  else
    die "$name mismatch — active=$active hash=${got:0:12} want=${WANT:0:12}"
  fi
}

deploy_local() {
  log "local (web1)"
  systemctl stop pqcrypta-proxy
  cp "$BIN" /usr/local/bin/pqcrypta-proxy
  systemctl start pqcrypta-proxy
  sleep 8
  local active got
  active=$(systemctl is-active pqcrypta-proxy)
  got=$(sha256sum /usr/local/bin/pqcrypta-proxy | cut -d' ' -f1)
  [ "$active" = active ] && [ "$got" = "$WANT" ] \
    && echo "  [OK]   local active, hash matches" \
    || die "local mismatch — active=$active hash=${got:0:12}"
}

deploy_remote_mv() { # name  scpdest  ssh-cmd...   (busy-binary safe: .new then mv)
  local name="$1" dest="$2"; shift 2
  log "$name"
  # $@ is the ssh command; derive scp from it is fragile, so callers pass both.
  "${SSH[@]}" "systemctl stop pqcrypta-proxy" || true
  "${SCP[@]}" "$BIN" "$dest:/usr/local/bin/pqcrypta-proxy.new" || die "$name scp failed"
  "${SSH[@]}" "mv /usr/local/bin/pqcrypta-proxy.new /usr/local/bin/pqcrypta-proxy \
    && chmod +x /usr/local/bin/pqcrypta-proxy && systemctl start pqcrypta-proxy" || die "$name start failed"
  # mail host is slow to bind (ACME); poll
  local i active
  for i in $(seq 1 12); do
    active=$("${SSH[@]}" "systemctl is-active pqcrypta-proxy" 2>/dev/null || true)
    [ "$active" = active ] && break; sleep 6
  done
  local got
  got=$("${SSH[@]}" "sha256sum /usr/local/bin/pqcrypta-proxy 2>/dev/null | cut -d' ' -f1")
  [ "$active" = active ] && [ "$got" = "$WANT" ] \
    && echo "  [OK]   $name active, hash matches" \
    || die "$name mismatch — active=$active hash=${got:0:12} want=${WANT:0:12}"
}

# --- 2. Deploy --------------------------------------------------------------
deploy_local
if [ "$LOCAL_ONLY" -eq 0 ]; then
  # remotellm (WireGuard 10.10.0.2, plain key)
  SSH=(ssh -p 22 root@10.10.0.2); SCP=(scp -P 22 -C)
  deploy_remote_mv "remotellm" "root@10.10.0.2"
  # api3 (pentest key, slow link → -C)
  SSH=(ssh -i /root/.ssh/pentest_sync_rsa -p 22 root@74.208.108.89); SCP=(scp -C -i /root/.ssh/pentest_sync_rsa -P 22)
  deploy_remote_mv "api3" "root@74.208.108.89"
  # mail host (core.fated.org)
  SSH=(ssh -o Port=22 mail); SCP=(scp -C -o Port=22)
  deploy_remote_mv "mail" "mail"
fi

log "all target nodes on $WANT"

# --- 3. Optional post-deploy WAF regression gate ----------------------------
if [ "$GATE" -eq 1 ]; then
  log "post-deploy WAF regression gate"
  bash pentests/regression/postdeploy_gate.sh || die "post-deploy gate failed — investigate before trusting this deploy"
fi

log "DEPLOY OK"

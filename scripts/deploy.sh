#!/bin/bash
# Install a pqcrypta-proxy binary on one or more nodes, one at a time.
#
# Usage:
#   scripts/deploy.sh [--gate] BINARY NODE...
#
#   BINARY  a release build (`cargo build --release --bin pqcrypta-proxy`, on a
#           build host whose glibc is no newer than the oldest node's); this
#           script builds nothing
#   NODE    `local`, or an ssh destination (a host alias, user@host)
#   --gate  run pentests/regression/postdeploy_gate.sh once every node is done
#
# Environment: PQCRYPTA_CONFIG (default /etc/pqcrypta/proxy-config.toml) and
# PQCRYPTA_USER (default pqcrypta), the service's configuration and account on
# every node.
#
# On each node, in turn: the binary is copied beside the live one and run with
# `--validate` as the service account against that node's configuration, which
# loads it and runs the startup security checks as a real start would, so a
# binary that would not start never replaces one that does; the live binary is
# kept as `.prev-<UTC time>`; the new one is installed and the service
# restarted; and the node must be active and running this binary's version
# within 90 s, or the previous binary is put back. The first node that fails
# stops the run. With the socket unit (`pqcrypta-proxy --socket-unit`) the
# restart refuses no connection.
set -euo pipefail

GATE=0
if [ "${1:-}" = --gate ]; then
    GATE=1
    shift
fi
BIN=${1:?usage: scripts/deploy.sh [--gate] BINARY NODE...}
shift
[ $# -gt 0 ] || { echo "usage: scripts/deploy.sh [--gate] BINARY NODE..." >&2; exit 2; }
[ -x "$BIN" ] || { echo "$BIN is not an executable" >&2; exit 2; }
CONFIG=${PQCRYPTA_CONFIG:-/etc/pqcrypta/proxy-config.toml}
RUN_AS=${PQCRYPTA_USER:-pqcrypta}
VERSION=$("$BIN" --version)
case "$VERSION" in
*"measurement build"*)
    echo "$BIN is a measurement build ($VERSION): not deployed" >&2
    exit 2
    ;;
esac
STAMP=$(date -u +%Y%m%dT%H%M%SZ)
echo "Installing $VERSION from $BIN"

# What runs on each node: $1 the staged binary, $2 the configuration, $3 the
# service account, $4 the version expected, $5 the backup suffix
read -r -d '' STEP <<'EOF' || true
set -eu
new=$1 config=$2 run_as=$3 want=$4 stamp=$5
live=/usr/local/bin/pqcrypta-proxy
if ! runuser -u "$run_as" -- "$new" --config "$config" --validate >/tmp/pqcrypta-proxy-validate.log 2>&1; then
    echo "  validation failed:"; tail -5 /tmp/pqcrypta-proxy-validate.log; rm -f "$new"; exit 3
fi
cp -p "$live" "$live.prev-$stamp"
install -m 0755 "$new" "$live" && rm -f "$new"
systemctl restart pqcrypta-proxy
for _ in $(seq 1 45); do
    if systemctl is-active -q pqcrypta-proxy && [ "$("$live" --version)" = "$want" ]; then
        sleep 3
        if systemctl is-active -q pqcrypta-proxy; then
            echo "  active: $want (previous kept as $live.prev-$stamp)"; exit 0
        fi
    fi
    sleep 2
done
echo "  not active with $want: putting $live.prev-$stamp back"
install -m 0755 "$live.prev-$stamp" "$live"
systemctl restart pqcrypta-proxy
exit 4
EOF

for node in "$@"; do
    echo "== $node"
    staged=/usr/local/bin/pqcrypta-proxy.new
    if [ "$node" = local ]; then
        install -m 0755 "$BIN" "$staged"
        bash -c "$STEP" step "$staged" "$CONFIG" "$RUN_AS" "$VERSION" "$STAMP"
    else
        scp -q "$BIN" "$node:$staged"
        # The step on the node's shell's standard input, its arguments quoted
        # for that shell
        args=$(printf '%q ' "$staged" "$CONFIG" "$RUN_AS" "$VERSION" "$STAMP")
        remote="bash -s -- $args"
        ssh "$node" "$remote" <<<"$STEP"
    fi
done

if [ "$GATE" -eq 1 ]; then
    "$(dirname "$0")/../pentests/regression/postdeploy_gate.sh"
fi

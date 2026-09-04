#!/usr/bin/env bash
# Interleave two binaries A/B/A/B rather than running all of A then all of B.
# Run-to-run spread within a single cell reached 102% here, so a block design
# would attribute drift to whichever binary happened to run during a quiet
# patch. Alternating and taking medians is the only way these are comparable.
set -uo pipefail

# Shared guards — see benchlib.sh. Each exists because its absence produced a
# confident wrong number that was believed for a while.
# shellcheck source=/root/bench/benchlib.sh
. /root/bench/benchlib.sh
# Orchestrator only: bench-routes.sh takes the lock per invocation, so taking
# it here as well would deadlock every child. Just raise the fd limit.
bench_require_fds
A=$1; B=$2; N=${3:-6}
for i in $(seq "$N"); do
  BIN="$A" ./bench-routes.sh 2>/dev/null | tail -3 | awk -v t="A" "{print t, \$3}"
  BIN="$B" ./bench-routes.sh 2>/dev/null | tail -3 | awk -v t="B" "{print t, \$3}"
done

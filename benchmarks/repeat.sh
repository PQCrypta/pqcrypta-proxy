#!/usr/bin/env bash
# Interleave two binaries rather than running all of A then all of B.
# Run-to-run spread within a single cell reached 102% here, so a block design
# would attribute drift to whichever binary happened to run during a quiet
# patch. Alternating and taking medians is the only way these are comparable.
#
# COUNTERBALANCED ORDER (ABBA), not plain A-then-B every round.
#
# Alternating rounds is not enough on its own: if every round runs A first and
# B second, the *slot* is confounded with the binary and any systematic cost of
# running second lands entirely on B. That cost is real and it is large here —
# a null test (the identical binary in both slots, 6 rounds) measured the second
# slot 3.7% slower. Against a genuine difference of ~1% that artefact dominates,
# and a naive A-then-B run reported a 5% "regression" at z = -2.41 that
# disappeared the moment position was held constant.
#
# So round parity flips the order: odd rounds run A then B, even rounds run B
# then A. Each binary then spends half its reps in each slot and the position
# effect cancels in the median instead of being charged to one side.
#
# When you need the residual anyway, run a null test (same binary twice) to
# size the slot effect, and compare binaries *within* a slot.
set -uo pipefail

# Shared guards — see benchlib.sh. Each exists because its absence produced a
# confident wrong number that was believed for a while.
# shellcheck source=/root/bench/benchlib.sh
. /root/bench/benchlib.sh
# Orchestrator only: bench-routes.sh takes the lock per invocation, so taking
# it here as well would deadlock every child. Just raise the fd limit.
bench_require_fds
A=$1; B=$2; N=${3:-6}

cell() {  # cell <binary> <label>
  BIN="$1" ./bench-routes.sh 2>/dev/null | tail -3 | awk -v t="$2" "{print t, \$3}"
}

for i in $(seq "$N"); do
  if [ $((i % 2)) -eq 1 ]; then
    cell "$A" A
    cell "$B" B
  else
    cell "$B" B
    cell "$A" A
  fi
done

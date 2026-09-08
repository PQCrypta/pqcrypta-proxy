#!/usr/bin/env bash
# The published matrix, re-measured on the long window.
#
# 60s cells with a 15s warm-up instead of 10s/2s: coefficient of variation within
# an unchanged cell goes from ~14% to ~5-8% for us and from ~7% to 1.4% for
# HAProxy, because the short window was measuring a transient rather than steady
# state. It also appears to understate us at 64 KB.
#
# The cost is time: 108 measurements per pass at 75s each is ~2.5 hours, so two
# passes plus a backend ceiling is most of a working day. That is the price of a
# table whose third digit means something.
set -uo pipefail
cd /root/bench
OUT=/root/bench/out
STAMP=$(date +%Y%m%d_%H%M%S)
RES="$OUT/res-60s-$STAMP"
mkdir -p "$RES"
echo "results -> $RES"

./ressample.py "$RES/resources.csv" 2 &
SAMPLER=$!
trap 'kill $SAMPLER 2>/dev/null' EXIT

# One rep is enough here: this is a guard on the backend, not a published figure.
echo "########## backend ceiling  $(date -Is)"
RESULTS="$RES/backend-ceiling.csv" REPS=1 ./bench-backend.sh 2>&1

for run in 1 2; do
  echo "########## full matrix run $run  $(date -Is)"
  RESULTS="$RES/results-run$run.csv" REPS=3 ./run-bench.sh 2>&1
done

echo "########## done $(date -Is)  -> $RES"

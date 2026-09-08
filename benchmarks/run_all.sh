#!/usr/bin/env bash
# The whole published suite, in one pass, on the corrected layout.
#
# Order matters: the backend ceiling is measured first, because every number
# after it is only meaningful if the backend is not the thing being measured.
set -uo pipefail
cd /root/bench
OUT=/root/bench/out
STAMP=$(date +%Y%m%d_%H%M%S)
RES="$OUT/res-$STAMP"
mkdir -p "$RES"
echo "results -> $RES"

# Both proxies and the generator sampled in the same tick. Server CPU alone is
# meaningless: an idle-looking server under load is a claim about the client
# until proven otherwise, and a proxy reading ABOVE its own budget is how the
# cpu-map override was caught.
./ressample.py "$RES/resources.csv" 2 &
SAMPLER=$!
trap 'kill $SAMPLER 2>/dev/null' EXIT

echo "########## backend ceiling  $(date -Is)"
RESULTS="$RES/backend-ceiling.csv" REPS=3 ./bench-backend.sh 2>&1

for run in 1 2; do
  echo "########## full matrix run $run  $(date -Is)"
  RESULTS="$RES/results-run$run.csv" REPS=3 ./run-bench.sh 2>&1
done

for run in 1 2; do
  echo "########## as-deployed run $run  $(date -Is)"
  RESULTS="$RES/results-depl$run.csv" REPS=3 ./run-pqc-only.sh 2>&1
done

echo "########## security arms  $(date -Is)"
RESULTS_DIR="$RES" REPS=3 ./run-sec.sh 2>&1

echo "########## handshake  $(date -Is)"
RESULTS="$RES/handshake.csv" CONNS=200 REPS=3 ./bench-handshake2.sh 2>&1

echo "########## done $(date -Is)  -> $RES"

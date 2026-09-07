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
REPS=3 DUR=10 ./bench-backend.sh 2>&1
cp "$OUT/backend-ceiling.csv" "$RES/" 2>/dev/null

for run in 1 2; do
  echo "########## full matrix run $run  $(date -Is)"
  REPS=3 DUR=10 ./run-bench.sh 2>&1
  cp "$OUT/results.csv" "$RES/results-run$run.csv"
done

for run in 1 2; do
  echo "########## as-deployed run $run  $(date -Is)"
  REPS=3 DUR=10 ./run-pqc-only.sh 2>&1
  cp "$OUT/results-pqc2.csv" "$RES/results-depl$run.csv"
done

echo "########## security arms  $(date -Is)"
REPS=3 DUR=10 ./run-sec.sh 2>&1
cp "$OUT/results-sec-off.csv" "$OUT/results-sec-on.csv" "$RES/" 2>/dev/null

echo "########## handshake  $(date -Is)"
CONNS=200 REPS=3 ./bench-handshake2.sh 2>&1
cp "$OUT/handshake/results.csv" "$RES/handshake.csv" 2>/dev/null

echo "########## done $(date -Is)  -> $RES"

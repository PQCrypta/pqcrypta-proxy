#!/usr/bin/env bash
# Every benchmark /proxy-comparison/ quotes, on the build now deployed.
set -uo pipefail
cd /root/bench
export NOW_BIN=/root/bench/pqc-93256d06
STAMP=$(date +%Y%m%d_%H%M%S)
matrix() {  # $1=name $2=arms $3=reps [$4=ceiling]
  local RES=/root/bench/out/$1-$STAMP
  mkdir -p "$RES"
  {
    echo "results -> $RES  $(date -Is)"
    ./ressample-lean.py "$RES/resources2.csv" 2 &
    local SAMPLER=$!
    if [ "${4:-}" = ceiling ]; then
      echo "########## backend ceiling  $(date -Is)"
      RESULTS="$RES/backend-ceiling.csv" REPS=1 ./bench-backend.sh 2>&1
    fi
    ARMS="$2" RUN_TAG="$1-" RESULTS="$RES/matrix.csv" REPS="$3" ./run-lean.sh 2>&1
    local rc=$?
    kill $SAMPLER 2>/dev/null
    echo "########## done $(date -Is)  exit=$rc"
  } > "$RES/run.log" 2>&1
}
matrix cmp3 "haproxy lean-now pqc-full" 6 ceiling
matrix feat2 "plumb feat" 4
matrix sec2 "sec-off sec-on" 4
BIN=$NOW_BIN RES=/root/bench/out/handshake-$STAMP ./run-handshake.sh
BIN=$NOW_BIN ./nd-ab.sh > /root/bench/out/nd-ab-$STAMP.log 2>&1
BIN=$NOW_BIN RES=/root/bench/out/window-$STAMP ./window-study.sh
echo "########## all done $(date -Is)" > /root/bench/out/current-$STAMP.done
# The consistency section: where the run-to-run spread comes from, re-asked on
# the current build.
for s in spread-confirm cycles stalls steal smt; do
  BIN=$NOW_BIN ./$s.sh > /root/bench/out/$s-$STAMP.log 2>&1
done
echo "########## consistency done $(date -Is)" >> /root/bench/out/current-$STAMP.done

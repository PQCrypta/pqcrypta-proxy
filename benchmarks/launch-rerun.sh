#!/usr/bin/env bash
# Every published figure that fetches a 64 KB body, re-measured after the
# backend fix (conf/nginx.conf: sendfile off, nginx's default -- sendfile with
# tcp_nopush held one 64 KB response in three hundred for 40 ms, on both
# proxies), on the build now deployed. Each run is packaged for publication as
# it finishes, into out/publish-$STAMP/<run>/, and out/publish-$STAMP.done
# lists what finished.
set -uo pipefail
cd /root/bench
export NOW_BIN=/root/bench/pqc-fa8556d2
COMMIT=6d75ab9
STAMP=$(date +%Y%m%d_%H%M%S)
PUB=/root/bench/out/publish-$STAMP
mkdir -p "$PUB"
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
  grep -q "exit=0" "$RES/run.log"
}
publish() { echo "$1 $(date -Is)" >> "$PUB.done"; }

if matrix cmp4 "haproxy lean-now pqc-full" 6 ceiling; then
  BINARY=$NOW_BIN FULL_ARM=pqc-full FULL_CONFIG=pqc-bench-full.toml \
    python3 export-bench.py out/cmp4-$STAMP cmp4- "$PUB/cmp4-$STAMP" lean-now $COMMIT >/dev/null && publish cmp4-$STAMP
fi
if matrix feat3 "plumb feat" 4; then
  BINARY=$NOW_BIN BASE=plumb CONFS=pqc-bench.toml,pqc-bench-features.toml,nginx.conf \
    python3 export-bench.py out/feat3-$STAMP feat3- "$PUB/feat3-$STAMP" feat $COMMIT >/dev/null && publish feat3-$STAMP
fi
if matrix sec3 "sec-off sec-on" 4; then
  BINARY=$NOW_BIN BASE=sec-off CONFS=pqc-sec-off.toml,pqc-sec-on.toml,nginx.conf \
    python3 export-bench.py out/sec3-$STAMP sec3- "$PUB/sec3-$STAMP" sec-on $COMMIT >/dev/null && publish sec3-$STAMP
fi
BIN=$NOW_BIN OUT=/root/bench/out/nd-ab-$STAMP.csv ./nd-ab.sh > /root/bench/out/nd-ab-$STAMP.log 2>&1
BIN=$NOW_BIN OUT=/root/bench/out/nd-h1-dist-$STAMP.txt ./nd-h1-dist.sh >/dev/null 2>&1
if grep -q "^########## done" /root/bench/out/nd-ab-$STAMP.log; then
  BINARY=$NOW_BIN DIST=/root/bench/out/nd-h1-dist-$STAMP.txt \
    python3 export-study.py nagle out/nd-ab-$STAMP.csv "$PUB/nagle-$STAMP" $COMMIT >/dev/null && publish nagle-$STAMP
fi
echo "all $(date -Is)" >> "$PUB.done"

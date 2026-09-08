#!/usr/bin/env bash
# Is the spread a steady-state problem?
#
# The values look bimodal — a cluster near 18k with jumps to 24k — which is the
# shape of something settling into one of two states rather than continuous
# noise. If a longer warm-up and a longer measurement collapse the coefficient of
# variation, the rig was simply measuring the transient.
set -uo pipefail
. /root/bench/benchlib.sh
bench_guard_init
export LD_LIBRARY_PATH=/opt/h3bench/lib
H2LOAD=/opt/h3bench/bin/h2load
BODY=${BODY:-64k}
N=${N:-6}

arm() {  # $1=duration $2=warmup
  bench_stop_proxies
  bench_spawn_proxy /root/bench/pqcrypta-proxy /root/bench/conf/pqc-bench.toml
  local vals=()
  for i in $(seq "$N"); do
    vals+=("$(taskset -c "$BENCH_GEN_CPUS" timeout $(( $1 + $2 + 40 )) "$H2LOAD" --h1 \
      -c 10 -m 1 -t 6 --duration="$1" --warm-up-time="$2" \
      "https://bench.local:18444/$BODY" 2>/dev/null | awk '/^finished in/ {print $4}')")
  done
  bench_stop_proxies
  python3 -c "
import sys, statistics
v=[float(x) for x in sys.argv[1:] if x]
if len(v)<2: print('  dur=$1 wu=$2: insufficient'); raise SystemExit
print('  dur=%-3s wu=%-3s  median %9.0f  min %9.0f  max %9.0f  spread %.2fx  cv %.1f%%'
      % ('$1','$2', statistics.median(v), min(v), max(v), max(v)/min(v),
         100*statistics.stdev(v)/statistics.mean(v)))" "${vals[@]}"
}

arm 10 2
arm 30 10
arm 60 15

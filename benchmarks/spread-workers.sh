#!/usr/bin/env bash
# Is the spread tokio's work-stealing between the two SMT threads?
#
# Two workers on two hyperthreads of one physical core can migrate tasks between
# them; one worker cannot. HAProxy runs thread-per-core with no stealing on the
# identical cores and holds ~7% spread, so if one worker is stable and two are
# not, the scheduler is implicated rather than the hardware.
#
# Throughput will drop with one worker. That is not the point — the point is the
# coefficient of variation.
set -uo pipefail
. /root/bench/benchlib.sh
bench_guard_init
export LD_LIBRARY_PATH=/opt/h3bench/lib
H2LOAD=/opt/h3bench/bin/h2load
BODY=${BODY:-64k}
N=${N:-6}
DUR=${DUR:-10}

measure() {
  taskset -c "$BENCH_GEN_CPUS" timeout 60 "$H2LOAD" --h1 -c 10 -m 1 -t 6 \
    --duration="$DUR" --warm-up-time=2 "https://bench.local:18444/$BODY" 2>/dev/null \
  | awk '/^finished in/ {print $4}'
}

arm() {  # $1=workers $2=cpus
  sed -e "s/^worker_threads = .*/worker_threads = $1/" /root/bench/conf/pqc-bench.toml \
      > /root/bench/conf/pqc-w$1.toml
  bench_stop_proxies
  BENCH_PROXY_CPUS="$2" bench_spawn_proxy /root/bench/pqcrypta-proxy /root/bench/conf/pqc-w$1.toml
  local vals=()
  for i in $(seq "$N"); do vals+=("$(measure)"); done
  bench_stop_proxies
  python3 -c "
import sys, statistics
v=[float(x) for x in sys.argv[1:]]
print('  %-22s median %9.0f  min %9.0f  max %9.0f  spread %.2fx  cv %.1f%%'
      % ('$1 worker(s) on $2', statistics.median(v), min(v), max(v), max(v)/min(v),
         100*statistics.stdev(v)/statistics.mean(v)))" "${vals[@]}"
}

arm 2 4-5
arm 1 4-5
arm 1 4

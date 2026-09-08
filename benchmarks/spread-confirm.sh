#!/usr/bin/env bash
# Confirm the 60s/15s window, and measure HAProxy at the same settings.
#
# One arm at cv 4.9% could be luck. And a duration that stabilises us has to be
# checked against HAProxy too — a change that improves only our own numbers is
# not a fix to the harness, it is a thumb on the scale.
set -uo pipefail
. /root/bench/benchlib.sh
bench_guard_init
export LD_LIBRARY_PATH=/opt/h3bench/lib
H2LOAD=/opt/h3bench/bin/h2load
BODY=${BODY:-64k}
N=${N:-6}
DUR=${DUR:-60}
WU=${WU:-15}

measure() {  # $1=port
  taskset -c "$BENCH_GEN_CPUS" timeout $((DUR+WU+60)) "$H2LOAD" --h1 -c 10 -m 1 -t 6 \
    --duration="$DUR" --warm-up-time="$WU" "https://bench.local:$1/$BODY" 2>/dev/null \
  | awk '/^finished in/ {print $4}'
}

report() { python3 -c "
import sys, statistics
v=[float(x) for x in sys.argv[2:] if x]
print('  %-10s median %9.0f  min %9.0f  max %9.0f  spread %.2fx  cv %.1f%%'
      % (sys.argv[1], statistics.median(v), min(v), max(v), max(v)/min(v),
         100*statistics.stdev(v)/statistics.mean(v)))" "$@"; }

bench_stop_proxies
bench_spawn_proxy /root/bench/pqcrypta-proxy /root/bench/conf/pqc-bench.toml
p=(); for i in $(seq "$N"); do p+=("$(measure 18444)"); done
bench_stop_proxies
report pqcrypta "${p[@]}"

setsid taskset -c "$BENCH_PROXY_CPUS" haproxy -f /root/bench/conf/haproxy.cfg -db </dev/null >/dev/null 2>&1 9>&- &
sleep 6
h=(); for i in $(seq "$N"); do h+=("$(measure 18443)"); done
bench_stop_proxies
report haproxy "${h[@]}"

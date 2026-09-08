#!/usr/bin/env bash
# The single-in-flight-stream cell, both proxies, current build.
# This is the cell that read 385 req/s before the ACK fix.
set -uo pipefail
. /root/bench/benchlib.sh
bench_guard_init
export LD_LIBRARY_PATH=/opt/h3bench/lib
H2LOAD=/opt/h3bench/bin/h2load

cell() {  # $1=label $2=port $3=alpn
  local pid c0 c1 t0 t1 out
  pid=$(ss -lntupH 2>/dev/null | grep ":$2" | grep -oP 'pid=\K[0-9]+' | head -1)
  c0=$(awk '{print $14+$15}' "/proc/$pid/stat"); t0=$(date +%s.%N)
  out=$(taskset -c "$BENCH_GEN_CPUS" timeout 40 "$H2LOAD" $3 -c 10 -m 1 -t 6 \
        --duration=10 --warm-up-time="${WU:-$BENCH_WARMUP}" "https://bench.local:$2/1k" 2>/dev/null)
  t1=$(date +%s.%N); c1=$(awk '{print $14+$15}' "/proc/$pid/stat")
  echo "$out" | awk -v l="$1" -v a="$c0" -v b="$c1" -v s="$t0" -v e="$t1" '
    /^finished in/ { rps=$4 }
    /^time for request:/ { lat=$(NF-2) }
    END { printf "  %-28s %12s req/s  %10s   %5.0f%% of 200%%\n", l, rps, lat, (b-a)/100/(e-s)*100 }'
}

bench_stop_proxies
setsid taskset -c "$BENCH_PROXY_CPUS" haproxy -f /root/bench/conf/haproxy.cfg -db </dev/null >/dev/null 2>&1 9>&- &
sleep 5
cell "HAProxy, HTTP/3" 18443 --alpn-list=h3
cell "HAProxy, HTTP/2" 18443 --alpn-list=h2
cell "HAProxy, HTTP/1.1" 18443 --h1
bench_stop_proxies

bench_spawn_proxy /root/bench/pqcrypta-proxy /root/bench/conf/pqc-bench.toml
cell "PQ Crypta, HTTP/3" 18444 --alpn-list=h3
cell "PQ Crypta, HTTP/2" 18444 --alpn-list=h2
cell "PQ Crypta, HTTP/1.1" 18444 --h1
bench_stop_proxies

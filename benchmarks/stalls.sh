#!/usr/bin/env bash
# Same instructions, half the IPC. What is starving the pipeline?
#   dTLB-load-misses up  -> huge pages being split/compacted (khugepaged, THP)
#   LLC-load-misses up   -> cache being evicted by something outside our control
#   neither              -> execution-port contention, i.e. an SMT sibling we do
#                           not own, which on a VM means another tenant
set -uo pipefail
while fuser /run/lock/pqc-bench.lock >/dev/null 2>&1; do sleep 30; done
. /root/bench/benchlib.sh
bench_guard_init
export LD_LIBRARY_PATH=/opt/h3bench/lib
OUT=/root/bench/out/variance
bench_stop_proxies
bench_spawn_proxy "${BIN:-/root/bench/pqcrypta-proxy}" /root/bench/conf/pqc-bench.toml
taskset -c "$BENCH_GEN_CPUS" timeout 140 /opt/h3bench/bin/h2load --alpn-list=h2 \
    -c 10 -m 10 -t 6 --duration=120 --warm-up-time=5 \
    "https://bench.local:18444/1k" >/dev/null 2>&1 &
LOADPID=$!
sleep 8
perf stat -C 4,5 -e cycles,instructions,cache-misses,dTLB-load-misses,LLC-load-misses \
    -I 1000 -x, -o "$OUT/perf2.csv" sleep 100 &
PERFPID=$!
: > "$OUT/pkts2.csv"
last=$(cat /sys/class/net/lo/statistics/rx_packets)
for n in $(seq 100); do
  sleep 1; p=$(cat /sys/class/net/lo/statistics/rx_packets)
  echo "$n,$((p-last))" >> "$OUT/pkts2.csv"; last=$p
done
wait $PERFPID 2>/dev/null; kill $LOADPID 2>/dev/null; wait $LOADPID 2>/dev/null
bench_stop_proxies
echo "=== THP state ==="
cat /sys/kernel/mm/transparent_hugepage/enabled
grep -E "AnonHugePages|HugePages_" /proc/meminfo
echo DONE

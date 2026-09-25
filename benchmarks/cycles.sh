#!/usr/bin/env bash
# The decisive split. On the proxy's own CPUs, per second:
#   cycles/s falls in the slow mode          -> the CLOCK changed (host-side)
#   cycles/s flat, instructions/request up   -> WE are doing more work
#   cycles & instructions flat, IPC down     -> cache/memory contention
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
perf stat -C 4,5 -e cycles,instructions -I 1000 -x, -o "$OUT/perf.csv" sleep 100 &
PERFPID=$!
# packets in lockstep with perf's own 1s cadence
: > "$OUT/pkts.csv"
last=$(cat /sys/class/net/lo/statistics/rx_packets)
for n in $(seq 100); do
  sleep 1
  p=$(cat /sys/class/net/lo/statistics/rx_packets)
  echo "$n,$((p-last))" >> "$OUT/pkts.csv"; last=$p
done
wait $PERFPID 2>/dev/null
kill $LOADPID 2>/dev/null; wait $LOADPID 2>/dev/null
bench_stop_proxies
echo DONE

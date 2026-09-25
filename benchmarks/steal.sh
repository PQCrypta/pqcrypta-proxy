#!/usr/bin/env bash
# Is the run-to-run variance ours, or the hypervisor's?
#
# The box is a VM with no cpufreq sysfs. "Same guest CPU time, half the work" is
# what CPU steal and SMT contention from another tenant look like from inside a
# guest: the vCPU is scheduled, accrues time, but gets fewer physical cycles.
#
# Sample per-CPU steal alongside throughput, under load, on the proxy's own
# pinned CPUs.
set -uo pipefail
while fuser /run/lock/pqc-bench.lock >/dev/null 2>&1; do sleep 30; done
. /root/bench/benchlib.sh
bench_guard_init
export LD_LIBRARY_PATH=/opt/h3bench/lib
OUT=/root/bench/out/variance
mkdir -p "$OUT"

snap() { awk '/^cpu4 |^cpu5 /{u+=$2;s+=$4;i+=$5;st+=$9} END{print u,s,i,st}' /proc/stat; }

bench_stop_proxies
bench_spawn_proxy "${BIN:-/root/bench/pqcrypta-proxy}" /root/bench/conf/pqc-bench.toml
taskset -c "$BENCH_GEN_CPUS" timeout 130 /opt/h3bench/bin/h2load --alpn-list=h2 \
    -c 10 -m 10 -t 6 --duration=120 --warm-up-time=5 \
    "https://bench.local:18444/1k" >/dev/null 2>&1 &
LOADPID=$!
sleep 8

echo "sec,pkts_per_s,busy_ticks,steal_ticks,idle_ticks" > "$OUT/steal.csv"
lastp=$(cat /sys/class/net/lo/statistics/rx_packets)
read -r u0 s0 i0 st0 < <(snap)
for n in $(seq 100); do
  sleep 1
  p=$(cat /sys/class/net/lo/statistics/rx_packets)
  read -r u s i st < <(snap)
  echo "$n,$((p-lastp)),$(( (u-u0)+(s-s0) )),$((st-st0)),$((i-i0))" >> "$OUT/steal.csv"
  lastp=$p; u0=$u; s0=$s; i0=$i; st0=$st
done
kill $LOADPID 2>/dev/null; wait $LOADPID 2>/dev/null
bench_stop_proxies
echo DONE

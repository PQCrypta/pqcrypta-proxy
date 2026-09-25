#!/usr/bin/env bash
# Where the HTTP/1.1 Nagle stall comes from: the per-request time distribution
# (min, max, mean, sd) with tcp_nodelay off, which the nd-ab CSV reduces to a mean.
set -uo pipefail
. /root/bench/benchlib.sh
bench_guard_init
export LD_LIBRARY_PATH=/opt/h3bench/lib
BIN=${BIN:-/root/bench/pqc-93256d06}
OUT=${OUT:-/root/bench/out/nd-h1-dist-$(date +%Y%m%d_%H%M%S).txt}
exec > >(tee "$OUT") 2>&1
for cfg in off on; do
  bench_stop_proxies
  bench_spawn_proxy "$BIN" /root/bench/conf/pqc-nd-$cfg.toml 2>/dev/null
  echo "=== tcp_nodelay $cfg"
  taskset -c "$BENCH_GEN_CPUS" timeout 60 /opt/h3bench/bin/h2load --h1 -c 10 -m 1 -t 6 --duration=15 --warm-up-time=3 \
      "https://bench.local:18444/64k" 2>/dev/null | grep -E "^(finished|requests|time for request|time for connect|time to 1st byte|status)"
done
bench_stop_proxies

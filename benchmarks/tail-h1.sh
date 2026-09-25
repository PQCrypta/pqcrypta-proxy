#!/usr/bin/env bash
# The HTTP/1.1 64 KB request-time tail on both proxies: h2load min/max/mean/sd.
set -uo pipefail
. /root/bench/benchlib.sh
bench_guard_init
export LD_LIBRARY_PATH=/opt/h3bench/lib
BIN=${BIN:-/root/bench/pqc-93256d06}
CFG=${CFG:-/root/bench/conf/pqc-bench-lean.toml}
BODY=${BODY:-64k}
for arm in haproxy ours; do
  bench_stop_proxies
  if [ $arm = haproxy ]; then
    setsid taskset -c "$BENCH_PROXY_CPUS" haproxy -f /root/bench/conf/haproxy.cfg -db </dev/null >/dev/null 2>&1 9>&- &
    until ss -lntupH | grep -q ":18443"; do sleep 1; done; port=18443
  else
    bench_spawn_proxy "$BIN" "$CFG" 2>/dev/null; port=18444
  fi
  sleep 3
  echo "=== $arm $BODY"
  taskset -c "$BENCH_GEN_CPUS" timeout 60 /opt/h3bench/bin/h2load --h1 -c 10 -m 1 -t 6 --duration=15 --warm-up-time=3 \
      "https://bench.local:$port/$BODY" 2>/dev/null | grep -E "^(finished|time for request)"
done
bench_stop_proxies

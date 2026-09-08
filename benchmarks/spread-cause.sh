#!/usr/bin/env bash
# Where does our run-to-run spread come from?
#
# First suspect is the harness, not the proxy: the A/B scripts restart the proxy
# before every cell, so each measurement sees a fresh process — new memory
# layout, new thread placement, a cold backend connection pool. run-bench.sh does
# not do that. If the spread collapses when one instance serves every cell, the
# variance was the restart and not the software.
#
#   restart : stop and start the proxy before each measurement (what A/B does now)
#   persist : one instance, N measurements back to back (what run-bench.sh does)
set -uo pipefail
. /root/bench/benchlib.sh
bench_guard_init
export LD_LIBRARY_PATH=/opt/h3bench/lib
H2LOAD=/opt/h3bench/bin/h2load
BIN=${BIN:-/root/bench/pqcrypta-proxy}
BODY=${BODY:-64k}
N=${N:-6}
DUR=${DUR:-10}

measure() {  # assumes a proxy is already running
  taskset -c "$BENCH_GEN_CPUS" timeout 60 "$H2LOAD" --h1 -c 10 -m 1 -t 6 \
    --duration="$DUR" --warm-up-time=2 "https://bench.local:18444/$BODY" 2>/dev/null \
  | awk '/^finished in/ {print $4}'
}

echo "=== persist: one instance, $N measurements ==="
bench_stop_proxies
bench_spawn_proxy "$BIN" /root/bench/conf/pqc-bench.toml
persist=()
for i in $(seq "$N"); do r=$(measure); persist+=("$r"); printf "  %2d  %10s\n" "$i" "$r"; done
bench_stop_proxies

echo "=== restart: fresh instance per measurement ==="
restart=()
for i in $(seq "$N"); do
  bench_stop_proxies
  bench_spawn_proxy "$BIN" /root/bench/conf/pqc-bench.toml
  r=$(measure); restart+=("$r"); printf "  %2d  %10s\n" "$i" "$r"
done
bench_stop_proxies

python3 - "${persist[@]}" -- "${restart[@]}" <<'PY'
import sys, statistics
args=sys.argv[1:]; i=args.index('--')
p=[float(x) for x in args[:i]]; r=[float(x) for x in args[i+1:]]
for tag,v in (('persist',p),('restart',r)):
    print("  %-8s median %9.0f   min %9.0f   max %9.0f   spread %.2fx   cv %.1f%%"
          % (tag, statistics.median(v), min(v), max(v), max(v)/min(v),
             100*statistics.stdev(v)/statistics.mean(v)))
PY

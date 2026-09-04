#!/usr/bin/env bash
# Does the route-matching fix actually matter? Measure it against a config that
# looks like production — 60 routes, 9 of them carrying a path_regex — rather
# than the single-route bench config, which cannot show the cost at all.
#
# Before the fix, every request compiled every one of those 9 regexes from
# source and allocated a lowercased copy of the path per route. After, each is
# compiled once and the comparisons allocate nothing.
set -uo pipefail
. /root/bench/benchlib.sh
bench_guard_init
LOCK=/run/lock/pqc-bench.lock
exec 9>"$LOCK" || exit 1
flock -n 9 || { echo "another benchmark holds the lock"; exit 1; }
ulimit -n 65535 2>/dev/null
export LD_LIBRARY_PATH=/opt/h3bench/lib

BIN=${BIN:?set BIN to the binary under test}
CFG=${CFG:-/root/bench/conf/pqc-routes.toml}
OUT=/root/bench/out/routes
mkdir -p "$OUT"

for p in $(ss -lntupH 2>/dev/null | grep -E ":1844[3-5]" | grep -oP 'pid=\K[0-9]+' | sort -u); do
  tr '\0' ' ' < "/proc/$p/cmdline" 2>/dev/null | grep -qE "pqc-bench|pqc-routes|bench/conf/haproxy" && kill "$p" 2>/dev/null
done
sleep 2

# 9>&- closes the flock fd in the child. The proxy is started with setsid and
# outlives this script, so without it the *proxy* inherits the lock and holds
# it forever, and every later run refuses to start.
setsid taskset -c 2-5 "$BIN" --config "$CFG" </dev/null >/dev/null 2>&1 9>&- &
sleep 6
ss -lntupH 2>/dev/null | grep -q ":18444" || { echo "proxy did not start"; exit 1; }

for rep in 1 2 3; do
  printf "  %-28s rep%s  " "$(basename "$BIN")" "$rep"
  taskset -c 6-11 timeout 60 /opt/h3bench/bin/h2load --h1 -c 100 -m 1 \
      --duration=8 --warm-up-time=2 https://bench.local:18444/empty 2>/dev/null \
    | grep -oE "^finished in [0-9.]+s, [0-9.]+ req/s" | sed 's/^finished in [0-9.]*s, //'
done

for p in $(ss -lntupH 2>/dev/null | grep -E ":1844[45]" | grep -oP 'pid=\K[0-9]+' | sort -u); do
  tr '\0' ' ' < "/proc/$p/cmdline" 2>/dev/null | grep -q "pqc-routes" && kill "$p" 2>/dev/null
done

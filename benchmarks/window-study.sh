#!/usr/bin/env bash
# Why the comparison measures 60 s after a 15 s warm-up, measured rather than
# asserted: the same cell, N runs per window, for HAProxy and for our
# like-for-like arm, at 10 s / 2 s and at 60 s / 15 s. A short window that
# flatters one proxy more than the other is a comparison of warm-up behaviour.
set -uo pipefail
. /root/bench/benchlib.sh
bench_guard_init
export LD_LIBRARY_PATH=/opt/h3bench/lib
H2LOAD=/opt/h3bench/bin/h2load
BIN=${BIN:-/root/bench/pqc-93256d06}
BODY=${BODY:-64k}
N=${N:-6}
RES=${RES:-/root/bench/out/window-$(date +%Y%m%d_%H%M%S)}
mkdir -p "$RES"
exec > >(tee -a "$RES/run.log") 2>&1
echo "arm,duration_s,warmup_s,rep,req_per_s" > "$RES/window.csv"
start() {
  bench_stop_proxies
  if [ "$1" = haproxy ]; then
    setsid taskset -c "$BENCH_PROXY_CPUS" haproxy -f /root/bench/conf/haproxy.cfg -db </dev/null >/dev/null 2>&1 9>&- &
    local w=0; until ss -lntupH | grep -q ":18443"; do w=$((w+1)); [ $w -gt 20 ] && exit 1; sleep 1; done
  else
    bench_spawn_proxy "$BIN" /root/bench/conf/pqc-bench-lean.toml
  fi
  sleep 4
}
for win in "10 2" "60 15"; do
  read -r dur wu <<< "$win"
  for rep in $(seq "$N"); do
    for arm in haproxy lean-now; do     # alternate within every repetition
      port=18444; [ "$arm" = haproxy ] && port=18443
      start "$arm"
      rps=$(taskset -c "$BENCH_GEN_CPUS" timeout $((dur + wu + 40)) "$H2LOAD" --h1 -c 10 -m 1 -t 6 \
            --duration="$dur" --warm-up-time="$wu" "https://bench.local:$port/$BODY" 2>/dev/null \
            | awk '/^finished in/ {print $4}')
      echo "$arm,$dur,$wu,$rep,${rps:-0}" >> "$RES/window.csv"
      echo "  $arm dur=$dur wu=$wu r$rep $rps req/s"
    done
  done
done
bench_stop_proxies
echo "########## done $(date -Is)"

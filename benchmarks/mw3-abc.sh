#!/usr/bin/env bash
# Separate the middleware's plumbing from its work.
#
#   A  full chain            eight layers, each boxing a future and cloning, each
#                            doing its job
#   C  chain, no work        same eight layers, same boxing/cloning/Next
#                            indirection, each returning immediately
#   B  no chain              collapsed to one pass-through layer
#
#   A - C = what the layers DO
#   C - B = what the layering COSTS
#
# Run at 64 KB: all three arms differ in response header bytes, and at 64 KB that
# difference is ~1% of the response instead of ~40%. Header bytes are recorded
# per arm so the residual confound is visible rather than assumed away.
#
# Order rotates each round so no arm is permanently in the slow slot.
set -uo pipefail
. /root/bench/benchlib.sh
bench_guard_init
export LD_LIBRARY_PATH=/opt/h3bench/lib
H2LOAD=/opt/h3bench/bin/h2load
BODY=${BODY:-64k}
ROUNDS=${ROUNDS:-3}
DUR=${DUR:-60}
WU=${WU:-15}

cell_running() {  # $1=port, proxy already started
  local pid c0 c1 t0 t1 out hb
  pid=$(ss -lntupH 2>/dev/null | grep ":$1" | grep -oP 'pid=\K[0-9]+' | head -1)
  [ -n "$pid" ] || { echo "- - -"; return; }
  hb=$(curl -sk -o /dev/null -D - "https://bench.local:$1/$BODY" 2>/dev/null | wc -c)
  c0=$(awk '{print $14+$15}' "/proc/$pid/stat"); t0=$(date +%s.%N)
  out=$(taskset -c "$BENCH_GEN_CPUS" timeout $((DUR+WU+60)) "$H2LOAD" --h1 -c 10 -m 1 -t 6 \
        --duration="$DUR" --warm-up-time="$WU" "https://bench.local:$1/$BODY" 2>/dev/null)
  t1=$(date +%s.%N); c1=$(awk '{print $14+$15}' "/proc/$pid/stat")
  bench_stop_proxies
  echo "$out" | awk -v a="$c0" -v b="$c1" -v s="$t0" -v e="$t1" -v h="$hb" '
    /^finished in/ { rps=$4 }
    END { printf "%s %.0f %s\n", (rps==""?"-":rps), (b-a)/100/(e-s)*100, h }'
}

cell() {
  bench_stop_proxies
  bench_spawn_proxy "$1" /root/bench/conf/pqc-bench.toml
  local pid c0 c1 t0 t1 out hb
  pid=$(ss -lntupH 2>/dev/null | grep ':18444' | grep -oP 'pid=\K[0-9]+' | head -1)
  [ -n "$pid" ] || { echo "- - -"; return; }
  hb=$(curl -sk -o /dev/null -D - "https://bench.local:18444/$BODY" 2>/dev/null | wc -c)
  c0=$(awk '{print $14+$15}' "/proc/$pid/stat"); t0=$(date +%s.%N)
  out=$(taskset -c "$BENCH_GEN_CPUS" timeout $((DUR+WU+60)) "$H2LOAD" --h1 -c 10 -m 1 -t 6 \
        --duration="$DUR" --warm-up-time="$WU" "https://bench.local:18444/$BODY" 2>/dev/null)
  t1=$(date +%s.%N); c1=$(awk '{print $14+$15}' "/proc/$pid/stat")
  bench_stop_proxies
  echo "$out" | awk -v a="$c0" -v b="$c1" -v s="$t0" -v e="$t1" -v h="$hb" '
    /^finished in/ { rps=$4 }
    END { printf "%s %.0f %s\n", (rps==""?"-":rps), (b-a)/100/(e-s)*100, h }'
}

printf "%-4s %14s %8s %12s\n" arm "req/s" "cpu%" "resp hdr B"
for i in $(seq "$ROUNDS"); do
  case $((i % 3)) in
    1) order="A C B" ;;
    2) order="C B A" ;;
    0) order="B A C" ;;
  esac
  for who in $order; do
    if [ "$who" = H ]; then
      bench_stop_proxies
      setsid taskset -c "$BENCH_PROXY_CPUS" haproxy -f /root/bench/conf/haproxy.cfg -db </dev/null >/dev/null 2>&1 9>&- &
      sleep 6
      read -r rps cpu hb < <(cell_running 18443)
    else
      case $who in A) bin=/root/bench/pqc-mw-A ;; B) bin=/root/bench/pqc-mw-B ;; C) bin=/root/bench/pqc-mw-C ;; esac
      read -r rps cpu hb < <(cell "$bin")
    fi
    printf "%-4s %14s %8s %12s\n" "$who" "$rps" "$cpu" "$hb"
  done
done

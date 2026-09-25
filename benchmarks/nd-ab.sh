#!/usr/bin/env bash
# What TCP_NODELAY costs in throughput, at the body size where the pooled matrix
# suggested it might cost something.
#
# ONE binary, two configs -- the knob as an operator would set it, rather than
# two builds (trap 8). Order flips on round parity so neither arm eats the cost
# of running second (trap 11).
#
# The m=1 cells are the control that proves the knob is actually read: with
# nodelay off the 40 ms delayed-ACK stall must come back. A knob that changes
# no measurement is an inert knob.
set -uo pipefail

# Wait for the lock BEFORE sourcing benchlib: bench_guard_init takes the lock
# itself and refuses to start rather than queueing.
while fuser /run/lock/pqc-bench.lock >/dev/null 2>&1; do
    echo "waiting for the lock  $(date -Is)"; sleep 120
done

. /root/bench/benchlib.sh
bench_guard_init
export LD_LIBRARY_PATH=/opt/h3bench/lib
H2LOAD=/opt/h3bench/bin/h2load
BIN=${BIN:-/root/bench/pqc-knob}
ON=/root/bench/conf/pqc-nd-on.toml
OFF=/root/bench/conf/pqc-nd-off.toml
ROUNDS=${ROUNDS:-3}
DUR=${DUR:-$BENCH_DUR}
WU=${WU:-$BENCH_WARMUP}
OUT=${OUT:-/root/bench/out/nd-ab-$(date +%Y%m%d_%H%M%S).csv}

echo "arm,protocol,body,conns,streams,round,req_per_s,mean_lat,cpu_pct" > "$OUT"

cell() {  # $1=cfg $2=alpn $3=body $4=conns $5=streams
  bench_stop_proxies
  bench_spawn_proxy "$BIN" "$1"
  local pid c0 c1 t0 t1 out
  pid=$(ss -lntupH 2>/dev/null | grep ':18444' | grep -oP 'pid=\K[0-9]+' | head -1)
  [ -n "$pid" ] || { echo "- - -"; return; }
  c0=$(awk '{print $14+$15}' "/proc/$pid/stat"); t0=$(date +%s.%N)
  out=$(taskset -c "$BENCH_GEN_CPUS" timeout $((DUR + WU + 90)) "$H2LOAD" --alpn-list="$2" \
        -c "$4" -m "$5" -t 6 --duration="$DUR" --warm-up-time="$WU" \
        "https://bench.local:18444/$3" 2>/dev/null)
  t1=$(date +%s.%N); c1=$(awk '{print $14+$15}' "/proc/$pid/stat")
  bench_stop_proxies
  echo "$out" | awk -v a="$c0" -v b="$c1" -v s="$t0" -v e="$t1" '
    /^finished in/ { rps=$4 } /^time for request:/ { lat=$(NF-2) }
    END { printf "%s %s %.0f\n", (rps==""?"-":rps), (lat==""?"-":lat), (b-a)/100/(e-s)*100 }'
}

run_set() {  # $1=alpn $2=body $3=conns $4=streams
  for i in $(seq "$ROUNDS"); do
    if [ $((i % 2)) -eq 1 ]; then order="on off"; else order="off on"; fi
    for arm in $order; do
      [ "$arm" = on ] && cfg=$ON || cfg=$OFF
      read -r rps lat cpu < <(cell "$cfg" "$1" "$2" "$3" "$4")
      printf "%-4s %-9s %-6s c=%-4s m=%-3s r%d  %12s req/s  lat=%-10s cpu=%s%%\n" \
             "$arm" "$1" "$2" "$3" "$4" "$i" "$rps" "$lat" "$cpu"
      echo "$arm,$1,$2,$3,$4,$i,$rps,$lat,$cpu" >> "$OUT"
    done
  done
}

echo "########## knob proof: the stall must return with nodelay off  $(date -Is)"
run_set h2 64k 10 1

echo "########## the 64 KB throughput question  $(date -Is)"
run_set http/1.1 64k 10 1
run_set h2 64k 10 10
run_set h2 64k 100 10

echo "########## 1 KB control -- effect should be 64 KB specific  $(date -Is)"
run_set h2 1k 10 10

echo "########## done $(date -Is) -> $OUT"

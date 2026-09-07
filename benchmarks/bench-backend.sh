#!/usr/bin/env bash
# The backend's own ceiling, measured with the same threaded generator as the
# proxies.
#
# The published ceiling (~84k req/s at 1 KB) was measured before the generator
# was threaded, and HAProxy has since been measured *above* it on the same body
# size -- which means that figure was the generator's limit, not nginx's, and the
# claim that the backend is "comfortably clear of either proxy" rested on it.
# A backend that is not clear turns every cell it binds into a measurement of
# nginx rather than of a proxy.
set -uo pipefail
. /root/bench/benchlib.sh
bench_guard_init

export LD_LIBRARY_PATH=/opt/h3bench/lib
H2LOAD=/opt/h3bench/bin/h2load
OUT=/root/bench/out
REPS=${REPS:-3}
DUR=${DUR:-10}
HZ=$(getconf CLK_TCK)

# Sum utime+stime over every worker: the question is whether the set is
# saturated, not whether one of them is. The budget is 100% per worker CPU, read
# from the running master rather than assumed -- it was assumed once, as 200%,
# and stayed that way after the backend was given four CPUs.
worker_ticks() {
  local t=0 p
  for p in $(pgrep -P "$(cat "$OUT/nginx.pid")"); do
    t=$((t + $(awk '{print $14+$15}' "/proc/$p/stat" 2>/dev/null || echo 0)))
  done
  echo "$t"
}

WORKERS=$(pgrep -P "$(cat "$OUT/nginx.pid")" | wc -l)
BUDGET=$((WORKERS * 100))
echo "backend workers: $WORKERS, CPU budget ${BUDGET}%"
echo "body,conns,rep,req_per_s,throughput,nginx_cpu_pct,cpu_budget_pct" > "$OUT/backend-ceiling.csv"

for body in empty 1k 64k; do
  for conns in 10 100; do
    for rep in $(seq 1 "$REPS"); do
      before=$(worker_ticks); t0=$(date +%s.%N)
      out=$(taskset -c "$BENCH_GEN_CPUS" timeout $((DUR + 30)) "$H2LOAD" --h1 \
              -c "$conns" -m 1 -t "${GEN_THREADS:-6}" --duration="$DUR" --warm-up-time=2 \
              "http://127.0.0.1:18080/$body" 2>/dev/null)
      t1=$(date +%s.%N); after=$(worker_ticks)
      rps=$(echo "$out" | awk '/^finished in/ {print $4}')
      bps=$(echo "$out" | awk '/^finished in/ {print $6}')
      cpu=$(awk -v a="$before" -v b="$after" -v s="$t0" -v e="$t1" -v hz="$HZ" \
            'BEGIN{ printf "%.1f", (b-a)/hz/(e-s)*100 }')
      echo "$body,$conns,$rep,$rps,$bps,$cpu,$BUDGET" >> "$OUT/backend-ceiling.csv"
      printf "  nginx %-5s c=%-4s r%s  %11s req/s  %10s  nginx_cpu=%s%% of %s%%\n" \
        "$body" "$conns" "$rep" "$rps" "$bps" "$cpu" "$BUDGET"
    done
  done
done
echo "=== done: $OUT/backend-ceiling.csv ==="

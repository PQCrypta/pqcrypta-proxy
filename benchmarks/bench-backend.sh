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

# Output path. Defaults to a timestamped name so no two runs share a file:
# a fixed name is truncated by the next run, and anything copying it in the
# meantime saves a partial file over the good one. Pass RESULTS explicitly to
# put it where you want it.
RESULTS=${RESULTS:-$OUT/backend-ceiling-$(date +%Y%m%d_%H%M%S).csv}
REPS=${REPS:-3}
DUR=${DUR:-$BENCH_DUR}
WU_PAD=${WU:-$BENCH_WARMUP}
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
echo "body,conns,rep,req_per_s,throughput,nginx_cpu_pct,cpu_budget_pct" > "$RESULTS"

for body in empty 1k 64k; do
  for conns in 10 100; do
    for rep in $(seq 1 "$REPS"); do
      before=$(worker_ticks); t0=$(date +%s.%N)
      out=$(taskset -c "$BENCH_GEN_CPUS" timeout $((DUR + WU_PAD + 40)) "$H2LOAD" --h1 \
              -c "$conns" -m 1 -t "${GEN_THREADS:-6}" --duration="$DUR" --warm-up-time="${WU:-$BENCH_WARMUP}" \
              "http://127.0.0.1:18080/$body" 2>/dev/null)
      t1=$(date +%s.%N); after=$(worker_ticks)
      rps=$(echo "$out" | awk '/^finished in/ {print $4}')
      bps=$(echo "$out" | awk '/^finished in/ {print $6}')
      cpu=$(awk -v a="$before" -v b="$after" -v s="$t0" -v e="$t1" -v hz="$HZ" \
            'BEGIN{ printf "%.1f", (b-a)/hz/(e-s)*100 }')
      echo "$body,$conns,$rep,$rps,$bps,$cpu,$BUDGET" >> "$RESULTS"
      printf "  nginx %-5s c=%-4s r%s  %11s req/s  %10s  nginx_cpu=%s%% of %s%%\n" \
        "$body" "$conns" "$rep" "$rps" "$bps" "$cpu" "$BUDGET"
    done
  done
done
# Row count, asserted rather than assumed. A short file means the run died, or
# something truncated it — analysing one silently produces a plausible table from
# half the data. chmod is not a guard here: this runs as root, and root ignores
# the permission bits.
expected=$((3 * 2 * REPS))
got=$(( $(grep -c . "$RESULTS") - 1 ))
if [ "$got" -ne "$expected" ]; then
    echo "FATAL: $RESULTS has $got rows, expected $expected" >&2
    echo "       the run did not finish, or the file was overwritten" >&2
    exit 1
fi
echo "rows: $got (as expected)"

# A hint to anyone reading, not a guard — see above.
chmod 444 "$RESULTS" 2>/dev/null
echo "=== done: $RESULTS ==="

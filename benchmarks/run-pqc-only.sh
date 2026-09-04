#!/usr/bin/env bash
# Re-run only the pqcrypta-proxy half of the matrix.
#
# The first pass measured a build with Nagle left on for backend connections and
# a pool of 10 idle connections against HAProxy's maxconn 20000 — a difference
# between two configs rather than two proxies. This pass carries the TCP_NODELAY
# fix and a pool matched to what production runs. HAProxy's numbers are unchanged
# and are not re-run: nothing about its side moved.
set -uo pipefail

# Shared guards — see benchlib.sh. Each exists because its absence produced a
# confident wrong number that was believed for a while.
# shellcheck source=/root/bench/benchlib.sh
. /root/bench/benchlib.sh
bench_guard_init

# Both proxies get the same descriptor limit, and it is the one production runs
# under (the systemd unit sets LimitNOFILE=65535). The first pass inherited the
# shell default of 1024, which caps a proxy near 500 concurrent connections
# because every client connection costs one descriptor and its backend
# connection costs another — so that pass measured a ulimit, not a proxy.
export LD_LIBRARY_PATH=/opt/h3bench/lib
H2LOAD=/opt/h3bench/bin/h2load
OUT=/root/bench/out
mkdir -p "$OUT/raw2"

REPS=${REPS:-3}
DUR=${DUR:-8}

stop_bench_proxies() {
  local pids
  pids=$(ss -lntupH 2>/dev/null | grep -E ":1844[3-5]" | grep -oP 'pid=\K[0-9]+' | sort -u)
  for p in $pids; do
    tr '\0' ' ' < "/proc/$p/cmdline" 2>/dev/null | grep -qE "pqc-bench.toml|bench/conf/haproxy.cfg" && kill "$p" 2>/dev/null
  done
  sleep 2
}

parse() {
  awk '
    /^finished in/       { rps=$4; bps=$6 }
    /^requests:/         { gsub(/,/,""); for(i=1;i<=NF;i++){ if($i=="succeeded") ok=$(i-1); if($i=="failed") fail=$(i-1) } }
    /^status codes:/     { gsub(/,/,""); for(i=1;i<=NF;i++) if($i=="2xx") ok2xx=$(i-1) }
    /^time for request:/ { lat_mean=$(NF-2) }
    END { printf "%s %s %s %s %s %s\n", (rps==""?"0":rps),(bps==""?"0":bps),(ok==""?"0":ok),(fail==""?"0":fail),(lat_mean==""?"-":lat_mean),(ok2xx==""?"0":ok2xx) }
  '
}

stop_bench_proxies
setsid taskset -c 2-5 /root/bench/pqcrypta-proxy --config "${CFG:-/root/bench/conf/pqc-bench-features.toml}" </dev/null >>"$OUT/pqc2.log" 2>&1 &
sleep 6

echo "proxy,protocol,body,conns,streams,rep,req_per_s,throughput,succeeded,failed,mean_latency,http_2xx" > "$OUT/results-pqc2.csv"

for alpn in "http/1.1" h2 h3; do
  for body in empty 1k 64k; do
    for conns in 10 100; do
      streams=1; [ "$alpn" != "http/1.1" ] && streams=10
      extra=(--h1)
      [ "$alpn" = "h2" ] && extra=(--alpn-list=h2)
      [ "$alpn" = "h3" ] && extra=(--alpn-list=h3)
      for rep in $(seq 1 "$REPS"); do
        raw="$OUT/raw2/pqc_${alpn//\//-}_${body}_c${conns}_r${rep}.txt"
        taskset -c 6-11 timeout $((DUR + 30)) "$H2LOAD" "${extra[@]}" \
            -c "$conns" -m "$streams" --duration="$DUR" --warm-up-time=2 \
            "https://bench.local:18444/$body" > "$raw" 2>/dev/null
        read -r rps bps ok fail lat ok2xx < <(parse < "$raw")
        echo "pqc,$alpn,$body,$conns,$streams,$rep,$rps,$bps,$ok,$fail,$lat,$ok2xx" >> "$OUT/results-pqc2.csv"
        printf "  pqc2 %-8s %-5s c=%-4s r%s  %11s req/s  %10s  lat=%-9s 2xx=%-8s fail=%s\n" \
          "$alpn" "$body" "$conns" "$rep" "$rps" "$bps" "$lat" "$ok2xx" "$fail"
      done
    done
  done
done

stop_bench_proxies
echo "=== done: $OUT/results-pqc2.csv ==="

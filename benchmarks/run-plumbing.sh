#!/usr/bin/env bash
# The plumbing-only arm: pqcrypta-proxy with every feature HAProxy does not have
# turned off — no early hints, no priority hints, no request coalescing, no
# Server-Timing, on top of the WAF/fingerprinting/rate-limiting already off.
#
# This answers "how fast is the proxy". The as-deployed arm (defaults left on)
# answers "how fast is what I will actually run", and is the more honest number
# to lead with. Both get published.
set -uo pipefail

# Shared guards — see benchlib.sh. Each exists because its absence produced a
# confident wrong number that was believed for a while.
# shellcheck source=/root/bench/benchlib.sh
. /root/bench/benchlib.sh
bench_guard_init

export LD_LIBRARY_PATH=/opt/h3bench/lib
H2LOAD=/opt/h3bench/bin/h2load
OUT=/root/bench/out
mkdir -p "$OUT/raw-plumbing"

REPS=${REPS:-3}
DUR=${DUR:-8}

stop_bench_proxies() {
  pkill -f "haproxy -f /root/bench/conf/haproxy" 2>/dev/null
  for p in $(ss -lntupH 2>/dev/null | grep -E ":1844[3-5]" | grep -oP 'pid=\K[0-9]+' | sort -u); do
    tr '\0' ' ' < "/proc/$p/cmdline" 2>/dev/null | grep -qE "pqc-bench|bench/conf/haproxy" && kill "$p" 2>/dev/null
  done
  sleep 2
}

parse() {
  awk '
    /^finished in/       { rps=$4; bps=$6 }
    /^requests:/         { gsub(/,/,""); for(i=1;i<=NF;i++){ if($i=="succeeded") ok=$(i-1); if($i=="failed") fail=$(i-1) } }
    /^status codes:/     { gsub(/,/,""); for(i=1;i<=NF;i++) if($i=="2xx") ok2xx=$(i-1) }
    /^time for request:/ { lat=$(NF-2) }
    END { printf "%s %s %s %s %s %s\n",(rps==""?"0":rps),(bps==""?"0":bps),(ok==""?"0":ok),(fail==""?"0":fail),(lat==""?"-":lat),(ok2xx==""?"0":ok2xx) }
  '
}

stop_bench_proxies
setsid taskset -c 2-5 /root/bench/pqcrypta-proxy --config /root/bench/conf/pqc-bench.toml </dev/null >>"$OUT/pqc-plumbing.log" 2>&1 &
sleep 6

echo "proxy,protocol,body,conns,streams,rep,req_per_s,throughput,succeeded,failed,mean_latency,http_2xx" > "$OUT/results-plumbing.csv"

for alpn in "http/1.1" h2 h3; do
  for body in empty 1k 64k; do
    for conns in 10 100; do
      streams=1; [ "$alpn" != "http/1.1" ] && streams=10
      extra=(--h1)
      [ "$alpn" = "h2" ] && extra=(--alpn-list=h2)
      [ "$alpn" = "h3" ] && extra=(--alpn-list=h3)
      for rep in $(seq 1 "$REPS"); do
        raw="$OUT/raw-plumbing/pqc_${alpn//\//-}_${body}_c${conns}_r${rep}.txt"
        taskset -c 6-11 timeout $((DUR + 30)) "$H2LOAD" "${extra[@]}" \
            -c "$conns" -m "$streams" --duration="$DUR" --warm-up-time=2 \
            "https://bench.local:18444/$body" > "$raw" 2>/dev/null
        read -r rps bps ok fail lat ok2xx < <(parse < "$raw")
        echo "pqc,$alpn,$body,$conns,$streams,$rep,$rps,$bps,$ok,$fail,$lat,$ok2xx" >> "$OUT/results-plumbing.csv"
        printf "  plumb %-8s %-5s c=%-4s r%s  %11s req/s  %10s  lat=%-9s 2xx=%-8s fail=%s\n" \
          "$alpn" "$body" "$conns" "$rep" "$rps" "$bps" "$lat" "$ok2xx" "$fail"
      done
    done
  done
done

stop_bench_proxies
echo "=== done: $OUT/results-plumbing.csv ==="

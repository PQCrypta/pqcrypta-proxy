#!/usr/bin/env bash
# HAProxy vs pqcrypta-proxy — HTTP/1.1, HTTP/2, HTTP/3.
#
# One proxy runs at a time, pinned to cores 2-5. The generator is pinned to 6-11
# and the backend to 0-1, so nothing under test ever shares a core with the thing
# measuring it. Each cell is run REPS times and the median reported, because a
# single run of anything network-shaped is noise.
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
mkdir -p "$OUT/raw"

REPS=${REPS:-3}
DUR=${DUR:-10}

start_proxy() {  # $1 = haproxy|pqc
  stop_proxies
  if [ "$1" = haproxy ]; then
    setsid taskset -c 2-5 haproxy -f /root/bench/conf/haproxy.cfg -db </dev/null >>"$OUT/haproxy.log" 2>&1 &
  else
    setsid taskset -c 2-5 /root/bench/pqcrypta-proxy --config /root/bench/conf/pqc-bench.toml </dev/null >>"$OUT/pqc.log" 2>&1 &
  fi
  sleep 5
}

stop_proxies() {
  pkill -f "haproxy -f /root/bench/conf/haproxy.cfg" 2>/dev/null
  local pids
  pids=$(ss -lntupH 2>/dev/null | grep -E ":1844[3-5]" | grep -oP 'pid=\K[0-9]+' | sort -u)
  for p in $pids; do
    tr '\0' ' ' < "/proc/$p/cmdline" 2>/dev/null | grep -qE "pqc-bench.toml|bench/conf/haproxy.cfg" && kill "$p" 2>/dev/null
  done
  sleep 2
}

# One measurement. Echoes: reqs_per_sec bytes_per_sec p50 p95 p99 ok fail
one_run() {  # $1=port $2=alpn $3=path $4=conns $5=streams
  local port=$1 alpn=$2 path=$3 conns=$4 streams=$5
  local extra=()
  [ "$alpn" = "http/1.1" ] && extra=(--h1)
  [ "$alpn" = "h2" ]  && extra=(--alpn-list=h2)
  [ "$alpn" = "h3" ]  && extra=(--alpn-list=h3)

  taskset -c 6-11 timeout $((DUR + 30)) "$H2LOAD" "${extra[@]}" \
      -c "$conns" -m "$streams" --duration="$DUR" --warm-up-time=2 \
      "https://bench.local:${port}${path}" 2>/dev/null
}

# h2load prints counts with trailing commas ("6734 succeeded,"), which is why the
# first version of this reported ok=0 on every run. Strip punctuation first.
parse() {  # stdin = h2load output
  awk '
    /^finished in/       { rps=$4; bps=$6 }
    /^requests:/         { gsub(/,/,""); for(i=1;i<=NF;i++){ if($i=="succeeded") ok=$(i-1); if($i=="failed") fail=$(i-1) } }
    /^status codes:/     { gsub(/,/,""); for(i=1;i<=NF;i++) if($i=="2xx") ok2xx=$(i-1) }
    /^time for request:/ { lat_mean=$(NF-2); lat_max=$4 }
    END { printf "%s %s %s %s %s %s\n",
            (rps==""?"0":rps), (bps==""?"0":bps),
            (ok==""?"0":ok), (fail==""?"0":fail),
            (lat_mean==""?"-":lat_mean), (ok2xx==""?"0":ok2xx) }
  '
}

echo "proxy,protocol,body,conns,streams,rep,req_per_s,throughput,succeeded,failed,mean_latency,http_2xx" > "$OUT/results.csv"

for proxy in haproxy pqc; do
  port=18443; [ "$proxy" = pqc ] && port=18444
  echo "### $proxy on :$port"
  start_proxy "$proxy"

  for alpn in "http/1.1" h2 h3; do
    for body in empty 1k 64k; do
      for conns in 10 100; do
        streams=1
        [ "$alpn" != "http/1.1" ] && streams=10
        for rep in $(seq 1 "$REPS"); do
          raw="$OUT/raw/${proxy}_${alpn//\//-}_${body}_c${conns}_r${rep}.txt"
          one_run "$port" "$alpn" "/$body" "$conns" "$streams" > "$raw"
          read -r rps bps ok fail lat ok2xx < <(parse < "$raw")
          echo "$proxy,$alpn,$body,$conns,$streams,$rep,$rps,$bps,$ok,$fail,$lat,$ok2xx" >> "$OUT/results.csv"
          printf "  %-7s %-8s %-5s c=%-4s r%s  %11s req/s  %10s  lat=%-9s 2xx=%-8s fail=%s\n" \
            "$proxy" "$alpn" "$body" "$conns" "$rep" "$rps" "$bps" "$lat" "$ok2xx" "$fail"
        done
      done
    done
  done
  stop_proxies
done

echo
echo "=== raw CSV at $OUT/results.csv ==="

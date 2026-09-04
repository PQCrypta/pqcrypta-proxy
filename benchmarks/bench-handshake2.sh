#!/usr/bin/env bash
# What does post-quantum key exchange cost per handshake?
#
# Measured rather than asserted, on both proxies, on the same OpenSSL 3.5.5 that
# carries ML-KEM natively — so this is a head-to-head on the same key exchange,
# not one product's PQC against another's classical.
#
# `openssl s_time` cannot do this: it has no -servername, so it sends no SNI and
# a SNI-based listener never sees a usable hello. h2load can, it drives the same
# certificate selection real clients do, and it takes --groups. One request per
# connection (-n == -c) so every connection is a fresh handshake, and the figure
# read out is *mean connect time*, which is the handshake cost directly rather
# than a rate with process-spawn overhead folded in.
set -uo pipefail

# Shared guards — see benchlib.sh. Each exists because its absence produced a
# confident wrong number that was believed for a while.
# shellcheck source=/root/bench/benchlib.sh
. /root/bench/benchlib.sh
bench_guard_init
export LD_LIBRARY_PATH=/opt/h3bench/lib
H2LOAD=/opt/h3bench/bin/h2load
OUT=/root/bench/out/handshake
mkdir -p "$OUT"

CONNS=${CONNS:-200}
REPS=${REPS:-3}

stop_bench_proxies() {
  pkill -f "haproxy -f /root/bench/conf/haproxy" 2>/dev/null
  for p in $(ss -lntupH 2>/dev/null | grep -E ":1844[3-5]" | grep -oP 'pid=\K[0-9]+' | sort -u); do
    tr '\0' ' ' < "/proc/$p/cmdline" 2>/dev/null | grep -qE "pqc-bench|bench/conf/haproxy" && kill "$p" 2>/dev/null
  done
  sleep 2
}

# Read the group off the connection rather than trusting the config — the same
# rule the proxy applies to its own startup banner. Classical reports as
# "Peer Temp Key"; the hybrid reports as "Negotiated TLS1.3 group".
negotiated() {  # $1=port $2=curve
  timeout 10 openssl s_client -connect "127.0.0.1:$1" -servername bench.local \
      -curves "$2" -tls1_3 </dev/null 2>/dev/null \
    | grep -m1 -oE "Negotiated TLS1.3 group: .*|Peer Temp Key: [^,]*" \
    | sed -E 's/.*group: *//; s/Peer Temp Key: *//'
}

echo "proxy,curve,rep,mean_connect_us,handshakes_per_sec,negotiated" > "$OUT/results.csv"

for proxy in haproxy pqc; do
  port=18443; [ "$proxy" = pqc ] && port=18444
  stop_bench_proxies
  if [ "$proxy" = haproxy ]; then
    setsid taskset -c 2-5 haproxy -f /root/bench/conf/haproxy.cfg -db </dev/null >/dev/null 2>&1 &
  else
    setsid taskset -c 2-5 /root/bench/pqcrypta-proxy --config /root/bench/conf/pqc-bench.toml </dev/null >/dev/null 2>&1 &
  fi
  sleep 6

  for curve in X25519 X25519MLKEM768; do
    grp=$(negotiated "$port" "$curve")
    if [ -z "$grp" ]; then
      printf "  %-8s %-16s NOT NEGOTIABLE — skipped\n" "$proxy" "$curve"
      echo "$proxy,$curve,-,-,-,not-negotiable" >> "$OUT/results.csv"
      continue
    fi
    for rep in $(seq 1 "$REPS"); do
      raw="$OUT/${proxy}_${curve}_r${rep}.txt"
      taskset -c 6-11 timeout 90 "$H2LOAD" --h1 --groups="$curve" \
          -c "$CONNS" -n "$CONNS" -m 1 "https://bench.local:${port}/empty" \
          > "$raw" 2>/dev/null
      # "time for connect:  min  max  mean  sd  +/- sd" — mean is field 4.
      read -r conn_us hps < <(awk '
        /^time for connect:/ {
          v=$4
          if (v ~ /ms$/)      { sub(/ms$/,"",v); us=v*1000 }
          else if (v ~ /us$/) { sub(/us$/,"",v); us=v }
          else if (v ~ /s$/)  { sub(/s$/,"",v);  us=v*1000000 }
          printf "%.0f %.0f\n", us, (us>0 ? 1000000/us : 0)
        }' "$raw")
      echo "$proxy,$curve,$rep,${conn_us:-0},${hps:-0},$grp" >> "$OUT/results.csv"
      printf "  %-8s %-16s r%s  connect=%6s us  =%7s handshakes/s/conn   negotiated=%s\n" \
        "$proxy" "$curve" "$rep" "${conn_us:-?}" "${hps:-?}" "$grp"
    done
  done
done

stop_bench_proxies
echo "=== $OUT/results.csv ==="

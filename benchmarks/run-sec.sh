#!/usr/bin/env bash
# What the security stack actually costs, measured where it actually runs.
#
# The old "features" arm could not measure this and never did. Everything in this
# rig runs over loopback, and SecurityState::is_trusted short-circuits the entire
# per-request security block for loopback peers -- blocklist, rate limits,
# header-size checks, WAF, the lot. On top of that, both of its configs kept
# [waf], [fingerprint], [rate_limiting] and [advanced_rate_limiting] disabled, so
# the two arms differed only in [http3] and [headers].
#
# So this binds a non-loopback address on a dummy interface. RFC1918 is *not*
# implicitly trusted -- only loopback and explicit trusted_internal_cidrs -- so
# 10.99.0.1 takes the full security path.
#
# Both arms use the same binary and the same threaded generator. The previous
# published features figure compared a six-thread run against a one-thread run,
# which is a comparison of two generators.
set -uo pipefail
. /root/bench/benchlib.sh
bench_guard_init

export LD_LIBRARY_PATH=/opt/h3bench/lib
H2LOAD=/opt/h3bench/bin/h2load
OUT=/root/bench/out

# Where the two arms land. Timestamped by default for the same reason as the
# other runners: a fixed name is a file the next run will truncate.
RESULTS_DIR=${RESULTS_DIR:-$OUT/sec-$(date +%Y%m%d_%H%M%S)}
mkdir -p "$RESULTS_DIR"
BIN=${BIN:-/root/bench/pqcrypta-proxy}

# A browser UA, because waf.block_scanner_uas is on and correctly rejects a
# tool that announces itself as one. The rule still runs and still costs what
# it costs; the request simply is not one it should reject.
UA="Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/140.0.0.0 Safari/537.36"
REPS=${REPS:-3}
DUR=${DUR:-$BENCH_DUR}
WU_PAD=${WU:-$BENCH_WARMUP}

# Preflight: prove the security path is live in one arm and not the other before
# spending an hour measuring the difference between them. An arm that silently
# runs with the WAF bypassed produces a "security is free" figure.
preflight() {  # $1=config $2=expected status for the probe
  bench_stop_proxies
  bench_spawn_proxy "$BIN" "$1"
  local got
  got=$(curl -sk -o /dev/null -w '%{http_code}' --max-time 5 -A "$UA" \
        "https://bench-sec.local:18444/1k?id=1%20UNION%20SELECT%20password%20FROM%20users")
  local plain
  plain=$(curl -sk -o /dev/null -w '%{http_code}' --max-time 5 -A "$UA" \
        "https://bench-sec.local:18444/1k")
  bench_stop_proxies
  if [ "$plain" != "200" ]; then
    echo "FATAL: $1 answered $plain for a plain GET, expected 200" >&2
    echo "       an arm that rejects everything would price the rejection path" >&2
    exit 1
  fi
  if [ "$got" != "$2" ]; then
    echo "FATAL: $1 answered $got for the SQLi probe, expected $2" >&2
    echo "       the arms are not what they claim to be; refusing to measure" >&2
    exit 1
  fi
  # And a burst at the concurrency the run actually uses. Every ban that has
  # ruined this arm was rate- or connection-triggered and therefore invisible to
  # a single request.
  local burst fourxx total
  bench_spawn_proxy "$BIN" "$1"
  burst=$(taskset -c "$BENCH_GEN_CPUS" timeout 60 "$H2LOAD" --h1 -H "user-agent: $UA" \
      -c 100 -m 1 -t 6 --duration=5 --warm-up-time=1 \
      "https://bench-sec.local:18444/1k" 2>/dev/null \
    | awk '/^status codes:/ { gsub(/,/,""); for(i=1;i<=NF;i++){ if($i=="2xx") ok=$(i-1); if($i=="4xx") bad=$(i-1) } }
           END { printf "%d %d", ok+0, bad+0 }')
  read -r total fourxx <<<"$burst"
  bench_stop_proxies
  if [ "$fourxx" -gt 0 ] || [ "$total" -lt 1000 ]; then
    echo "FATAL: $1 under load returned $fourxx 4xx and only $total 2xx" >&2
    echo "       something bans at concurrency; the arm would price rejection" >&2
    exit 1
  fi
  echo "preflight ok: $(basename "$1") -> plain $plain, sqli $got, burst ${total} 2xx / ${fourxx} 4xx"
}

parse() {
  awk '
    /^finished in/       { rps=$4; bps=$6 }
    /^requests:/         { gsub(/,/,""); for(i=1;i<=NF;i++){ if($i=="succeeded") ok=$(i-1); if($i=="failed") fail=$(i-1) } }
    /^status codes:/     { gsub(/,/,""); for(i=1;i<=NF;i++){ if($i=="2xx") ok2xx=$(i-1); if($i=="4xx") c4xx=$(i-1) } }
    /^time for request:/ { lat=$(NF-2) }
    END { printf "%s %s %s %s %s %s %s\n",(rps==""?"0":rps),(bps==""?"0":bps),(ok==""?"0":ok),(fail==""?"0":fail),(lat==""?"-":lat),(ok2xx==""?"0":ok2xx),(c4xx==""?"0":c4xx) }
  '
}

preflight /root/bench/conf/pqc-sec-off.toml 200
preflight /root/bench/conf/pqc-sec-on.toml  403

for arm in off on; do
  cfg=/root/bench/conf/pqc-sec-$arm.toml
  csv="$RESULTS_DIR/results-sec-$arm.csv"
  mkdir -p "$OUT/raw-sec-$arm"
  bench_stop_proxies
  bench_spawn_proxy "$BIN" "$cfg"
  echo "proxy,protocol,body,conns,streams,rep,req_per_s,throughput,succeeded,failed,mean_latency,http_2xx,http_4xx" > "$csv"
  for alpn in "http/1.1" h2 h3; do
    for body in empty 1k 64k; do
      for conns in 10 100; do
        streams=1; [ "$alpn" != "http/1.1" ] && streams=10
        extra=(--h1)
        [ "$alpn" = "h2" ] && extra=(--alpn-list=h2)
        [ "$alpn" = "h3" ] && extra=(--alpn-list=h3)
        for rep in $(seq 1 "$REPS"); do
          threads=${GEN_THREADS:-6}
          [ "$threads" -gt "$conns" ] && threads=$conns
          raw="$OUT/raw-sec-$arm/pqc_${alpn//\//-}_${body}_c${conns}_r${rep}.txt"
          taskset -c "$BENCH_GEN_CPUS" timeout $((DUR + WU_PAD + 40)) "$H2LOAD" "${extra[@]}" \
              -H "user-agent: $UA" \
              -c "$conns" -m "$streams" -t "$threads" --duration="$DUR" --warm-up-time="${WU:-$BENCH_WARMUP}" \
              "https://bench-sec.local:18444/$body" > "$raw" 2>/dev/null
          read -r rps bps ok fail lat ok2xx c4xx < <(parse < "$raw")
          echo "pqc,$alpn,$body,$conns,$streams,$rep,$rps,$bps,$ok,$fail,$lat,$ok2xx,$c4xx" >> "$csv"
          printf "  sec-%-3s %-8s %-5s c=%-4s r%s  %11s req/s  lat=%-9s 2xx=%-8s 4xx=%-8s fail=%s\n" \
            "$arm" "$alpn" "$body" "$conns" "$rep" "$rps" "$lat" "$ok2xx" "$c4xx" "$fail"
        done
      done
    done
  done
  bench_stop_proxies
  chmod 444 "$csv" 2>/dev/null
  echo "=== done: $csv ==="
done

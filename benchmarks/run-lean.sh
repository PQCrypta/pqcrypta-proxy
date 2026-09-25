#!/usr/bin/env bash
# HAProxy vs pqcrypta-proxy, four arms, interleaved per cell.
#
#   haproxy      HAProxy 3.2.9, conf/haproxy.cfg                 (unchanged)
#   pqc-current  proxy before the lean-chain fix, conf/pqc-bench.toml
#                -- the arm /proxy-comparison/ has published against
#   pqc-fixed    proxy with the fix, same config  -- what the code fix is worth
#   pqc-lean     proxy with the fix, conf/pqc-bench-lean.toml
#                -- configured to put HAProxy's response on the wire
#
# And two pairs that price our own features rather than compare proxies, so
# they get the same interleaving as the comparison instead of a block design:
#   plumb / feat       conf/pqc-bench.toml against pqc-bench-features.toml --
#                      early hints, priority hints, coalescing, Server-Timing
#   sec-off / sec-on   conf/pqc-sec-{off,on}.toml off 10.99.0.1 -- WAF,
#                      fingerprinting and both rate limiters
#
# And the comparison's own arms on the current build:
#   lean-now   conf/pqc-bench-lean.toml -- like for like with HAProxy
#   pqc-full   conf/pqc-bench-full.toml off 10.99.0.1 -- as deployed
#
# Why a new script rather than run-bench.sh: that one measures each proxy as a
# block, all of A then all of B, and a block design hands run-to-run drift to
# whichever binary ran during a quiet patch. Here every cell measures all four
# arms back to back, and the arm order rotates each rep (a Latin square at
# REPS=4), so each arm spends one rep in each slot -- trap 11, the slot effect,
# measured 3.7% on a null test, cancels instead of landing on one arm.
set -uo pipefail
. /root/bench/benchlib.sh
bench_guard_init

export LD_LIBRARY_PATH=/opt/h3bench/lib
H2LOAD=/opt/h3bench/bin/h2load
OUT=/root/bench/out
RESULTS=${RESULTS:-$OUT/lean-$(date +%Y%m%d_%H%M%S).csv}
HDRS=${RESULTS%.csv}-headers.txt
mkdir -p "$OUT/raw-lean"

REPS=${REPS:-4}
DUR=${DUR:-$BENCH_DUR}
WU=${WU:-$BENCH_WARMUP}

read -r -a ARMS <<< "${ARMS:-haproxy pqc-current pqc-fixed pqc-lean}"
arm_port() { [ "$1" = haproxy ] && echo 18443 || echo 18444; }

# The security arms bind 10.99.0.1 on a dummy interface, because loopback is
# trusted and SecurityState::is_trusted skips the whole per-request security
# block for it -- measured over loopback, security is free. They also send a
# browser User-Agent: waf.block_scanner_uas is on and correctly 403s a tool
# that announces itself, and a run that gets rejected prices the rejection
# path. The rule still runs and still costs what it costs.
BROWSER_UA="Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/140.0.0.0 Safari/537.36"
# Arms whose security path must run: bound off loopback, driven as a browser.
secured() { case "$1" in sec-*|pqc-full) return 0 ;; *) return 1 ;; esac; }
arm_host() { if secured "$1"; then echo bench-sec.local; else echo bench.local; fi; }
arm_ip()   { if secured "$1"; then echo 10.99.0.1; else echo 127.0.0.1; fi; }
set_arm_request() {  # sets ARM_HOST and ARM_HDR for one_run
  ARM_HOST=$(arm_host "$1")
  ARM_HDR=()
  if secured "$1"; then ARM_HDR=(-H "user-agent: $BROWSER_UA"); fi
}
# The build the cost arms measure: the one deployed, copied here by hash.
NOW_BIN=${NOW_BIN:-/root/bench/pqc-93256d06}

start_arm() {
  bench_stop_proxies
  case "$1" in
    haproxy)
      setsid taskset -c "$BENCH_PROXY_CPUS" haproxy -f /root/bench/conf/haproxy.cfg -db \
        </dev/null >>"$OUT/haproxy.log" 2>&1 9>&- &
      local w=0
      until ss -lntupH | grep -q ":18443"; do
        w=$((w+1)); [ $w -gt 20 ] && { echo "FATAL: haproxy never bound" >&2; exit 1; }; sleep 1
      done ;;
    pqc-current) bench_spawn_proxy /root/bench/pqc-current /root/bench/conf/pqc-bench.toml ;;
    pqc-fixed)   bench_spawn_proxy /root/bench/pqc-fixed   /root/bench/conf/pqc-bench.toml ;;
    pqc-lean)    bench_spawn_proxy /root/bench/pqc-fixed   /root/bench/conf/pqc-bench-lean.toml ;;
    # The deployed build, configured like for like.
    pqc-final)   bench_spawn_proxy /root/bench/pqc-final   /root/bench/conf/pqc-bench-lean.toml ;;
    # HTTP/3 throughput work (h3-throughput branch), same config.
    pqc-h3)      bench_spawn_proxy /root/bench/pqc-h3      /root/bench/conf/pqc-bench-lean.toml ;;
    # The deployed build (2b4390f), same config.
    pqc-now)     bench_spawn_proxy /root/bench/pqc-now     /root/bench/conf/pqc-bench-lean.toml ;;
    # What the optional features cost: the plumbing config against the same
    # config with early hints, priority hints, coalescing and Server-Timing on.
    plumb)       bench_spawn_proxy "$NOW_BIN" /root/bench/conf/pqc-bench.toml ;;
    feat)        bench_spawn_proxy "$NOW_BIN" /root/bench/conf/pqc-bench-features.toml ;;
    # What the security stack costs: WAF, fingerprinting and both rate
    # limiters off against on, off a non-loopback address.
    sec-off)     bench_spawn_proxy "$NOW_BIN" /root/bench/conf/pqc-sec-off.toml ;;
    sec-on)      bench_spawn_proxy "$NOW_BIN" /root/bench/conf/pqc-sec-on.toml ;;
    lean-now)    bench_spawn_proxy "$NOW_BIN" /root/bench/conf/pqc-bench-lean.toml ;;
    pqc-full)    bench_spawn_proxy "$NOW_BIN" /root/bench/conf/pqc-bench-full.toml ;;
    *) echo "FATAL: unknown arm $1" >&2; exit 1 ;;
  esac
  # QUIC binds after TCP; give both listeners time to come up.
  sleep 4
  local pid
  pid=$(ss -lntupH | grep -E ":1844[34]" | grep -oP 'pid=\K[0-9]+' | head -1)
  bench_assert_pinning "$pid" "$BENCH_PROXY_CPUS" || exit 1
}

one_run() {  # $1=port $2=alpn $3=path $4=conns $5=streams
  local extra=()
  [ "$2" = "http/1.1" ] && extra=(--h1)
  [ "$2" = "h2" ] && extra=(--alpn-list=h2)
  [ "$2" = "h3" ] && extra=(--alpn-list=h3)
  local threads=${GEN_THREADS:-6}
  [ "$threads" -gt "$4" ] && threads=$4
  taskset -c "$BENCH_GEN_CPUS" timeout $((DUR + WU + 40)) "$H2LOAD" "${extra[@]}" "${ARM_HDR[@]}" \
    -c "$4" -m "$5" -t "$threads" --duration="$DUR" --warm-up-time="$WU" \
    "https://${ARM_HOST:-bench.local}:$1$3" 2>/dev/null
}

parse() {
  awk '
    /^finished in/       { rps=$4; bps=$6 }
    /^requests:/         { gsub(/,/,""); for(i=1;i<=NF;i++){ if($i=="succeeded") ok=$(i-1); if($i=="failed") fail=$(i-1) } }
    /^status codes:/     { gsub(/,/,""); for(i=1;i<=NF;i++) if($i=="2xx") ok2xx=$(i-1) }
    /^time for request:/ { lat_mean=$(NF-2) }
    /^traffic:/          { for(i=1;i<=NF;i++) if($i ~ /headers/) { hdr=$(i-1) } }
    END { printf "%s %s %s %s %s %s %s\n",
            (rps==""?"0":rps), (bps==""?"0":bps), (ok==""?"0":ok), (fail==""?"0":fail),
            (lat_mean==""?"-":lat_mean), (ok2xx==""?"0":ok2xx), (hdr==""?"-":hdr) }'
}

# ── Preflight: what each arm actually puts on the wire ───────────────────
# The whole point of the lean arm is response parity, so prove it before
# spending six hours: capture every arm's headers on h1 and h2, and refuse to
# run if the lean arm still carries a header the proxy adds of its own accord.
: > "$HDRS"
for arm in "${ARMS[@]}"; do
  start_arm "$arm"
  port=$(arm_port "$arm")
  set_arm_request "$arm"
  for v in --http1.1 --http2; do
    h=$(curl -sk "$v" -D- -o /dev/null "${ARM_HDR[@]}" --resolve "$ARM_HOST:$port:$(arm_ip "$arm")" "https://$ARM_HOST:$port/1k")
    { echo "=== $arm $v  ($(printf '%s' "$h" | wc -c) header bytes)"; echo "$h"; } >> "$HDRS"
    printf '%s' "$h" | head -1 | grep -q " 200" || { echo "FATAL: $arm $v did not return 200" >&2; cat "$HDRS" >&2; exit 1; }
  done
  # h3, one request, so a broken QUIC listener fails here and not in hour three.
  read -r _ _ _ _ _ h3ok _ < <(DUR=3 WU=1 one_run "$port" h3 /1k 1 1 | parse)
  [ "${h3ok:-0}" -gt 0 ] || { echo "FATAL: $arm h3 served no 2xx in preflight" >&2; exit 1; }
  # The security arms must be what they claim: a SQLi probe blocked by one
  # and served by the other, and no 4xx under a burst at the concurrency the
  # run uses -- every ban that has ruined this arm was rate- or
  # connection-triggered and invisible to a single request.
  if secured "$arm"; then
    want=200; [ "$arm" = sec-off ] || want=403
    got=$(curl -sk -o /dev/null -w '%{http_code}' --max-time 5 "${ARM_HDR[@]}" \
          --resolve "$ARM_HOST:$port:$(arm_ip "$arm")" \
          "https://$ARM_HOST:$port/1k?id=1%20UNION%20SELECT%20password%20FROM%20users")
    [ "$got" = "$want" ] || { echo "FATAL: $arm answered $got to the SQLi probe, expected $want" >&2; exit 1; }
    burst=$(taskset -c "$BENCH_GEN_CPUS" timeout 60 "$H2LOAD" --h1 "${ARM_HDR[@]}" -c 100 -m 1 -t 6 \
            --duration=5 --warm-up-time=1 "https://$ARM_HOST:$port/1k" 2>/dev/null \
      | awk '/^status codes:/ { gsub(/,/,""); for(i=1;i<=NF;i++){ if($i=="2xx") ok=$(i-1); if($i=="4xx") bad=$(i-1) } }
             END { printf "%d %d", ok+0, bad+0 }')
    read -r b2xx b4xx <<<"$burst"
    if [ "$b4xx" -gt 0 ] || [ "$b2xx" -lt 1000 ]; then
      echo "FATAL: $arm under load returned $b4xx 4xx and only $b2xx 2xx; something bans at concurrency" >&2
      exit 1
    fi
    echo "preflight ok: $arm -> sqli $got, burst $b2xx 2xx / $b4xx 4xx"
  fi
done
bench_stop_proxies
if awk '/^=== (pqc-(lean|final)|lean-now)/{on=1;next} /^===/{on=0} on' "$HDRS" \
     | grep -qiE '^(strict-transport-security|x-ratelimit|alt-svc|x-webtransport-port|x-quantum|content-security-policy|server: pqcrypta)'; then
  echo "FATAL: a like-for-like arm still emits proxy-added headers; see $HDRS" >&2
  exit 1
fi
echo "preflight ok; headers per arm in $HDRS"
grep '^===' "$HDRS"

# ── The matrix ───────────────────────────────────────────────────────────
echo "arm,slot,protocol,body,conns,streams,rep,req_per_s,throughput,succeeded,failed,mean_latency,http_2xx,header_bytes" > "$RESULTS"
n=${#ARMS[@]}
for alpn in "http/1.1" h2 h3; do
  for body in empty 1k 64k; do
    for conns in 10 100; do
      streams=1; [ "$alpn" != "http/1.1" ] && streams=10
      for rep in $(seq 1 "$REPS"); do
        for slot in $(seq 0 $((n - 1))); do
          arm=${ARMS[$(( (slot + rep - 1) % n ))]}
          port=$(arm_port "$arm")
          start_arm "$arm"
          set_arm_request "$arm"
          raw="$OUT/raw-lean/${RUN_TAG:-}${arm}_${alpn//\//-}_${body}_c${conns}_r${rep}.txt"
          one_run "$port" "$alpn" "/$body" "$conns" "$streams" > "$raw"
          read -r rps bps ok fail lat ok2xx hdr < <(parse < "$raw")
          echo "$arm,$slot,$alpn,$body,$conns,$streams,$rep,$rps,$bps,$ok,$fail,$lat,$ok2xx,$hdr" >> "$RESULTS"
          printf "  %-11s s%s %-8s %-5s c=%-4s r%s %11s req/s  lat=%-9s 2xx=%-8s fail=%s\n" \
            "$arm" "$slot" "$alpn" "$body" "$conns" "$rep" "$rps" "$lat" "$ok2xx" "$fail"
        done
      done
    done
  done
done
bench_stop_proxies

expected=$((3 * 3 * 2 * REPS * n))
got=$(( $(grep -c . "$RESULTS") - 1 ))
[ "$got" -eq "$expected" ] || { echo "FATAL: $RESULTS has $got rows, expected $expected" >&2; exit 1; }
echo "rows: $got (as expected)"
chmod 444 "$RESULTS"
echo "=== $RESULTS"

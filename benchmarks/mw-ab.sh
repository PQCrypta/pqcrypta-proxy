#!/usr/bin/env bash
# What does the middleware chain cost, with its features already off?
#
# A: shipped — eight from_fn layers, each boxing a future and cloning itself per
#    request, every one of them consulting a disabled feature and standing aside.
# B: MEASUREMENT ONLY — chain collapsed to a single pass-through layer.
#
# B is not a shippable configuration: no security evaluator, no rate limiting, no
# cache. It exists to price the layering.
#
# B also returns FEWER RESPONSE HEADERS, because the layers that add them are
# gone. Smaller responses are cheaper independently of the layering, so the
# header delta is measured too and the result is an UPPER BOUND on what removing
# the layering alone would buy.
set -uo pipefail
. /root/bench/benchlib.sh
bench_guard_init
export LD_LIBRARY_PATH=/opt/h3bench/lib
H2LOAD=/opt/h3bench/bin/h2load
A=${A:-/root/bench/pqc-mw-A}
B=${B:-/root/bench/pqc-mw-B}
ROUNDS=${ROUNDS:-4}
DUR=${DUR:-10}

hdr_bytes() {  # response header size, so the confound is quantified not assumed
  curl -sk -o /dev/null -D - "https://bench.local:18444/${BODY:-1k}" 2>/dev/null | wc -c
}

cell() {  # $1=bin -> "rps cpu hdrbytes"
  bench_stop_proxies
  bench_spawn_proxy "$1" /root/bench/conf/pqc-bench.toml
  local pid c0 c1 t0 t1 out hb
  pid=$(ss -lntupH 2>/dev/null | grep ':18444' | grep -oP 'pid=\K[0-9]+' | head -1)
  [ -n "$pid" ] || { echo "- - -"; return; }
  hb=$(hdr_bytes)
  c0=$(awk '{print $14+$15}' "/proc/$pid/stat"); t0=$(date +%s.%N)
  out=$(taskset -c "$BENCH_GEN_CPUS" timeout 60 "$H2LOAD" --h1 -c 10 -m 1 -t 6 \
        --duration="$DUR" --warm-up-time=2 "https://bench.local:18444/${BODY:-1k}" 2>/dev/null)
  t1=$(date +%s.%N); c1=$(awk '{print $14+$15}' "/proc/$pid/stat")
  bench_stop_proxies
  echo "$out" | awk -v a="$c0" -v b="$c1" -v s="$t0" -v e="$t1" -v h="$hb" '
    /^finished in/ { rps=$4 }
    END { printf "%s %.0f %s\n", (rps==""?"-":rps), (b-a)/100/(e-s)*100, h }'
}

printf "%-6s %14s %8s %12s\n" binary "req/s" "cpu%" "resp hdr B"
for i in $(seq "$ROUNDS"); do
  if [ $((i % 2)) -eq 1 ]; then order="A B"; else order="B A"; fi
  for who in $order; do
    [ "$who" = A ] && bin=$A || bin=$B
    read -r rps cpu hb < <(cell "$bin")
    printf "%-6s %14s %8s %12s\n" "$who" "$rps" "$cpu" "$hb"
  done
done

#!/usr/bin/env bash
# Instructions-per-request A/B -- the development feedback loop for optimisation
# work, in place of req/s.
#
# Why: on this rig req/s has a run-to-run cv of 21-27%, so a 5% change needs two
# pooled 108-cell passes (most of a day) to see. Instructions retired per request
# has a cv of 0.30% on the same runs, because it measures the WORK the code does
# rather than how fast the machine happened to retire it. A 1% change is visible
# in a single run.
#
# Usage: instr-ab.sh <binA> <binB> [rounds] [config]
# Order flips on round parity so neither binary always runs in the same slot.
set -uo pipefail
while fuser /run/lock/pqc-bench.lock >/dev/null 2>&1; do sleep 30; done
. /root/bench/benchlib.sh
bench_guard_init
export LD_LIBRARY_PATH=/opt/h3bench/lib
A=${1:?usage: instr-ab.sh <binA> <binB> [rounds] [config]}
B=${2:?}
ROUNDS=${3:-4}
CFG=${4:-/root/bench/conf/pqc-bench.toml}
OUT=/root/bench/out/variance
DUR=45; WU=8; WIN=43

measure() {  # $1=binary -> "req_per_s instr_per_req"
  bench_stop_proxies
  bench_spawn_proxy "$1" "$CFG"
  local PROXY out_f rps req ins
  PROXY=$(ss -lntupH 2>/dev/null | grep ':18444' | grep -oP 'pid=\K[0-9]+' | head -1)
  [ -z "$PROXY" ] && { echo "0 0"; return; }
  out_f=$(mktemp)
  ( taskset -c "$BENCH_GEN_CPUS" timeout 140 /opt/h3bench/bin/h2load --alpn-list=h2 \
      -c 10 -m 10 -t 6 --duration=$DUR --warm-up-time=$WU \
      "https://bench.local:18444/1k" >"$out_f" 2>/dev/null ) &
  local LP=$!
  sleep $((WU+1))
  perf stat -p "$PROXY" -e instructions -x, -o "$OUT/ab-p.txt" -- sleep $WIN >/dev/null 2>&1
  wait $LP 2>/dev/null
  rps=$(awk '/^finished in/{print $4}' "$out_f")
  req=$(awk '/^requests:/{print $2}' "$out_f")
  ins=$(awk -F, '/instructions/{print $1}' "$OUT/ab-p.txt" | tr -d ' ')
  rm -f "$out_f"; bench_stop_proxies
  awk -v r="${rps:-0}" -v q="${req:-1}" -v i="${ins:-0}" -v w=$WIN -v d=$DUR \
      'BEGIN{printf "%s %.0f", r, i/(q*w/d)}'
}

echo "A = $A"; echo "B = $B"; echo
printf "%-6s %-6s %12s %14s\n" round arm "req/s" "instr/req"
: > "$OUT/instr-ab.csv"; echo "round,arm,req_per_s,instr_per_req" >> "$OUT/instr-ab.csv"
for i in $(seq "$ROUNDS"); do
  if [ $((i % 2)) -eq 1 ]; then order="A B"; else order="B A"; fi
  for who in $order; do
    [ "$who" = A ] && bin=$A || bin=$B
    read -r rps ipr < <(measure "$bin")
    printf "%-6s %-6s %12s %14s\n" "$i" "$who" "$rps" "$ipr"
    echo "$i,$who,$rps,$ipr" >> "$OUT/instr-ab.csv"
  done
done
awk -F, 'NR>1{n[$2]++; s[$2]+=$4; v[$2","n[$2]]=$4}
  END{ for(a in s){m[a]=s[a]/n[a]}
       for(a in s){ for(k=1;k<=n[a];k++){d=v[a","k]-m[a]; ss[a]+=d*d} }
       printf "\n  A: %.0f instr/req  (cv %.2f%%, n=%d)\n", m["A"], sqrt(ss["A"]/n["A"])/m["A"]*100, n["A"]
       printf "  B: %.0f instr/req  (cv %.2f%%, n=%d)\n", m["B"], sqrt(ss["B"]/n["B"])/m["B"]*100, n["B"]
       printf "  B/A = %.4f  (%+.2f%% instructions per request)\n", m["B"]/m["A"], (m["B"]/m["A"]-1)*100 }' "$OUT/instr-ab.csv"
echo DONE

#!/usr/bin/env bash
# Can we measure "did this change make the code cheaper" WITHOUT fighting the
# rig's throughput noise?
#
# req/s conflates work done with how fast the machine happened to retire it.
# Instructions per request measures only the work. If its run-to-run cv is small
# where req/s is 12-28%, it is the instrument to optimise against -- and req/s
# becomes the final headline number rather than the development feedback loop.
set -uo pipefail
while fuser /run/lock/pqc-bench.lock >/dev/null 2>&1; do sleep 30; done
. /root/bench/benchlib.sh
bench_guard_init
export LD_LIBRARY_PATH=/opt/h3bench/lib
OUT=${OUT:-/root/bench/out/variance}
BIN=${BIN:-/root/bench/pqcrypta-proxy}
mkdir -p "$OUT"
echo "run,req_per_s,requests,instructions,instr_per_req" > "$OUT/instr.csv"
for r in $(seq 6); do
  bench_stop_proxies
  bench_spawn_proxy "$BIN" /root/bench/conf/pqc-bench.toml
  PROXY=$(ss -lntupH 2>/dev/null | grep ':18444' | grep -oP 'pid=\K[0-9]+' | head -1)
  [ -z "$PROXY" ] && { echo "run $r: no listener"; continue; }
  # Count instructions for the PROXY PROCESS only, over the SAME window h2load
  # is measuring. perf must not start until the warm-up is over, or it charges
  # warm-up and idle instructions against measured requests -- which is noise
  # with a trend in it, not a cleaner signal.
  out_f=$(mktemp)
  ( taskset -c "$BENCH_GEN_CPUS" timeout 120 /opt/h3bench/bin/h2load --alpn-list=h2 \
        -c 10 -m 10 -t 6 --duration=45 --warm-up-time=8 \
        "https://bench.local:18444/1k" >"$out_f" 2>/dev/null ) &
  LOADPID=$!
  sleep 9                      # 8s warm-up plus a second of margin
  perf stat -p "$PROXY" -e instructions -x, -o "$OUT/p-$r.txt" -- sleep 43 &
  PERF=$!
  wait $PERF 2>/dev/null
  wait $LOADPID 2>/dev/null
  out=$(cat "$out_f"); rm -f "$out_f"
  # Requests are scaled to the perf window rather than taken raw, since the two
  # cover different spans by design.
  SCALE=$(awk 'BEGIN{printf "%.6f", 43/45}')
  rps=$(echo "$out" | awk '/^finished in/{print $4}')
  req=$(echo "$out" | awk '/^requests:/{print $2}')
  ins=$(awk -F, '/instructions/{print $1}' "$OUT/p-$r.txt" | tr -d ' ')
  req=$(awk -v q="${req:-0}" -v s="$SCALE" 'BEGIN{printf "%.0f", q*s}')
  bench_stop_proxies
  [ -z "${ins:-}" ] && continue
  echo "$r,${rps:-0},${req:-0},$ins,$(awk -v i="$ins" -v q="${req:-1}" 'BEGIN{printf "%.0f", i/q}')" >> "$OUT/instr.csv"
  printf "  run %d: %10s req/s  %s instr/req\n" "$r" "${rps:-0}" "$(awk -v i="$ins" -v q="${req:-1}" 'BEGIN{printf "%.0f", i/q}')"
done
awk -F, 'NR>1{r[NR]=$2; p[NR]=$5; n++; sr+=$2; sp+=$5}
  END{mr=sr/n; mp=sp/n;
      for(i in r){d=r[i]-mr; sdr+=d*d; e=p[i]-mp; sdp+=e*e}
      printf "\n  req/s      : mean %.0f  cv %.1f%%\n", mr, sqrt(sdr/n)/mr*100;
      printf "  instr/req  : mean %.0f  cv %.2f%%\n", mp, sqrt(sdp/n)/mp*100}' "$OUT/instr.csv"
echo DONE

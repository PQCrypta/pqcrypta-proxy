#!/usr/bin/env bash
# Does the delayed ACK cause the HTTP/3 single-stream stall?
#
# A: shipped binary — `ack_eliciting_threshold: 1`, so one ack-eliciting packet
#    never crosses the threshold and the ACK waits for the 25 ms timer.
# B: same tree, threshold 0 — acknowledge every ack-eliciting packet at once.
#
# If the stall is the delayed ACK, B's 1-stream cell jumps from ~385 req/s to
# something near the ~20k the pipelined cells already reach. If it does not move,
# the explanation is wrong and nothing about it should be published.
#
# The pipelined cells are measured too, because that is where acknowledging every
# packet could cost: ACK batching exists to keep CPU down under load, and a fix
# that buys the 1-stream case by losing the 50-stream case is not a fix.
#
# Order flips on round parity: running A first every round confounds the binary
# with the slot, and a null test on this rig put the slot effect at 3.7%.
set -uo pipefail
. /root/bench/benchlib.sh
bench_guard_init
export LD_LIBRARY_PATH=/opt/h3bench/lib
H2LOAD=/opt/h3bench/bin/h2load
A=${A:-/root/bench/pqcrypta-proxy}
B=${B:-/root/bench/pqc-ackthresh0}
ROUNDS=${ROUNDS:-3}
DUR=${DUR:-$BENCH_DUR}

cell() {  # $1=bin $2=streams -> "rps lat cpu"
  bench_stop_proxies
  bench_spawn_proxy "$1" /root/bench/conf/pqc-bench.toml
  local pid c0 c1 t0 t1 out
  pid=$(ss -lntupH 2>/dev/null | grep ':18444' | grep -oP 'pid=\K[0-9]+' | head -1)
  [ -n "$pid" ] || { echo "- - -"; return; }
  c0=$(awk '{print $14+$15}' "/proc/$pid/stat"); t0=$(date +%s.%N)
  out=$(taskset -c "$BENCH_GEN_CPUS" timeout 60 "$H2LOAD" --alpn-list=h3 \
        -c 10 -m "$2" -t 6 --duration="$DUR" --warm-up-time="${WU:-$BENCH_WARMUP}" \
        "https://bench.local:18444/empty" 2>/dev/null)
  t1=$(date +%s.%N); c1=$(awk '{print $14+$15}' "/proc/$pid/stat")
  bench_stop_proxies
  echo "$out" | awk -v a="$c0" -v b="$c1" -v s="$t0" -v e="$t1" '
    /^finished in/ { rps=$4 }
    /^time for request:/ { lat=$(NF-2) }
    END { printf "%s %s %.0f\n", (rps==""?"-":rps), (lat==""?"-":lat), (b-a)/100/(e-s)*100 }'
}

printf "%-8s %-8s %14s %12s %10s\n" binary streams "req/s" "mean lat" "cpu%"
for m in 1 10 50; do
  for i in $(seq "$ROUNDS"); do
    if [ $((i % 2)) -eq 1 ]; then order="A B"; else order="B A"; fi
    for who in $order; do
      [ "$who" = A ] && bin=$A || bin=$B
      read -r rps lat cpu < <(cell "$bin" "$m")
      printf "%-8s %-8s %14s %12s %10s\n" "$who" "$m" "$rps" "$lat" "$cpu"
    done
  done
done

#!/usr/bin/env bash
# Is the rig's instability SMT contention between our own two workers?
#
# Layout today: proxy on CPUs 4-5, which are the two SMT siblings of ONE
# physical core. Two threads then share one core's execution units, L1 and L2 --
# and whether they collide depends on their instantaneous instruction mix, which
# is exactly the kind of thing that goes metastable and holds a mode for
# seconds.
#
#   A: 4,5   two workers, ONE physical core   (current)
#   B: 4,6   two workers, TWO physical cores, siblings 5 and 7 left idle
# Generator moves to 8-11 in both arms so the comparison is fair.
set -uo pipefail
while fuser /run/lock/pqc-bench.lock >/dev/null 2>&1; do sleep 30; done
. /root/bench/benchlib.sh
bench_guard_init
export LD_LIBRARY_PATH=/opt/h3bench/lib
OUT=/root/bench/out/variance
GEN=8-11

run_arm() {  # $1=cpus $2=label
  local vals=()
  for r in 1 2 3 4; do
    bench_stop_proxies
    BENCH_PROXY_CPUS="$1" bench_spawn_proxy "${BIN:-/root/bench/pqcrypta-proxy}" /root/bench/conf/pqc-bench.toml
    local out rps
    out=$(taskset -c "$GEN" timeout 120 /opt/h3bench/bin/h2load --alpn-list=h2 \
          -c 10 -m 10 -t 4 --duration=45 --warm-up-time=10 \
          "https://bench.local:18444/1k" 2>/dev/null)
    rps=$(echo "$out" | awk '/^finished in/{print $4}')
    vals+=("${rps:-0}")
    printf "  %s run %d: %12s req/s\n" "$2" "$r" "${rps:-ERR}"
    bench_stop_proxies
  done
  printf '%s\n' "${vals[@]}" | awk -v l="$2" '
    {v[NR]=$1; s+=$1}
    END{m=s/NR; for(i=1;i<=NR;i++){d=v[i]-m; ss+=d*d}
        mn=v[1]; mx=v[1]; for(i=1;i<=NR;i++){if(v[i]<mn)mn=v[i]; if(v[i]>mx)mx=v[i]}
        printf "  => %s: mean %.0f  cv %.1f%%  spread %.2fx\n", l, m, sqrt(ss/NR)/m*100, mx/mn}'
}

echo "### A: two workers on ONE physical core (CPUs 4-5, SMT siblings) -- current layout"
run_arm 4-5 A
echo "### B: two workers on TWO physical cores (CPUs 4,6; siblings idle)"
run_arm 4,6 B
echo DONE

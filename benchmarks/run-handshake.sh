#!/usr/bin/env bash
# What a handshake costs on each proxy, per key-exchange group, interleaved.
#
# Replaces bench-handshake2.sh, which measured all of HAProxy and then all of
# ours (a block design hands drift to whichever ran in a quiet patch), three
# repetitions each, and ran our proxy with [pqc] disabled -- the hybrid it
# reported only negotiated because that setting was not honoured, a defect
# fixed on 2026-09-24. Here: our proxy runs pqc-bench-pq.toml (post-quantum on,
# OpenSSL provider, so TCP handshakes use the same OpenSSL 3.5 as HAProxy), the
# two proxies alternate within every repetition with the order rotated, and
# the groups compared are ones both offer. X25519 is not among them: our
# listeners never offer it.
#
# One request per connection (-n == -c) so every connection is a fresh
# handshake; the figure is h2load's mean connect time. The negotiated group is
# read off a connection with openssl s_client before each group is measured,
# and the run refuses to continue if it is not the group asked for.
set -uo pipefail
. /root/bench/benchlib.sh
bench_guard_init
export LD_LIBRARY_PATH=/opt/h3bench/lib
H2LOAD=/opt/h3bench/bin/h2load
OUT=/root/bench/out
RES=${RES:-$OUT/handshake-$(date +%Y%m%d_%H%M%S)}
mkdir -p "$RES" "$OUT/raw-hs"
BIN=${BIN:-/root/bench/pqc-93256d06}
CFG=${CFG:-/root/bench/conf/pqc-bench-pq.toml}
# HAProxy with the groups our proxy offers (the comparison config leaves
# them to OpenSSL's default list, which has no SecP384r1MLKEM1024 -- the
# 2026-09-25 run stopped there, correctly, on "negotiated nothing").
HAPROXY_CFG=${HAPROXY_CFG:-/root/bench/conf/haproxy-hs.cfg}
CONNS=${CONNS:-200}
REPS=${REPS:-8}
read -r -a KX <<< "${KX_GROUPS:-secp384r1 X25519MLKEM768 SecP384r1MLKEM1024}"
TAG=${RUN_TAG:-hs-}
exec > >(tee -a "$RES/run.log") 2>&1
echo "results -> $RES  $(date -Is)"

start() {
  bench_stop_proxies
  if [ "$1" = haproxy ]; then
    setsid taskset -c "$BENCH_PROXY_CPUS" haproxy -f "$HAPROXY_CFG" -db \
      </dev/null >>"$OUT/haproxy.log" 2>&1 9>&- &
    local w=0
    until ss -lntupH | grep -q ":18443"; do
      w=$((w+1)); [ $w -gt 20 ] && { echo "FATAL: haproxy never bound" >&2; exit 1; }; sleep 1
    done
  else
    bench_spawn_proxy "$BIN" "$CFG"
  fi
  sleep 4
}
port() { [ "$1" = haproxy ] && echo 18443 || echo 18444; }

negotiated() {  # $1=port $2=group
  timeout 10 openssl s_client -connect "127.0.0.1:$1" -servername bench.local \
      -groups "$2" -tls1_3 </dev/null 2>/dev/null \
    | grep -m1 -oE "Negotiated TLS1.3 group: .*|Peer Temp Key: [^,]*, [^,]*" \
    | sed -E 's/.*group: *//; s/Peer Temp Key: [^,]*, *//'
}

echo "proxy,group,rep,slot,mean_connect_us,handshakes,negotiated" > "$RES/handshake.csv"
ARMS=(haproxy pqc)
for g in "${KX[@]}"; do
  for rep in $(seq 1 "$REPS"); do
    for slot in 0 1; do
      arm=${ARMS[$(( (slot + rep - 1) % 2 ))]}
      p=$(port "$arm")
      start "$arm"
      grp=$(negotiated "$p" "$g")
      if [ -z "$grp" ] || ! printf '%s' "$grp" | grep -qi "$(printf '%s' "$g" | sed 's/^secp384r1$/secp384r1/')"; then
        echo "FATAL: $arm negotiated '${grp:-nothing}' when offered only $g" >&2; exit 1
      fi
      raw="$OUT/raw-hs/${TAG}${arm}_${g}_r${rep}.txt"
      taskset -c "$BENCH_GEN_CPUS" timeout 120 "$H2LOAD" --h1 --groups="$g" \
          -c "$CONNS" -n "$CONNS" -m 1 "https://bench.local:${p}/empty" > "$raw" 2>/dev/null
      read -r us ok < <(awk '
        /^time for connect:/ { v=$4
          if (v ~ /ms$/) { sub(/ms$/,"",v); us=v*1000 } else if (v ~ /us$/) { sub(/us$/,"",v); us=v } else if (v ~ /s$/) { sub(/s$/,"",v); us=v*1000000 } }
        /^requests:/ { gsub(/,/,""); for(i=1;i<=NF;i++) if($i=="succeeded") ok=$(i-1) }
        END { printf "%.0f %d\n", us, ok }' "$raw")
      echo "$arm,$g,$rep,$slot,${us:-0},${ok:-0},$grp" >> "$RES/handshake.csv"
      printf "  %-8s %-20s r%s s%s connect=%8s us  ok=%s  (%s)\n" "$arm" "$g" "$rep" "$slot" "${us:-?}" "${ok:-?}" "$grp"
    done
  done
done
bench_stop_proxies
expected=$(( ${#KX[@]} * REPS * 2 ))
got=$(( $(grep -c . "$RES/handshake.csv") - 1 ))
[ "$got" -eq "$expected" ] || { echo "FATAL: $got rows, expected $expected" >&2; exit 1; }
echo "########## done $(date -Is)  rows=$got"

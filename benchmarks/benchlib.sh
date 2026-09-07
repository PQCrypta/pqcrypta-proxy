#!/usr/bin/env bash
# Shared guards for every benchmark script here.
#
# Each of these exists because its absence produced a confident, wrong number
# that was believed for a while. They live in one file so the scripts cannot
# drift apart again — six of the seven were missing at least one of them.
#
# Source it, then call bench_guard_init.

# ── 1. Descriptor limit ──────────────────────────────────────────────────
# A proxy needs two descriptors per in-flight request, so the stock 1024 caps
# it near 500 concurrent connections whatever its config says: past that it
# answers 5xx while looking perfectly healthy. Measured once at 100 % 5xx —
# 100,829 of 100,829 requests. 65535 is what the production systemd unit sets.
bench_require_fds() {
    ulimit -n 65535 2>/dev/null
    local n; n=$(ulimit -n)
    if [ "$n" -lt 20000 ]; then
        echo "FATAL: fd limit is $n; results would be descriptor-bound, not proxy-bound" >&2
        exit 1
    fi
    echo "fd limit: $n"
}

# ── 0. Where each part of the rig runs ───────────────────────────────────
# SMT siblings are paired on this box -- (0,1) (2,3) (4,5) (6,7) (8,9) (10,11) --
# so a range like "0-1" is ONE physical core, not two. The original layout read
# it as two and put the backend there; nginx saturated it and became the ceiling
# in ten of HAProxy's eighteen cells, which made those cells a measurement of
# nginx. Now:
#
#   cores 0-3    backend, two physical cores, four nginx workers
#   cores 4-5    proxy under test, one physical core, two workers
#   cores 6-11   generator, three physical cores
#
# The proxy gets the smallest share on purpose. The two ceilings this rig has
# actually hit are the generator's and the backend's, and both must stay several
# times clear of whatever the proxy can drive -- a clipped generator or backend
# understates whichever proxy is faster, which is the direction that flatters us.
BENCH_PROXY_CPUS=${BENCH_PROXY_CPUS:-4-5}
BENCH_GEN_CPUS=${BENCH_GEN_CPUS:-6-11}

# ── 2. One run at a time ─────────────────────────────────────────────────
# Two generators on the same cores against the same proxy produced 61 rows for
# 54 cells and a conclusion that had to be retracted. The lock fd is exported
# so children can be told to close it (see bench_spawn_proxy).
BENCH_LOCK_FD=9
bench_take_lock() {
    local lock=${1:-/run/lock/pqc-bench.lock}
    eval "exec ${BENCH_LOCK_FD}>\"\$lock\"" || exit 1
    if ! flock -n "$BENCH_LOCK_FD"; then
        echo "FATAL: another benchmark run holds $lock — refusing to start" >&2
        exit 1
    fi
}

# ── 3. Do not leak the lock into the proxy ───────────────────────────────
# The proxy is started detached and outlives the script. Without closing the
# lock fd in the child, the *proxy* holds the lock forever and every later run
# refuses to start — which looked exactly like the guard working correctly.
bench_spawn_proxy() {  # $1=binary $2=config $3...=extra args
    local bin=$1 cfg=$2; shift 2
    # 9>&- must be written literally: bash parses redirections before parameter
    # expansion, so "${BENCH_LOCK_FD}>&-" is passed to the proxy as an argument
    # rather than closing the descriptor — and the proxy then refuses to start
    # on an unrecognised argument, which reads as "proxy did not start".
    setsid taskset -c "$BENCH_PROXY_CPUS" "$bin" --config "$cfg" "$@" \
        </dev/null >/dev/null 2>&1 9>&- &
    sleep 6
}

# ── 4. Kill only what this harness started ───────────────────────────────
# `pkill -f` matches the invoking command line itself and will take out your own
# shell; worse, this box runs a *production* proxy that must never be touched.
# Match on the bench config path in /proc/PID/cmdline instead.
bench_stop_proxies() {
    local p
    for p in $(ss -lntupH 2>/dev/null | grep -E ":1844[3-5]" | grep -oP 'pid=\K[0-9]+' | sort -u); do
        # Basenames, not the directory: a hand-typed relative --config path
        # slipped through a directory match and left a proxy holding the cores.
        # These names exist only in this harness -- the production node on this
        # box runs /etc/pqcrypta/proxy-config.toml and never matches.
        if tr '\0' ' ' < "/proc/$p/cmdline" 2>/dev/null \
            | grep -qE "pqc-bench|pqc-sec|pqc-streams|pqc-noackfreq|conf/haproxy"; then
            kill "$p" 2>/dev/null
        fi
    done
    # Orphaned generators hold the lock too.
    local h
    for h in $(ps -eo pid,cmd --no-headers | awk '/\/opt\/h3bench\/bin\/h2load/ {print $1}'); do
        kill -9 "$h" 2>/dev/null
    done
    sleep 2
}

# ── 5. A generated config must not silently lose sections ────────────────
# One was built with `split("[[routes]]")[0]`, which dropped the sixteen
# sections declared after the routes block — including every one that turns the
# WAF, fingerprinting and rate limiting off. It started, served 200s, and read
# ~4x faster than the config it was supposed to mirror.
bench_check_config_sections() {  # $1=generated $2=reference
    local missing
    missing=$(comm -23 \
        <(grep -oE '^\[[a-z_0-9]+\]' "$2" | sort -u) \
        <(grep -oE '^\[[a-z_0-9]+\]' "$1" | sort -u) | tr '\n' ' ')
    if [ -n "$missing" ]; then
        echo "FATAL: $1 is missing sections present in $2: $missing" >&2
        echo "       a generated config that has lost sections runs on defaults" >&2
        exit 1
    fi
}


# ── 6. The proxy must actually be on the cores it was given ──────────────
# `taskset` sets an inherited mask, and a process is free to overwrite it.
# HAProxy does: `cpu-map auto:1/1-4 2-5` re-pins its threads after start. That
# line agreed with taskset in the original layout, so it was invisible until the
# layout changed and HAProxy quietly kept twice the cores of the proxy it was
# being compared against. Assert the mask per thread instead of trusting it.
bench_assert_pinning() {  # $1=pid $2=expected cpu list, e.g. 4-5
    local pid=$1 want=$2 expanded="" part lo hi c t got
    for part in ${want//,/ }; do
        if [[ $part == *-* ]]; then
            lo=${part%-*}; hi=${part#*-}
            for ((c=lo; c<=hi; c++)); do expanded="$expanded $c"; done
        else
            expanded="$expanded $part"
        fi
    done
    for t in /proc/"$pid"/task/*; do
        [ -r "$t/status" ] || continue
        got=$(awk '/^Cpus_allowed_list:/ {print $2}' "$t/status")
        for c in $(echo "$got" | tr ',' ' '); do
            if [[ $c == *-* ]]; then
                lo=${c%-*}; hi=${c#*-}
            else
                lo=$c; hi=$c
            fi
            for ((c2=lo; c2<=hi; c2++)); do
                if ! [[ " $expanded " == *" $c2 "* ]]; then
                    echo "FATAL: pid $pid thread ${t##*/} may run on CPU $c2, outside $want" >&2
                    echo "       a proxy on more cores than its opponent is not a comparison" >&2
                    return 1
                fi
            done
        done
    done
    echo "pinning ok: pid $pid within $want"
}

bench_guard_init() {
    bench_require_fds
    bench_take_lock "${1:-/run/lock/pqc-bench.lock}"
    trap 'bench_stop_proxies' EXIT INT TERM
}

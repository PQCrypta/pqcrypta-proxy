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
    setsid taskset -c 2-5 "$bin" --config "$cfg" "$@" \
        </dev/null >/dev/null 2>&1 "${BENCH_LOCK_FD}>&-" &
    sleep 6
}

# ── 4. Kill only what this harness started ───────────────────────────────
# `pkill -f` matches the invoking command line itself and will take out your own
# shell; worse, this box runs a *production* proxy that must never be touched.
# Match on the bench config path in /proc/PID/cmdline instead.
bench_stop_proxies() {
    local p
    for p in $(ss -lntupH 2>/dev/null | grep -E ":1844[3-5]" | grep -oP 'pid=\K[0-9]+' | sort -u); do
        if tr '\0' ' ' < "/proc/$p/cmdline" 2>/dev/null | grep -qE "/root/bench/conf/"; then
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

bench_guard_init() {
    bench_require_fds
    bench_take_lock "${1:-/run/lock/pqc-bench.lock}"
    trap 'bench_stop_proxies' EXIT INT TERM
}

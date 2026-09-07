#!/usr/bin/env python3
"""Sample CPU and RSS of the bench proxy, HAProxy and the generator together.

Server CPU alone is meaningless: a server that looks idle under load is usually a
claim about the *client*. Both sides are sampled in the same tick so the pair can
be read together, which is the only way to tell a proxy ceiling from a generator
ceiling.
"""
import os, sys, time

HZ = os.sysconf("SC_CLK_TCK")
PAGE = os.sysconf("SC_PAGE_SIZE")
INTERVAL = float(sys.argv[2]) if len(sys.argv) > 2 else 2.0
out = open(sys.argv[1], "w", buffering=1)
out.write("ts,role,pid,cpu_pct,rss_mb,threads\n")


def classify(pid):
    try:
        with open(f"/proc/{pid}/cmdline", "rb") as f:
            cmd = f.read().replace(b"\0", b" ").decode("utf8", "replace")
    except OSError:
        return None, None
    if "/opt/h3bench/bin/h2load" in cmd:
        return "generator", cmd
    if "haproxy -f /root/bench/conf/" in cmd:
        return "haproxy", cmd
    # Only the bench proxy, never the production node this box also runs.
    if "pqcrypta" in cmd and "/root/bench/conf/" in cmd:
        return "pqcrypta", cmd
    if cmd.startswith("nginx:"):
        # Workers carry "nginx: worker process" and none of the master's argv, so
        # matching the config path alone samples only the master -- which is idle
        # by design and says nothing about whether the backend is the ceiling.
        if "/root/bench/conf/nginx" in cmd:
            return "nginx-master", cmd
        try:
            with open("/proc/%s/stat" % pid) as f:
                ppid = f.read().rsplit(") ", 1)[1].split()[1]
            with open("/proc/%s/cmdline" % ppid, "rb") as f:
                parent = f.read().replace(b"\0", b" ").decode("utf8", "replace")
        except (OSError, IndexError):
            return None, None
        if "/root/bench/conf/nginx" in parent:
            return "nginx", cmd
        return None, None
    return None, None


def stat(pid):
    try:
        with open(f"/proc/{pid}/stat") as f:
            parts = f.read().rsplit(") ", 1)[1].split()
        # utime+stime are fields 14,15 of the full record: indices 11,12 here.
        ticks = int(parts[11]) + int(parts[12])
        threads = int(parts[17])
        with open(f"/proc/{pid}/statm") as f:
            rss = int(f.read().split()[1]) * PAGE / 1048576
        return ticks, rss, threads
    except (OSError, IndexError, ValueError):
        return None


prev = {}
while True:
    now = time.time()
    seen = set()
    for ent in os.listdir("/proc"):
        if not ent.isdigit():
            continue
        role, _ = classify(ent)
        if role is None:
            continue
        s = stat(ent)
        if s is None:
            continue
        ticks, rss, threads = s
        seen.add(ent)
        if ent in prev:
            pticks, pnow = prev[ent]
            dt = now - pnow
            if dt > 0:
                cpu = (ticks - pticks) / HZ / dt * 100
                out.write("%.1f,%s,%s,%.1f,%.1f,%d\n" % (now, role, ent, cpu, rss, threads))
        prev[ent] = (ticks, now)
    for gone in set(prev) - seen:
        del prev[gone]
    time.sleep(INTERVAL)

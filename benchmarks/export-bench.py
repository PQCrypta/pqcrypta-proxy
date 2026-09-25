#!/usr/bin/env python3
"""export-bench.py RESULT_DIR RUN_TAG OUT_DIR OURS_ARM OURS_COMMIT

Package one interleaved benchmark run for publication: the rows, the window
each row was measured over, and the CPU samples summed per role, so a page can
compute every figure it quotes from the record rather than from a transcript.

  matrix.csv          as written by run-lean.sh, one row per measurement
  backend-ceiling.csv the backend measured with nothing in front of it
  headers.txt         one response per arm and protocol, as served
  windows.csv         arm,protocol,body,conns,rep,start,end,traffic_bytes,group
                      -- end is the raw h2load file's mtime (written when the
                      run exits); start is end minus the measured duration, so
                      the warm-up is excluded; traffic_bytes is h2load's total
                      for the measured window; group is the key exchange
                      h2load reports as the server's temp key
  cpu.csv             ts,role,cpu_pct -- the 2 s samples, summed per role
  conf/*.txt          both proxies' configurations and the backend's, as run
  manifest.json       what ran: binaries and their hashes, versions, pinning,
                      durations -- read from the rig, not typed

A cost run -- one build against itself under two configurations -- sets
BASE to the baseline arm (OURS_ARM is then the variant), BINARY to the binary
both arms ran, and CONFS to the two configurations; the manifest then carries
"cost": {"base", "variant", "configs"} and no HAProxy block.
"""
import csv, glob, hashlib, json, os, re, shutil, subprocess, sys
from collections import defaultdict
from datetime import datetime, timezone

from benchpub import binary_commit, conf_as_run, lib, publishable, sh

d, tag, out, ours, commit = sys.argv[1:6]
DUR = int(os.environ.get("DUR", "60"))
os.makedirs(out, exist_ok=True)
shutil.copy(f"{d}/matrix.csv", f"{out}/matrix.csv")
# A cost run measures one build against itself and has no ceiling run of its own.
# disturbances.txt: anything else that ran on the host during the run, and the
# cells it overlapped. Published with the run and listed in the manifest, so a
# reader can check those cells against their repeats instead of trusting noise.
for src, dst in (("backend-ceiling.csv", "backend-ceiling.csv"), ("matrix-headers.txt", "headers.txt"),
                 ("disturbances.txt", "disturbances.txt")):
    if os.path.exists(f"{d}/{src}"):
        shutil.copy(f"{d}/{src}", f"{out}/{dst}")

pat = re.compile(re.escape(tag) + r"(.+?)_(http-1\.1|h2|h3)_(empty|1k|64k)_c(\d+)_r(\d+)\.txt$")
wins = []
for f in glob.glob(f"{os.path.dirname(d.rstrip('/'))}/raw-lean/{tag}*.txt"):
    m = pat.search(os.path.basename(f))
    if not m:
        continue
    end = os.stat(f).st_mtime
    txt = open(f).read()
    t = re.search(r"^traffic: \S+ \((\d+)\) total", txt, re.M)
    # "Server Temp Key: X25519 253 bits" / "Server Temp Key: ECDH prime256v1 256 bits"
    k = re.search(r"^Server Temp Key: (?:ECDH |DH )?(\S+)", txt, re.M)
    wins.append((m.group(1), m.group(2).replace("http-1.1", "http/1.1"), m.group(3), m.group(4),
                 m.group(5), f"{end - DUR:.1f}", f"{end:.1f}", t.group(1) if t else "",
                 k.group(1) if k else ""))
wins.sort(key=lambda w: float(w[6]))
with open(f"{out}/windows.csv", "w", newline="") as fh:
    w = csv.writer(fh)
    w.writerow(["arm", "protocol", "body", "conns", "rep", "start", "end", "traffic_bytes", "group"])
    w.writerows(wins)

roles = {"nginx": "backend", "nginx-master": "backend"}
by = defaultdict(float)
for r in csv.DictReader(open(f"{d}/resources2.csv")):
    role = roles.get(r["role"], r["role"])
    if role in ("haproxy", "pqcrypta", "generator", "backend"):
        by[(r["ts"], role)] += float(r["cpu_pct"])
with open(f"{out}/cpu.csv", "w", newline="") as fh:
    w = csv.writer(fh)
    w.writerow(["ts", "role", "cpu_pct"])
    for (ts, role), v in sorted(by.items(), key=lambda kv: (float(kv[0][0]), kv[0][1])):
        w.writerow([ts, role, f"{v:.1f}"])
print(f"{len(wins)} windows, {len(by)} cpu samples -> {out}")


def detect_disturbances():
    """What else ran on this host during the run, read from its journal.

    Two sources, so an unattended run cannot miss one: the production proxy's
    own restarts (systemd "Stopping" to "Started"), and anything a deploy step
    logged under the pqc-rig tag as "begin: WHAT" / "end: WHAT" (stage-node.sh
    brackets its copy and on-node --validate that way). Each event is listed
    with the cells whose measured window it overlapped, widened by 5 s.
    """
    if not wins:
        return []
    lo, hi = min(float(w[5]) for w in wins), max(float(w[6]) for w in wins)
    since = datetime.fromtimestamp(lo - 60, timezone.utc).strftime("%Y-%m-%d %H:%M:%S")
    until = datetime.fromtimestamp(hi + 60, timezone.utc).strftime("%Y-%m-%d %H:%M:%S")
    events = []
    stop = None
    for line in sh(f"TZ=UTC journalctl -u pqcrypta-proxy --since '{since}' --until '{until}' "
                   "-o short-unix --no-pager _PID=1").splitlines():
        try:
            ts = float(line.split()[0])
        except (IndexError, ValueError):  # "-- No entries --"
            continue
        if "Stopping pqcrypta-proxy" in line:
            stop = ts
        elif "Started pqcrypta-proxy" in line:
            events.append((stop if stop is not None else ts, ts, "production pqcrypta-proxy restarted"))
            stop = None
    begun = {}
    for line in sh(f"TZ=UTC journalctl -t pqc-rig --since '{since}' --until '{until}' "
                   "-o short-unix --no-pager").splitlines():
        m = re.match(r"(\S+) \S+ pqc-rig(?:\[\d+\])?: (begin|end): (.+)$", line)
        if not m:
            continue
        ts, edge, what = float(m.group(1)), m.group(2), m.group(3).strip()
        if edge == "begin":
            begun[what] = ts
        else:
            events.append((begun.pop(what, ts), ts, what))
    events += [(t, hi, what + " (no end logged)") for what, t in begun.items()]
    lines = []
    for t0, t1, what in sorted(events):
        cells = [f"{tag}{w[0]}_{w[1].replace('/', '-')}_{w[2]}_c{w[3]}_r{w[4]}" for w in wins
                 if float(w[5]) <= t1 + 5 and float(w[6]) >= t0 - 5]
        if not cells:
            continue
        span = datetime.fromtimestamp(t0, timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
        if t1 - t0 >= 1:
            span += ".." + datetime.fromtimestamp(t1, timezone.utc).strftime("%H:%M:%SZ")
        lines.append(f"{span}  {what}   {', '.join(cells)}")
    return lines


if not os.path.exists(f"{d}/disturbances.txt"):
    found = detect_disturbances()
    if found:
        with open(f"{d}/disturbances.txt", "w") as fh:
            fh.write(f"# Activity on this host that was not the benchmark, during run {os.path.basename(d.rstrip('/'))},\n"
                     "# found in its journal by export-bench.py: production proxy restarts and\n"
                     "# pqc-rig-tagged deploy steps. Each line: UTC window, what happened, cells\n"
                     "# whose measured window overlaps it.\n")
            fh.write("\n".join(found) + "\n")
        shutil.copy(f"{d}/disturbances.txt", f"{out}/disturbances.txt")
        print(f"{len(found)} disturbances found in the journal")


confs = os.environ.get("CONFS", "haproxy.cfg,pqc-bench-lean.toml,nginx.conf").split(",")
# The as-deployed arm's configuration is published whenever the manifest names
# it; a three-arm run whose third config was missing would cite a file the
# reader cannot open.
if os.environ.get("FULL_CONFIG") and os.environ["FULL_CONFIG"] not in confs:
    confs.append(os.environ["FULL_CONFIG"])
# When the run began, from its log, for conf_as_run's guard.
_st = re.search(r"results -> \S+\s+(\S+)", open(f"{d}/run.log").read())
run_started = datetime.fromisoformat(_st.group(1)).timestamp() if _st else os.stat(f"{d}/run.log").st_mtime
os.makedirs(f"{out}/conf", exist_ok=True)
for c in confs:
    # Published as .txt: a web server has no business serving .conf, and
    # serves .cfg and .toml with no type at all.
    with open(f"{out}/conf/{c}.txt", "w") as fh:
        fh.write(publishable(conf_as_run(c, d, run_started)))

def backend_cpus():
    """CPUs nginx is pinned to, from its worker_cpu_affinity masks."""
    m = re.search(r"^worker_cpu_affinity\s+([01 ]+);", open("/root/bench/conf/nginx.conf").read(), re.M)
    cpus = sorted({len(mask) - 1 - i for mask in m.group(1).split() for i, bit in enumerate(mask) if bit == "1"})
    return ",".join(map(str, cpus))

binary = os.environ.get("BINARY", f"/root/bench/{ours}")
commit = binary_commit(binary, commit)
base = os.environ.get("BASE")
log = open(f"{d}/run.log").read()
started = re.search(r"results -> \S+\s+(\S+)", log)
finished = re.search(r"########## done (\S+)", log)
hv = sh("haproxy -vv")
manifest = {
    "run": os.path.basename(d.rstrip("/")),
    "started": started.group(1) if started else None,
    "finished": finished.group(1) if finished else None,
    "ours": {
        "arm": ours,
        "commit": commit,
        "binary_sha256": hashlib.sha256(open(binary, "rb").read()).hexdigest(),
        "config": "conf/pqc-bench-lean.toml.txt",
    },
    # A three-arm comparison names its as-deployed arm with FULL_ARM and
    # FULL_CONFIG; OURS_ARM is then the like-for-like one.
    **({"full": {"arm": os.environ["FULL_ARM"],
                 "config": f"conf/{os.environ.get('FULL_CONFIG', '')}.txt"}}
       if os.environ.get("FULL_ARM") else {}),
    **({"cost": {"base": base, "variant": ours,
                 "configs": [f"conf/{c}.txt" for c in confs if c != "nginx.conf"]}} if base else {}),
    "haproxy": {
        "version": re.search(r"HAProxy version (\S+)", hv).group(1),
        "quic": "+QUIC" in hv,
        "ssl": re.search(r"Running on SSL library version : (.+)", hv).group(1).strip(),
        "config": "conf/haproxy.cfg.txt",
    },
    "generator": sh("/opt/h3bench/bin/h2load --version 2>&1 | head -1"),
    # Threads per h2load process: GEN_THREADS, capped at the connection count.
    "generator_threads": int(sh("grep -oP 'threads=\\$\\{GEN_THREADS:-\\K[0-9]+' /root/bench/run-lean.sh") or 0),
    "backend": sh("nginx -v 2>&1").replace("nginx version: ", ""),
    "cpus": {
        "proxy": lib("BENCH_PROXY_CPUS"),
        "generator": lib("BENCH_GEN_CPUS"),
        "backend": backend_cpus(),
    },
    "duration_s": int(lib("BENCH_DUR")),
    "warmup_s": int(lib("BENCH_WARMUP")),
    # From the rows, not the runner's default: a launcher passes REPS.
    "reps": max(int(r["rep"]) for r in csv.DictReader(open(f"{d}/matrix.csv"))),
    "cpu_model": sh("lscpu | sed -n 's/^Model name: *//p'"),
    "threads_per_core": int(sh("lscpu | sed -n 's/^Thread(s) per core: *//p'") or 1),
}
# The security arms' preflight, as the run logged it: what the SQLi probe drew
# and what a five-second burst at a hundred connections returned. The run
# refuses to start unless both are what the arm claims to be.
pre = [{"arm": a, "sqli_status": int(c), "burst_2xx": int(ok), "burst_4xx": int(bad)}
       for a, c, ok, bad in re.findall(r"^preflight ok: (\S+) -> sqli (\d+), burst (\d+) 2xx / (\d+) 4xx$", log, re.M)]
if pre:
    manifest["preflight"] = pre
if os.path.exists(f"{d}/disturbances.txt"):
    manifest["disturbances"] = [
        line.rstrip("\n") for line in open(f"{d}/disturbances.txt")
        if line.strip() and not line.startswith("#")
    ]
json.dump(manifest, open(f"{out}/manifest.json", "w"), indent=2)
print(json.dumps(manifest, indent=2))

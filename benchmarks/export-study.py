#!/usr/bin/env python3
"""export-study.py KIND SOURCE OUT_DIR COMMIT

Package one study for /proxy-comparison/: its rows as CSV, the configurations
it ran, and a manifest read from the rig -- binary hash, versions, pinning,
when it ran, and the load each probe offered, read from the script that ran it.
"kind" in the manifest is what the page's pb_study() finds it by, and what keeps
pb_newest() from ever mistaking it for a comparison run.

  handshake    SOURCE = run-handshake.sh's result directory
  nagle        SOURCE = nd-ab.sh's CSV; its log is the file of the same stamp
  window       SOURCE = window-study.sh's result directory
  consistency  SOURCE = the stamp launch-current.sh gave the probes' logs;
               INSTR=<instr.sh's OUT directory> adds instructions per request

BINARY is the binary the study ran (default /root/bench/pqc-93256d06).

The consistency probes write into one shared directory (out/variance) that
also holds older runs' files, so each file is published only if it was written
inside its own probe's log window; anything else is refused rather than
published under the wrong build.
"""
import csv, glob, hashlib, json, os, re, shutil, subprocess, sys
from datetime import datetime, timezone

from benchpub import binary_commit, conf_as_run, lib, publishable, sh

kind, src, out, commit = sys.argv[1:5]
BENCH = "/root/bench"
binary = os.environ.get("BINARY", f"{BENCH}/pqc-93256d06")
commit = binary_commit(binary, commit)
os.makedirs(f"{out}/conf", exist_ok=True)


def iso(ts):
    return datetime.fromtimestamp(ts, timezone.utc).isoformat(timespec="seconds")


def conf(name):
    # The study's own directory holds a snapshot when there is one; otherwise
    # the rig's file, refused if it changed after the study began.
    rd = src if os.path.isdir(src) else os.path.dirname(src)
    with open(f"{out}/conf/{name}.txt", "w") as fh:
        fh.write(publishable(conf_as_run(name, rd, STUDY_STARTED)))
    return f"conf/{name}.txt"


def script_default(script, var):
    """VAR's default in a script, as `VAR=${VAR:-value}`."""
    m = re.search(r"^" + var + r"=\$\{" + var + r":-([^}]*)\}", open(f"{BENCH}/{script}").read(), re.M)
    return m.group(1) if m else None


def h2load_load(script):
    """The load a probe offers, from its h2load line: protocol, conns, streams, body.

    A value the script takes from a variable is left as the variable's name.
    """
    s = open(f"{BENCH}/{script}").read().replace("\\\n", " ")
    m = re.search(r"(?:h2load|H2LOAD\"?)\s+(?:--alpn-list=(\S+)|--(h1))\s.*?-c (\S+) -m (\S+).*?/(\$?\w+)\"", s)
    num = lambda v: int(v) if v.isdigit() else v.strip('"')
    return {"protocol": m.group(1) or "http/1.1", "conns": num(m.group(3)), "streams": num(m.group(4)),
            "body": m.group(5)}


def born(path):
    """When a file was created: a probe's log is opened as the probe starts."""
    return int(sh(f"stat -c %W {path}"))


def log_window(path):
    """First and last timestamps a run log carries, or its mtime as the end."""
    txt = open(path).read()
    stamps = re.findall(r"\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d[+-]\d\d:\d\d", txt)
    return (stamps[0] if stamps else None), (stamps[-1] if len(stamps) > 1 else iso(os.stat(path).st_mtime))


manifest = {
    "kind": kind,
    "rig": "api3",
    "commit": commit,
    "binary_sha256": hashlib.sha256(open(binary, "rb").read()).hexdigest(),
    "cpu_model": sh("lscpu | sed -n 's/^Model name: *//p'"),
    "threads_per_core": int(sh("lscpu | sed -n 's/^Thread(s) per core: *//p'") or 1),
    "cpus": {"proxy": lib("BENCH_PROXY_CPUS"), "generator": lib("BENCH_GEN_CPUS")},
    "generator": sh("/opt/h3bench/bin/h2load --version 2>&1 | head -1"),
}
hv = sh("haproxy -vv")
haproxy = {"version": re.search(r"HAProxy version (\S+)", hv).group(1),
           "ssl": re.search(r"Running on SSL library version : (.+)", hv).group(1).strip()}

if kind == "handshake":
    STUDY_STARTED = born(f"{src}/run.log")
    shutil.copy(f"{src}/handshake.csv", out)
    started, finished = log_window(f"{src}/run.log")
    manifest.update(run=os.path.basename(src.rstrip("/")), started=started, finished=finished,
                    haproxy={**haproxy, "config": conf("haproxy-hs.cfg")},
                    ours={"config": conf("pqc-bench-pq.toml")},
                    conns=int(script_default("run-handshake.sh", "CONNS")),
                    requests_per_connection=1,
                    measure="h2load mean time for connect, HTTP/1.1, every connection a fresh handshake")
elif kind == "nagle":
    STUDY_STARTED = born(src)
    shutil.copy(src, f"{out}/nagle.csv")
    log = re.sub(r"\.csv$", ".log", src)
    stamp = re.search(r"(\d{8}_\d{6})\.csv$", src).group(1)
    # launch-current.sh names the log by its own stamp, the CSV by nd-ab.sh's.
    if not os.path.exists(log):
        cands = [f for f in glob.glob(f"{os.path.dirname(src)}/nd-ab-*.log")
                 if src in open(f).read()]
        log = cands[0] if cands else None
    if not log:
        sys.exit(f"no log names {src}")
    txt = open(log).read()
    sections = [{"started": t, "question": q.strip()} for q, t in
                re.findall(r"^########## (.+?)\s+(\d{4}-\d\d-\d\dT\S+)$", txt, re.M) if not q.startswith("done")]
    done = re.search(r"^########## done (\S+)", txt, re.M)
    manifest.update(run=f"nagle-{stamp}", started=sections[0]["started"], finished=done.group(1) if done else None,
                    sections=sections,
                    arms={"on": conf("pqc-nd-on.toml"), "off": conf("pqc-nd-off.toml")},
                    duration_s=int(lib("BENCH_DUR")), warmup_s=int(lib("BENCH_WARMUP")),
                    knob="server.tcp_nodelay")
    # nd-h1-dist.sh: h2load's per-request time distribution for one load, both
    # arms, which the CSV reduces to a mean.
    if os.environ.get("DIST"):
        shutil.copy(os.environ["DIST"], f"{out}/distribution.txt")
        manifest["distribution"] = {"file": "distribution.txt", "started": iso(born(os.environ["DIST"])),
                                    "load": h2load_load("nd-h1-dist.sh")}
elif kind == "window":
    STUDY_STARTED = born(f"{src}/run.log")
    shutil.copy(f"{src}/window.csv", out)
    done = re.search(r"^########## done (\S+)", open(f"{src}/run.log").read(), re.M)
    manifest.update(run=os.path.basename(src.rstrip("/")),
                    started=iso(born(f"{src}/run.log")), finished=done.group(1),
                    haproxy={**haproxy, "config": conf("haproxy.cfg")},
                    ours={"arm": "lean-now", "config": conf("pqc-bench-lean.toml")},
                    # The page reads it to flag a run whose backend stalled
                    # 64 KB responses (sendfile + tcp_nopush, before 2026-09-25).
                    backend={"config": conf("nginx.conf")},
                    load=h2load_load("window-study.sh") | {"body": script_default("window-study.sh", "BODY")})
elif kind == "consistency":
    stamp = src
    STUDY_STARTED = born(f"{BENCH}/out/cycles-{stamp}.log")
    probes = {}
    for probe, files in (("cycles", ["perf.csv", "pkts.csv"]), ("stalls", ["perf2.csv", "pkts2.csv"]),
                         ("steal", ["steal.csv"])):
        log = f"{BENCH}/out/{probe}-{stamp}.log"
        lo, hi = born(log), os.stat(log).st_mtime + 5
        for f in files:
            m = os.stat(f"{BENCH}/out/variance/{f}").st_mtime
            if not lo <= m <= hi:
                sys.exit(f"variance/{f} ({iso(m)}) was not written by {probe}-{stamp}.log's run")
        probes[probe] = {"started": iso(lo), "finished": iso(os.stat(log).st_mtime), "load": h2load_load(f"{probe}.sh")}

    def perf(path):
        rows = {}
        for line in open(path):
            p = line.strip().split(",")
            if line.startswith("#") or len(p) < 4:
                continue
            try:
                rows.setdefault(round(float(p[0])), {})[p[3]] = int(p[1])
            except ValueError:  # "<not supported>"
                pass
        return rows

    with open(f"{out}/persecond.csv", "w", newline="") as fh:
        w = csv.writer(fh)
        w.writerow(["probe", "sec", "pkts_per_s", "cycles", "instructions", "cache_misses", "dtlb_load_misses"])
        for probe, pf, kf in (("cycles", "perf.csv", "pkts.csv"), ("stalls", "perf2.csv", "pkts2.csv")):
            d = perf(f"{BENCH}/out/variance/{pf}")
            for line in open(f"{BENCH}/out/variance/{kf}"):
                if not line.strip():
                    continue
                sec, pk = map(int, line.split(","))
                e = d.get(sec, {})
                if "cycles" in e:
                    w.writerow([probe, sec, pk, e["cycles"], e["instructions"], e.get("cache-misses", ""),
                                e.get("dTLB-load-misses", "")])
    shutil.copy(f"{BENCH}/out/variance/steal.csv", out)
    # smt.sh prints its rows; each layout's CPUs are in its header line.
    with open(f"{out}/smt.csv", "w", newline="") as fh:
        w = csv.writer(fh)
        w.writerow(["layout", "cpus", "physical_cores", "run", "req_per_s"])
        cpus = {}
        for line in open(f"{BENCH}/out/smt-{stamp}.log"):
            m = re.match(r"### (\w): two workers on (\w+) physical cores? \(CPUs (\d[\d-]*(?:,\d[\d-]*)*)", line)
            if m:
                cpus[m.group(1)] = (m.group(3), {"ONE": 1, "TWO": 2}[m.group(2)])
            m = re.match(r"\s+(\w) run (\d+):\s+([\d.]+) req/s", line)
            if m:
                w.writerow([m.group(1), cpus[m.group(1)][0], cpus[m.group(1)][1], m.group(2), m.group(3)])
    sl = f"{BENCH}/out/smt-{stamp}.log"
    probes["smt"] = {"started": iso(born(sl)), "finished": iso(os.stat(sl).st_mtime), "load": h2load_load("smt.sh")}
    if os.environ.get("INSTR"):
        shutil.copy(f"{os.environ['INSTR']}/instr.csv", out)
        il = f"{os.environ['INSTR'].rstrip('/')}.log"
        probes["instr"] = {"started": iso(born(il)), "finished": iso(os.stat(il).st_mtime), "load": h2load_load("instr.sh")}
    manifest.update(run=f"consistency-{stamp}", started=min(p["started"] for p in probes.values()),
                    finished=max(p["finished"] for p in probes.values()), probes=probes,
                    ours={"config": conf("pqc-bench.toml")})
else:
    sys.exit(f"unknown kind {kind}")

json.dump(manifest, open(f"{out}/manifest.json", "w"), indent=2)
print(json.dumps(manifest, indent=2))

#!/usr/bin/env python3
"""Every figure /proxy-comparison/ publishes, from the run directory.

One line here per number the page states, so updating the page is mechanical.
The previous version took a single CSV and the page pooled two runs by hand,
which is how three figures drifted out of date without anyone noticing.

Arms, and what each is actually a measurement of:

  run1/run2      HAProxy and PQ Crypta, like-for-like: our extras off, HAProxy
                 doing plain proxying. Pooled -- a single run of this rig cannot
                 resolve better than ~15%.
  depl1/depl2    Our HTTP/3 extras and Server-Timing left on. That is all the old
                 "as-deployed" arm ever varied; it is NOT a security measurement.
  sec-off/sec-on WAF, fingerprinting and rate limiting genuinely off vs on, over
                 a non-loopback address so the security path is not short-
                 circuited. This is the security cost.
"""
import csv, statistics, collections, math, sys, os, glob

d = sys.argv[1] if len(sys.argv) > 1 else "."
PROTOS = ["http/1.1", "h2", "h3"]
BODIES = ["empty", "1k", "64k"]
CONNS = ["10", "100"]


def load(paths, want=None):
    cells = collections.defaultdict(list)
    for p in paths:
        if not os.path.exists(p):
            continue
        for r in csv.DictReader(open(p)):
            if want and r["proxy"] != want:
                continue
            try:
                cells[(r["protocol"], r["body"], r["conns"])].append(float(r["req_per_s"]))
            except (ValueError, KeyError):
                pass
    return cells


def med(cells, k):
    v = cells.get(k)
    return statistics.median(v) if v else None


def geo(a, b):
    """Geometric mean of b/a over all six cells of a protocol."""
    def per(proto):
        rs = []
        for body in BODIES:
            for c in CONNS:
                x, y = med(a, (proto, body, c)), med(b, (proto, body, c))
                if x and y:
                    rs.append(y / x)
        return math.exp(sum(map(math.log, rs)) / len(rs)) if rs else None
    return per


runs = sorted(glob.glob(os.path.join(d, "results-run*.csv")))
depls = sorted(glob.glob(os.path.join(d, "results-depl*.csv")))
hap = load(runs, "haproxy")
pqc = load(runs, "pqc")
depl = load(depls, "pqc")
secoff = load([os.path.join(d, "results-sec-off.csv")], "pqc")
secon = load([os.path.join(d, "results-sec-on.csv")], "pqc")

n = len(hap.get(("h2", "1k", "10"), []))
print("pooled from %d run(s), %d measurements per cell\n" % (len(runs), n))

print("=== full matrix (median of %d) ===" % n)
print("proto    body   conns    haproxy        pqc   pqc/HAP")
for p in PROTOS:
    for b in BODIES:
        for c in CONNS:
            h, q = med(hap, (p, b, c)), med(pqc, (p, b, c))
            if h and q:
                print("%-9s%-7s%-7s%10.0f %10.0f    %5.2fx" % (p, b, c, h, q, q / h))

print("\n=== TABLE: req/s (1k, c=10) | 64k c=100 ratio | geomean gap ===")
gap = geo(pqc, hap)
for p in PROTOS:
    h1k, q1k = med(hap, (p, "1k", "10")), med(pqc, (p, "1k", "10"))
    r64 = med(pqc, (p, "64k", "100")) / med(hap, (p, "64k", "100"))
    g = gap(p)
    lead = "level, %.2fx" % g if g < 1.05 else "HAProxy %.1fx" % g
    print("  %-9s %9.0f -> %9.0f | 64k %.2fx | gap %s" % (p, h1k, q1k, r64, lead))

print("\n=== every 64k cell, ours over theirs; and any cell where we lead ===")
for p in PROTOS:
    vals = ["%s c=%s %.2fx" % (p, c, med(pqc, (p, "64k", c)) / med(hap, (p, "64k", c))) for c in CONNS]
    print("  " + "   ".join(vals))
lead = [(p, b, c, med(pqc, (p, b, c)) / med(hap, (p, b, c)))
        for p in PROTOS for b in BODIES for c in CONNS
        if med(hap, (p, b, c)) and med(pqc, (p, b, c)) > med(hap, (p, b, c))]
print("  cells where we lead: " + (", ".join("%s %s c=%s %.2fx" % x for x in lead) or "none"))

print("\n=== consistency: spread within a cell, by body size ===")
agg = collections.defaultdict(list)
for name, cells in (("haproxy", hap), ("pqc", pqc)):
    for k, v in cells.items():
        if len(v) > 1:
            agg[(name, k[1])].append((max(v) - min(v)) / statistics.median(v) * 100)
for b in BODIES:
    row = ["%s median %.1f%% worst %.1f%%" % (px, statistics.median(agg[(px, b)]), max(agg[(px, b)]))
           for px in ("haproxy", "pqc")]
    print("  %-6s %s" % (b, "   |   ".join(row)))

print("\n=== degradation across reps (r3/r1) ===")
per = collections.defaultdict(dict)
for p in runs:
    for r in csv.DictReader(open(p)):
        per[(p, r["proxy"], r["protocol"], r["body"], r["conns"])][int(r["rep"])] = float(r["req_per_s"])
for px in ("haproxy", "pqc"):
    rr = [v[3] / v[1] for k, v in per.items() if k[1] == px and len(v) == 3]
    print("  %-8s median %.2f  min %.2f  (n=%d)" % (px, statistics.median(rr), min(rr), len(rr)))

if len(runs) > 1:
    print("\n=== precision floor: identical binary, run 1 vs run %d ===" % len(runs))
    for px, want in (("haproxy", "haproxy"), ("pqc", "pqc")):
        a, b = load([runs[0]], want), load([runs[-1]], want)
        rs = [med(b, k) / med(a, k) for k in a if med(a, k) and med(b, k)]
        print("  %-8s per-cell movement %.2fx to %.2fx" % (px, min(rs), max(rs)))
    print("  per-run protocol gaps:")
    for i, r in enumerate(runs, 1):
        g = geo(load([r], "pqc"), load([r], "haproxy"))
        print("    run %d: %s" % (i, " / ".join("%.1fx" % g(p) for p in PROTOS)))

if depl:
    print("\n=== HTTP/3 extras + Server-Timing: cost of leaving them on ===")
    print("    (pqc arm has them off; depl arm has them on -- geomean off/on)")
    g = geo(depl, pqc)
    for p in PROTOS:
        cellwise = [med(pqc, (p, b, c)) / med(depl, (p, b, c))
                    for b in BODIES for c in CONNS if med(depl, (p, b, c))]
        if cellwise:
            print("  %-9s %.2fx   per-cell %.2fx to %.2fx" % (p, g(p), min(cellwise), max(cellwise)))

if secoff and secon:
    print("\n=== WAF + fingerprinting + rate limiting: cost, off a non-loopback address ===")
    g = geo(secon, secoff)
    for p in PROTOS:
        cellwise = [med(secoff, (p, b, c)) / med(secon, (p, b, c))
                    for b in BODIES for c in CONNS if med(secon, (p, b, c))]
        print("  %-9s %.2fx   per-cell %.2fx to %.2fx" % (p, g(p), min(cellwise), max(cellwise)))
    print("  absolute, 1k c=10:  off %.0f  on %.0f req/s"
          % (med(secoff, ("h2", "1k", "10")), med(secon, ("h2", "1k", "10"))))

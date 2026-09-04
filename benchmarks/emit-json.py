#!/usr/bin/env python3
"""Emit the headline figures as JSON for the page updater.

Per protocol: HAProxy's best cell, ours in each arm at the same cell, and the
geometric-mean gap across all six cells of that protocol. The headline uses the
empty-body c=10 cell (pure per-request cost, no data movement) and the gap uses
the geometric mean, so one flattering cell cannot become the story.
"""
import csv, statistics, collections, math, json

OUT = "/root/bench/out"

def load(path, want=None):
    agg = collections.defaultdict(list)
    try:
        for r in csv.DictReader(open(path)):
            if want and r["proxy"] != want:
                continue
            try:
                agg[(r["protocol"], r["body"], r["conns"])].append(float(r["req_per_s"]))
            except (ValueError, KeyError):
                pass
    except FileNotFoundError:
        pass
    return agg

hap   = load(f"{OUT}/results.csv", "haproxy")
depl  = load(f"{OUT}/results-pqc2.csv", "pqc")
plumb = load(f"{OUT}/results-plumbing.csv", "pqc")

def med(rows):
    return statistics.median(rows) if rows else None

def geo(a, b, proto):
    rs = []
    for body in ["empty", "1k", "64k"]:
        for c in ["10", "100"]:
            k = (proto, body, c)
            x, y = med(a.get(k, [])), med(b.get(k, []))
            if x and y:
                rs.append(y / x)
    return math.exp(sum(math.log(r) for r in rs) / len(rs)) if rs else None

def fmt(v):
    return f"{v:,.0f} req/s" if v else "-"

out = {}
for tag, proto in [("h1", "http/1.1"), ("h2", "h2"), ("h3", "h3")]:
    k = (proto, "empty", "10")
    h, d, pl = med(hap.get(k, [])), med(depl.get(k, [])), med(plumb.get(k, []))
    # Gap is quoted against the plumbing arm: the fair like-for-like comparison.
    g = geo(hap, plumb, proto)
    out[tag] = {
        "hap": fmt(h), "depl": fmt(d), "plumb": fmt(pl),
        "gap": f"{1/g:.1f}" if g else "-",
    }
print(json.dumps(out, indent=1))

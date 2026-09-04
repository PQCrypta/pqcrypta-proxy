#!/usr/bin/env python3
"""Final benchmark table: HAProxy vs PQ Crypta, both arms.

Three files, three different things:
  results.csv           HAProxy (and the superseded pqc pass) at ulimit 65535
  results-pqc2.csv      PQ Crypta as-deployed  — defaults on, fingerprint fix in
  results-plumbing.csv  PQ Crypta plumbing-only — everything HAProxy lacks, off

"As-deployed" is the number to lead with: it is what an operator actually runs.
"Plumbing" isolates the proxy path so the two products are doing comparable work.
"""
import csv, statistics, collections, math

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

hdr = (f'{"protocol":<9}{"body":<6}{"conn":<6}{"HAProxy":>11}{"PQC deployed":>14}'
       f'{"PQC plumbing":>14}{"depl/HAP":>10}{"plumb/HAP":>11}')
print(hdr); print("-" * len(hdr))

for proto in ["http/1.1", "h2", "h3"]:
    for body in ["empty", "1k", "64k"]:
        for c in ["10", "100"]:
            k = (proto, body, c)
            h, d, pl = med(hap.get(k, [])), med(depl.get(k, [])), med(plumb.get(k, []))
            if h is None:
                continue
            ds = f"{d/h:.2f}x" if d else "-"
            ps = f"{pl/h:.2f}x" if pl else "-"
            print(f'{proto:<9}{body:<6}{c:<6}{h:>11,.0f}{(d or 0):>14,.0f}'
                  f'{(pl or 0):>14,.0f}{ds:>10}{ps:>11}')

def geo(a, b, proto):
    rs = []
    for body in ["empty", "1k", "64k"]:
        for c in ["10", "100"]:
            k = (proto, body, c)
            x, y = med(a.get(k, [])), med(b.get(k, []))
            if x and y:
                rs.append(y / x)
    return math.exp(sum(math.log(r) for r in rs) / len(rs)) if rs else None

print()
print("Geometric mean vs HAProxy (higher is better for us):")
for proto in ["http/1.1", "h2", "h3"]:
    d, p = geo(hap, depl, proto), geo(hap, plumb, proto)
    ds = f"{d:.2f}x" if d else "  -  "
    ps = f"{p:.2f}x" if p else "  -  "
    inv = f"HAProxy {1/d:.1f}x faster" if d else ""
    print(f"  {proto:<9} as-deployed {ds}   plumbing-only {ps}   ({inv})")

print()
print("What turning our own extras off is worth:")
for proto in ["http/1.1", "h2", "h3"]:
    g = geo(depl, plumb, proto)
    if g:
        print(f"  {proto:<9} {g:.2f}x")

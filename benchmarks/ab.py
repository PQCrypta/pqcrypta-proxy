import sys, statistics
A, B = [], []
for line in open("/root/bench/out/ab.log"):
    parts = line.split()
    if len(parts) == 2 and parts[0] in ("A", "B"):
        try:
            (A if parts[0] == "A" else B).append(float(parts[1]))
        except ValueError:
            pass
if not A or not B:
    print("no data yet"); sys.exit()

def summary(name, v):
    v = sorted(v)
    print(f"  {name:<22} n={len(v):<3} median={statistics.median(v):>10,.0f}  "
          f"min={v[0]:>10,.0f}  max={v[-1]:>10,.0f}")

print("Interleaved A/B on the corrected 60-route config")
summary("A route fix only", A)
summary("B all three fixes", B)
ma, mb = statistics.median(A), statistics.median(B)
print(f"\n  B/A on medians: {mb/ma:.2f}x")
# A rank-based check, because these distributions are wide and skewed: how often
# does a random B run beat a random A run? 0.5 would mean no difference at all.
wins = sum(1 for b in B for a in A if b > a)
print(f"  P(random B > random A) = {wins/(len(A)*len(B)):.2f}  (0.50 = indistinguishable)")

import csv, statistics, collections
a = collections.defaultdict(list)
for r in csv.DictReader(open("/root/bench/out/handshake/results.csv")):
    try:
        a[(r["proxy"], r["curve"])].append(float(r["mean_connect_us"]))
    except (ValueError, KeyError):
        pass
print("proxy       classical   X25519MLKEM768   PQC costs")
for p in ["haproxy", "pqc"]:
    c = statistics.median(a[(p, "X25519")])
    q = statistics.median(a[(p, "X25519MLKEM768")])
    print(f"{p:<11}{c/1000:>7.1f}ms{q/1000:>14.1f}ms{q/c:>11.2f}x")
hc = statistics.median(a[("haproxy", "X25519")]);         pc = statistics.median(a[("pqc", "X25519")])
hq = statistics.median(a[("haproxy", "X25519MLKEM768")]); pq = statistics.median(a[("pqc", "X25519MLKEM768")])
print()
print(f"PQ Crypta vs HAProxy, classical handshake: {pc/hc:.2f}x")
print(f"PQ Crypta vs HAProxy, PQC handshake:       {pq/hq:.2f}x")

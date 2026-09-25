# Benchmark harness

The rig behind the throughput and handshake figures published at
<https://pqcrypta.com/proxy-comparison/>. It is here so the numbers can be
re-run rather than taken on trust.

## Measuring an optimisation: use `instr-ab.sh`, not req/s

**Throughput on this rig is not a steady instrument.** Measured on the build of
2026-09-24 (`cycles.sh`, `stalls.sh`, `steal.sh`, `smt.sh`, `instr.sh`; the
per-second data is published as `runs/consistency-*` beside /proxy-comparison/):
throughput sits in a slow mode near 129,000 packets/s or a fast one near 187,000
for up to 100 s at a stretch. Across the two, cycles per second are no lower in
the slow mode and instructions per packet agree to 0.04 %; what changes is IPC,
1.14 in the fast mode and 0.74 in the slow. CPU steal is exactly zero in every
second, dTLB misses are about 2 per packet against ~59,000 cycles, and moving
the two workers onto separate physical cores raised throughput 5 % while
*widening* the scatter. The one counter that moves with the mode is cache
misses, 19 % more per packet in the slow mode. The machine's speed varies; the
work does not.

So measure the work (`instr.sh`, six fresh runs, same build):

| metric | cv over 6 fresh runs |
|---|---|
| req/s | **17.4 %** |
| instructions per request | **0.77 %** |

```sh
./instr-ab.sh <binA> <binB> [rounds] [config]
```

Counts instructions retired by the proxy process over the *same* window the
generator is measuring, and reports instructions per request for each binary.
At that spread a 1 % change stands two standard errors clear in about five
rounds of A/B (~9 minutes); by throughput it would take over two thousand.

Two things this does not replace. It measures instructions, so a change that
trades instructions for cache behaviour or syscalls will not show up correctly
— check `perf stat` for cycles and cache-misses too. And the published
comparison against HAProxy is still req/s, because that is what an operator
gets; this is the development feedback loop, not the headline.

**Align the windows.** `perf` must not start until the generator's warm-up is
over. Charging warm-up and idle instructions against measured requests took the
cv from 0.30 % to 3.98 % on an earlier build — still far better than req/s, but
with a trend in it that reads like a real effect.

## Layout

Everything runs on one machine with CPU pinning — a WAN path measures the link,
not the proxy. Twelve logical CPUs, and **that is six physical cores**: SMT
siblings are paired `(0,1) (2,3) (4,5) (6,7) (8,9) (10,11)`, so a range like
`0-1` is *one* core, not two.

| CPUs | physical cores | what |
|---|---|---|
| 0–3 | 2 | nginx backend (`conf/nginx.conf`), four workers, three fixed bodies from memory |
| 4–5 | 1 | proxy under test, two workers |
| 6–11 | 3 | `h2load` generator |

The proxy under test gets the smallest share deliberately. The two ceilings this
rig has actually hit are the generator's and the backend's, and a run is only
worth publishing if both stay several times clear of whatever the proxy can
drive — a clipped generator or backend understates *whichever proxy is faster*,
which is the direction that flatters us.

The backend's own ceiling is measured by `bench-backend.sh` with nothing in
front of it, before every comparison run, and published with the run as
`backend-ceiling.csv`; the page reads each cell against it.

**The backend runs nginx's defaults for file serving: `sendfile off`.** Until
2026-09-25 it ran `sendfile on; tcp_nopush on;`, and that combination holds
about one 64 KB response in three hundred for the peer's 40 ms delayed-ACK
timer: request time max 42 ms and sd 2.4 ms with nothing in front of nginx at
all, against ~2 ms and under 0.12 ms with sendfile off (`tail-h1.sh` shows it
through either proxy). Both proxies inherited the stall on every 64 KB fetch,
and a fixed stall costs the faster one proportionally more — the direction guard
6 warns about. Runs measured the old way are flagged on the page, which reads
the published `nginx.conf.txt`.

## The arms, and what each actually varies

`run-lean.sh` measures every arm of a run interleaved within each cell, with
the order rotated each repetition (a Latin square at `REPS=4`), so the slot
effect cancels instead of landing on one arm:

- **`haproxy`** — `conf/haproxy.cfg`, unchanged.
- **`lean-now`** — `conf/pqc-bench-lean.toml`: our proxy configured to do what
  HAProxy's configuration does and no more — no added headers, no Alt-Svc on
  TCP, the backend's `Server` header passed through, no compression. The
  preflight refuses to run if its responses carry a header the proxy adds of its
  own accord.
- **`pqc-full`** — `conf/pqc-bench-full.toml` off `10.99.0.1`: as deployed, WAF
  in block mode, TLS-layer fingerprinting, both rate limiters, the optional
  features and post-quantum key exchange.
- **`plumb` / `feat`** — `conf/pqc-bench.toml` against
  `pqc-bench-features.toml`: what early hints, priority hints, request
  coalescing and Server-Timing cost, one build against itself.
- **`sec-off` / `sec-on`** — `conf/pqc-sec-off.toml` / `pqc-sec-on.toml`, both
  on `10.99.0.1` on a dummy interface, because RFC1918 is *not* implicitly
  trusted (only loopback and explicit `trusted_internal_cidrs`), so the security
  path actually runs. Limits are raised far above the offered load on purpose:
  the cost under test is *evaluating* a request, and a run that trips the
  limiter measures the rejection path instead. The preflight refuses to start
  unless a SQLi probe returns 403 on the on-arm and 200 on the off-arm, a plain
  GET returns 200 on both, **and** a five-second burst at a hundred connections
  returns zero 4xx on both. That last check exists because two full arms were
  measured and thrown away after a preflight of one request passed and the run
  then tripped a ban it could never have reached — the connection rate limiter
  the first time, the fingerprint suspicious-rate threshold the second. A guard
  that tests a different workload from the one it guards is not a guard.

Set up the interface once:

```sh
ip link add pqcbench0 type dummy
ip addr add 10.99.0.1/24 dev pqcbench0
ip link set pqcbench0 up
echo '10.99.0.1 bench-sec.local' >> /etc/hosts
```

## Running, and publishing

```sh
./bench-backend.sh      # the backend's own ceiling — run this first, always
ARMS="haproxy lean-now pqc-full" RUN_TAG=cmp- RESULTS=out/cmp/matrix.csv REPS=6 ./run-lean.sh
./run-handshake.sh      # connect time per key-exchange group, both proxies interleaved
./nd-ab.sh              # TCP_NODELAY on vs off (server.tcp_nodelay)
./window-study.sh       # 10 s / 2 s against 60 s / 15 s windows, both proxies
./cycles.sh; ./stalls.sh; ./steal.sh; ./smt.sh; ./instr.sh   # the consistency probes
./launch-rerun.sh       # the published comparison, both cost pairs and the Nagle study, then packaged
```

Nothing the page says is typed. A run is packaged by `export-bench.py`
(comparison and cost runs) or `export-study.py KIND` (`handshake`, `nagle`,
`window`, `consistency`) into a directory the page reads as it renders
(`includes/proxy-bench.php`): the rows as CSV, the configurations as run, and a
manifest read from the rig — binary hash, the commit from the binary's own
`--version`, versions, pinning, the preflight's results and anything else that
ran on the host during the run. The page picks the newest run of each kind by
its start time and words every claim from the data, so a new run replaces the
published one without an edit. `pagefigs2.py` computed the page's figures from
a transcript before this and is kept only for the runs it produced; the
scripts it read (`run-bench.sh`, `run-pqc-only.sh`, `run-sec.sh`,
`bench-handshake2.sh`) block-measured each arm and are superseded by
`run-lean.sh` and `run-handshake.sh`.

`h2load` must be built with HTTP/3 (ngtcp2 + nghttp3 + `ngtcp2_crypto_ossl`);
the packaged one has no h3, and driving the three protocols with three different
clients would make them incomparable.

## Guards, and why each exists

`benchlib.sh` holds them, because six of the seven scripts were missing at least
one and every absence had already produced a confident wrong number.

1. **Descriptor limit.** A proxy needs two descriptors per in-flight request, so
   the stock 1024 caps it near 500 concurrent connections whatever its config
   says — past that it answers 5xx while looking healthy. Measured once at
   **100 % 5xx, 100,829 of 100,829 requests**.
2. **One run at a time.** Two generators on the same cores against the same
   proxy produced 61 rows for 54 cells and a conclusion that had to be retracted.
3. **Do not leak the lock into the proxy.** The proxy is started detached and
   outlives the script; without `9>&-` it inherits the lock fd and holds it
   forever, which looks exactly like the guard working correctly.
4. **Kill only what the harness started.** `pkill -f` matches the invoking
   command line and will take out your own shell — and this box runs a
   *production* proxy that must never be touched. Match the bench config path in
   `/proc/PID/cmdline` instead. This applies to *waiting* too: a wait loop built
   on `pgrep -f` never terminates, because it matches itself.
5. **A generated config must not silently lose sections.** One was built with
   `split("[[routes]]")[0]`, which dropped the sixteen sections declared after
   the routes block — including every one that turns the WAF, fingerprinting and
   rate limiting off. It started, served 200s, and read ~4× faster than the
   config it was meant to mirror.
6. **The proxy must actually be on the cores it was given.** `taskset` sets an
   inherited mask and a process is free to overwrite it. HAProxy does:
   `cpu-map auto:1/1-N` re-pins its threads after start. That line agreed with
   `taskset` in the original layout, so it was invisible — until the layout
   changed and HAProxy silently kept **twice the cores** of the proxy it was
   being compared against, inside a benchmark whose entire output is a ratio.
   `bench_assert_pinning` now checks every thread's `Cpus_allowed_list` after
   each proxy starts. It was caught only because the sampler read HAProxy at
   **311 % against a 200 % budget**; a number above its own budget is the only
   reason anyone would have looked.
7. **Thread count must match the CPUs.** HAProxy refuses to be measured
   honestly at four threads on two CPUs — it emits *"severe performance
   degradation"* — so both proxies run two workers on the one physical core they
   are given. Benchmarking a product in a configuration it warns about is not a
   comparison.

## Watching resources is part of the method, not a nicety

`ressample.py` samples the proxy, the backend and the generator **in the same
tick**, because either alone is meaningless. Three published defects came out of
reading them together:

- A server that looks idle under load is a claim about the **client** until
  proven otherwise. Per-thread CPU read 248 % of 400 % under h3 and drove hours
  of investigation into what made the workers wait; the answer was that the
  single-threaded generator had never been able to push hard enough. Threaded,
  the same measurement reads 384 %.
- A server reading **above** its own budget is a pinning bug (guard 6).
- A backend reading at its budget is the ceiling. nginx sat at 198–201 % of
  200 % in ten of HAProxy's eighteen cells, which made those cells a measurement
  of nginx: HAProxy posted 138,731 req/s on h2 empty against a backend that
  tops out at 138,508 with no proxy in the path at all.

A filter that stops matching reports "idle", which is the one answer a resource
sample must never invent — `ressample.py` matches the backend by its config
*directory*, having once silently stopped matching when the filename changed.

8. **A cell must be long enough to reach steady state.** Ten seconds is not.
   `window-study.sh`, 2026-09-25, six runs of each proxy per window, alternating:
   our coefficient of variation is **9.5 % at 10 s / 2 s against 3.6 % at 60 s /
   15 s**, HAProxy's 2.8 % and 1.1 %, and the short window reads our proxy
   **19 % higher** while moving HAProxy 0.5 %. Earlier, on a slower build: ~14 %
   at 10 s and at 30 s, ~5–8 % at 60 s. The short window measures a transient: the 10-second
   distribution is bimodal, mostly ~18k req/s with jumps to ~25k, and the mode
   persists for a whole 30-second run. It is a harness fix rather than a thumb on
   the scale precisely because it improves HAProxy too — a duration that
   stabilised only our own numbers would be the opposite. It also appears to
   understate us: one 64 KB cell moves 18.0k → 19.9k req/s on the longer window.
   `BENCH_DUR` / `BENCH_WARMUP` default to 60/15. Ruled out before landing on it:
   the per-cell proxy restart (one instance serving every cell still spreads
   1.40×) and tokio work-stealing/SMT (one worker pinned to one hyperthread only
   moves cv 14.1 % → 10.3 %).

   The cost is time. A full matrix pass is 108 measurements at 75 s, so ~2.5
   hours, and two passes plus a backend ceiling is most of a day. Anything that
   needs to resolve better than ~15 % has to pay it.

9. **The proxy under test must be the one actually listening.**
   `bench_stop_proxies` used to kill and sleep two seconds. At 60-second cells the
   old proxy holds its socket longer than that, the next one fails to bind, and
   **the old one keeps serving** — so every arm of an A/B measures the first
   binary and the comparison reads 1.00×. That is the worst failure mode
   available: it does not error, it agrees with you. Caught only because all three
   arms of a three-way reported identical response-header bytes, which is possible
   only if they were one process. The stop now waits for the socket to go,
   escalates to `SIGKILL` at 10 s and aborts at 20 s; `bench_spawn_proxy` then
   asserts that the process listening is the binary it just started and aborts
   naming both if not.

10. **No run writes a shared, reusable path.** Every runner took its output file
    name as a constant — `out/results.csv`, `out/results-pqc2.csv` — and the
    caller copied it somewhere durable afterwards. That leaves a window: the next
    run truncates the fixed name, and anything copying it in the meantime saves a
    partial file *over* the good one. It happened twice in one session to the same
    file, and both times the data survived only because the runner's log happened
    to contain every cell.

    Output paths are now a parameter (`RESULTS`, `RESULTS_DIR`) with a timestamped
    default, so two runs cannot collide and there is no live file worth copying;
    the callers write straight into the results directory and copy nothing. Each
    runner then **asserts its own row count** and fails if the file is short,
    because a truncated CSV analyses cleanly and produces a plausible table from
    half the data. Note that `chmod 444` on a finished file is a hint and not a
    guard: this harness runs as root, and root ignores the permission bits.

11. **Record what else ran.** The rig is a production host: a deploy restarts
    the proxy there and an on-node `--validate` burns CPU beside the generator.
    `export-bench.py` reads the host's journal for production-proxy restarts and
    for steps logged as `logger -t pqc-rig "begin: WHAT"` / `"end: WHAT"`, and
    lists each with the cells whose window it overlapped. Tag anything you run
    on the rig during a queue that way.
12. **Publish the configuration that ran, not the one there now.** The export
    reads `RUN/conf/NAME` when the run has a snapshot, and otherwise refuses a
    rig file modified after the run started. It once published the fixed
    backend config under a run measured with the old one.
13. **Count repetitions from the rows.** A launcher passes `REPS=6`; the
    manifest took the runner's default of 4 and the page said "median of 4" for
    a week.

## Measurement-only builds

Three cargo features exist to answer questions a profile cannot. None is ever
built by `scripts/deploy.sh`, and each produces a binary that must not ship.

- `count-allocs` — wraps the global allocator with counters. A profile gives the
  allocator's *share* of CPU; this gives the *number*, and the two lead to
  different work. Measured: **292 allocations and ~62 KB per request** to serve a
  1 KB response, which cross-checks against the profile's 14.5 % allocator share.
- `bench-no-middleware` — collapses the eight-layer chain to one pass-through
  layer. Measured: the chain costs **26.5 µs/request at 64 KB (1.33×, rank
  64/64)**, roughly twice our deficit to HAProxy at that body size.
- `bench-null-middleware` — keeps every layer, and its boxed future and
  per-request clone, but makes each do no work. Intended to split that 26.5 µs
  into work and plumbing. **It does not resolve**: two runs gave 23.0/5.2 and
  9.9/16.2 µs, inverting which half dominates.

Measure the middleware arms at **64 KB**. Collapsing the chain also drops the 848
response-header bytes those layers add, which is 40 % of a 1 KB response and 1 %
of a 64 KB one; at 1 KB that confound alone reads as 1.50×.

## Measuring a code change

Use `repeat.sh` / `repeat-h3.sh`, which alternate A/B and **flip the order on
round parity**. Running A first every round confounds the binary with the slot,
and the second slot is measurably slower here: a null test — the identical
binary in both slots — put it at **3.7 %**, which is larger than the differences
this rig is used to detect. It nearly published a false regression at
−4.95 %, z = −2.41; holding position constant collapsed it to −1.19 % and
−1.40 %, no effect at all.

Whenever a delta looks real, **run the null test first** (the same binary in
both slots) to size the slot effect, then compare within a slot rather than
pooling. Report the median **and** the rank statistic — how often a random B run
beats a random A run — because with distributions this wide the rank check is
the one that carries conviction.

## Certificates

The configs reference `/root/bench/certs/bench.local.*`, a throwaway self-signed
pair generated by the setup step. No key material is committed here; regenerate
with:

```sh
openssl req -x509 -newkey rsa:2048 -keyout bench.local.key -out bench.local.crt \
  -days 30 -nodes -subj "/CN=bench.local" \
  -addext "subjectAltName=DNS:bench.local,DNS:localhost,IP:127.0.0.1"
cat bench.local.crt bench.local.key > bench.local.pem
```

The filename matters: the SNI resolver keys certificates by filename stem, so a
cert named `bench.crt` registers as `bench` and a client asking for
`bench.local` is refused with an access-denied alert.

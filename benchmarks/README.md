# Benchmark harness

The rig behind the throughput and handshake figures published at
<https://pqcrypta.com/proxy-comparison/>. It is here so the numbers can be
re-run rather than taken on trust.

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

The backend's own ceiling, measured by `bench-backend.sh` with nothing in front
of it and the same threaded generator:

| body | c=10 | c=100 |
|---|---|---|
| empty | 268k req/s | 380k req/s |
| 1 KB | 164k req/s | 277k req/s |
| 64 KB | 57k req/s (3.5 GB/s) | 138k req/s (8.4 GB/s) |

Re-measure this whenever the layout changes, and read it against what the
proxies posted. It is not a formality: see guard 6.

## Two arms, and what each actually varies

- **plumbing-only** (`conf/pqc-bench.toml`) — everything HAProxy does not have
  is off. Answers *how fast is the proxy*. This is the arm `run-bench.sh` runs.
- **as-deployed** (`conf/pqc-bench-features.toml`) — differs from the plumbing
  config **only** in `[http3]` and `[headers]`: early hints, priority hints,
  request coalescing and Server-Timing. That is all it has ever varied.

It does **not** price the WAF, fingerprinting or rate limiting, and it never
did. Those are `enabled = false` in both configs, and everything above runs over
loopback, where `SecurityState::is_trusted()` short-circuits the whole
per-request security block before any of them is consulted. A figure from this
pair is a figure about four HTTP/3 extras; label it that way.

- **security cost** (`conf/pqc-sec-off.toml` / `conf/pqc-sec-on.toml`, driven by
  `run-sec.sh`) — the real one. Both bind `10.99.0.1` on a dummy interface,
  because RFC1918 is *not* implicitly trusted (only loopback and explicit
  `trusted_internal_cidrs`), so the security path actually runs. Limits are
  raised far above the offered load on purpose: the cost under test is
  *evaluating* a request, and a run that trips the limiter measures the
  rejection path instead. `run-sec.sh` refuses to start unless a SQLi probe
  returns 403 on the on-arm and 200 on the off-arm.

Set up the interface once:

```sh
ip link add pqcbench0 type dummy
ip addr add 10.99.0.1/24 dev pqcbench0
ip link set pqcbench0 up
echo '10.99.0.1 bench-sec.local' >> /etc/hosts
```

## Running

```sh
./run_all.sh            # the whole published suite, in the right order
./run-bench.sh          # both proxies, h1 + h2 + h3, three body sizes
./run-pqc-only.sh       # pqcrypta as-deployed arm only
./run-sec.sh            # security on vs off, off a non-loopback address
./bench-backend.sh      # the backend's own ceiling — run this first, always
./bench-routes.sh       # one config, one cell — for A/B on a code change
./bench-handshake2.sh   # TLS handshake cost, classical vs X25519MLKEM768
./repeat.sh A B 5       # interleaved A/B of two binaries
python3 pagefigs2.py out/res-<stamp>    # every figure the page publishes
```

`pagefigs2.py` is the single source of every number on the page: one line there
per figure the page states. It replaced `analyse-final.py` and `emit-json.py`,
which computed overlapping figures in three places and let three of them drift
out of date unnoticed. `run-plumbing.sh` was deleted outright — it drove
`h2load` with no `-t`, so it produced a single-threaded-generator arm that was
then compared against six-threaded ones, and `run-bench.sh` already runs the
same binary on the same config with the right generator.

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

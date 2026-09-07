#!/usr/bin/env python3
"""Build the security-on arm from the security-off arm, changing only the
sections under test.

The old "features" arm differed from the plumbing arm only in [http3] and
[headers] — the WAF, fingerprinting and rate limiting it claimed to price were
`enabled = false` in *both*, and everything ran over loopback, where
SecurityState::is_trusted short-circuits the whole per-request security block
before any of them is consulted. So the published figure priced four HTTP/3
extras and called them a security cost.

Both arms here bind a non-loopback address, so the security path actually runs.
Limits are raised far above the offered load on purpose: the cost being measured
is that of *evaluating* a request, and a run that starts returning 429 measures
how fast the proxy rejects instead.

Sections are replaced by a line scan rather than a regex. A multi-line regex over
TOML is exactly the shape that silently eats the sections that follow — the same
class of mistake that once dropped sixteen sections out of a generated config and
made it read four times faster than the one it was meant to mirror.
"""
import sys

src, dst = sys.argv[1], sys.argv[2]

ON = {
    "[waf]": """[waf]
enabled = true
mode = "block"
scan_json_body = true
""",
    "[fingerprint]": """[fingerprint]
enabled = true
tls_layer_capture = true
block_scanners = true
""",
    "[rate_limiting]": """[rate_limiting]
enabled = true
# Far above the offered load: the cost under test is evaluating a request, and a
# run that trips the limiter measures the rejection path instead.
requests_per_second = 4000000
burst_size = 2000000
connection_rate_limit = true
connections_per_second = 1000000
""",
    "[advanced_rate_limiting]": """[advanced_rate_limiting]
enabled = true

[advanced_rate_limiting.global_limits]
requests_per_second = 4000000
burst_size = 2000000

[advanced_rate_limiting.global_limits.per_ip]
requests_per_second = 4000000
burst_size = 2000000
requests_per_minute = 240000000
requests_per_hour = 4000000000

[advanced_rate_limiting.global_limits.per_fingerprint]
requests_per_second = 4000000
burst_size = 2000000
requests_per_minute = 240000000
requests_per_hour = 4000000000
""",
    "[security]": """[security]
dos_protection = true
# The generator is one IP holding a hundred connections; the default cap of 100
# sits exactly on that edge.
max_connections_per_ip = 60000
""",
}

out, skipping, replaced = [], False, set()
for line in open(src):
    stripped = line.strip()
    if stripped.startswith("[") and stripped.endswith("]"):
        skipping = False
        if stripped in ON:
            out.append(ON[stripped])
            replaced.add(stripped)
            skipping = True
            continue
    if not skipping:
        out.append(line)

missing = set(ON) - replaced
if missing:
    sys.exit("sections not found in %s: %s" % (src, " ".join(sorted(missing))))

open(dst, "w").write("".join(out))

# Section-list check, the guard from benchlib: a config that has quietly lost a
# section runs on defaults and reads faster than the one it claims to mirror.
def sections(path):
    return {l.strip() for l in open(path) if l.startswith("[")}

lost = sections(src) - sections(dst)
if lost:
    sys.exit("FATAL: %s lost sections present in %s: %s" % (dst, src, " ".join(sorted(lost))))
print("wrote %s (%d sections)" % (dst, len(sections(dst))))

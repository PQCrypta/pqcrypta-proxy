#!/usr/bin/python3 -I
"""CRS regression tests (go-ftw YAML) -> JSON cases for the proxy's WAF harness.

argv: <crs source dir> <out.json>. Each case is one stage of one test:
method, uri, headers, body, and what CRS expects of the rule the file is for:
"attack" (expect_ids has it), "benign" (no_expect_ids has it), or "other".
The paranoia level of every rule comes from the rule files' tags.
"""
import glob, json, os, re, sys, yaml

src, out = sys.argv[1], sys.argv[2]
BROWSER_UA = "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/140.0.0.0 Safari/537.36"

pl = {}
for f in glob.glob(os.path.join(src, "rules", "*.conf")):
    text = open(f, encoding="utf-8", errors="replace").read()
    ids = [(m.start(), m.group(1)) for m in re.finditer(r"\bid:(\d{6})", text)]
    for i, (pos, rid) in enumerate(ids):
        end = ids[i + 1][0] if i + 1 < len(ids) else len(text)
        m = re.search(r"paranoia-level/(\d)", text[pos:end])
        if m:
            pl[rid] = int(m.group(1))

cases, skipped = [], {"encoded_request": 0, "no_input": 0}
for f in sorted(glob.glob(os.path.join(src, "tests", "regression", "tests", "*", "*.yaml"))):
    doc = yaml.safe_load(open(f, encoding="utf-8"))
    if not isinstance(doc, dict):
        skipped["no_input"] += 1
        continue
    rule = str(doc.get("rule_id") or os.path.basename(f).split(".")[0])
    family = os.path.basename(os.path.dirname(f))
    for t in doc.get("tests") or []:
        for si, st in enumerate(t.get("stages") or []):
            st = st.get("stage", st)
            inp, outp = st.get("input") or {}, st.get("output") or {}
            if "encoded_request" in inp:
                skipped["encoded_request"] += 1
                continue
            log = outp.get("log") or {}
            expect = [str(x) for x in (log.get("expect_ids") or outp.get("expect_ids") or [])]
            no_expect = [str(x) for x in (log.get("no_expect_ids") or outp.get("no_expect_ids") or [])]
            kind = "attack" if rule in expect else "benign" if rule in no_expect else "other"
            headers = [[str(k), str(v)] for k, v in (inp.get("headers") or {}).items()]
            # CRS's tests address "localhost"; a request to this site names it.
            headers = [[k, "pqcrypta.com"] if k.lower() == "host" and v == "localhost" else [k, v] for k, v in headers]
            if not family.startswith("REQUEST-913"):
                headers = [[k, BROWSER_UA] if k.lower() == "user-agent" and "OWASP CRS test agent" in v else [k, v] for k, v in headers]
            data = inp.get("data")
            if isinstance(data, list):
                data = "\r\n".join(str(x) for x in data)
            cases.append({
                "id": f"{rule}-{t.get('test_id')}-{si}", "rule": rule, "family": family,
                "pl": pl.get(rule), "kind": kind, "desc": str(t.get("desc", ""))[:120],
                "method": str(inp.get("method", "GET")), "uri": str(inp.get("uri", "/")),
                "headers": headers, "body": None if data is None else str(data),
            })
json.dump(cases, open(out, "w"))
from collections import Counter
print(len(cases), "cases;", dict(Counter(c["kind"] for c in cases)), "skipped", skipped,
      "rules with a paranoia level:", len(pl))

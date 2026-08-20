import json, glob, csv
from collections import Counter

INTERNAL = ("chrome-extension://", "chrome://", "moz-extension://", "data:", "blob:")
def real(h): return h and "." in h and "example.com" not in h

# label tu meta.json
label_of = {}
for m in glob.glob("eval/results/*/meta.json"):
    d = json.load(open(m, encoding="utf-8"))
    label_of[d.get("ext_id")] = d.get("label", "?")

agg = {"malicious": Counter(), "benign": Counter()}
for f in glob.glob("eval/results/*/output/events.json"):
    ev = json.load(open(f, encoding="utf-8"))
    eid = ev.get("manifest", {}).get("name", "")  # fallback
    # lay label tu path
    import os
    rid = os.path.basename(os.path.dirname(os.path.dirname(f)))
    lab = label_of.get(rid, "malicious")
    for r in ev.get("network_requests", []):
        url = r.get("url", "")
        if url.startswith(INTERNAL): continue
        h = r.get("host", "")
        if not real(h): continue
        agg.setdefault(lab, Counter())[r.get("origin")] += 1

for lab in ("malicious", "benign"):
    c = agg.get(lab, Counter())
    tot = sum(c.values()) or 1
    print(f"\n=== {lab}: {sum(c.values())} request toi host thuc ===")
    for o, n in c.most_common():
        print(f"  {str(o):16} {n:6}  ({n/tot*100:4.1f}%)")
import json, glob, os
from collections import Counter

INTERNAL = ("chrome-extension://", "chrome://", "data:", "blob:")
HARNESS = {"example.com", "canary-page.invalid", "canary-cs.invalid", "tiktok.com", "www.tiktok.com"}
def real(h): return h and "." in h and h not in HARNESS and "example.com" not in h

label_of = {}
for m in glob.glob("eval/results/*/meta.json"):
    d = json.load(open(m, encoding="utf-8"))
    rid = os.path.basename(os.path.dirname(m))
    label_of[rid] = d.get("label", "malicious")

# Dem theo 3 nguon: SW (network_requests service_worker), CS (provenance ext=True), PAGE (provenance ext=False)
agg = {"malicious": Counter(), "benign": Counter()}
samples_with_ext = {"malicious": 0, "benign": 0}
tot = {"malicious": 0, "benign": 0}

for f in glob.glob("eval/results/*/output/events.json"):
    rid = os.path.basename(os.path.dirname(os.path.dirname(f)))
    lab = label_of.get(rid, "malicious")
    ev = json.load(open(f, encoding="utf-8"))
    tot[lab] += 1
    sw_hosts, cs_hosts, page_hosts = set(), set(), set()
    for r in ev.get("network_requests", []):
        if r.get("origin") == "service_worker":
            h = r.get("host", "")
            if real(h): sw_hosts.add(h)
    for h, ext in (ev.get("request_provenance", {}) or {}).items():
        if not real(h): continue
        (cs_hosts if ext else page_hosts).add(h)
    agg[lab]["SW (extension)"] += len(sw_hosts)
    agg[lab]["CS (extension)"] += len(cs_hosts)
    agg[lab]["PAGE (trang)"] += len(page_hosts)
    if sw_hosts or cs_hosts:
        samples_with_ext[lab] += 1

for lab in ("malicious", "benign"):
    a = agg[lab]; s = sum(a.values()) or 1
    print(f"\n=== {lab}: {tot[lab]} mau ===")
    for k in ("SW (extension)", "CS (extension)", "PAGE (trang)"):
        print(f"  {k:18} {a[k]:6} host-contact  ({a[k]/s*100:4.1f}%)")
    print(f"  -> {samples_with_ext[lab]}/{tot[lab]} mau co it nhat 1 host do EXTENSION goi (SW hoac CS)")
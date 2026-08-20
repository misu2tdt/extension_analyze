import csv, json, sys
from collections import Counter
from pathlib import Path

REPO = Path(__file__).resolve().parents[1]
results = Path(sys.argv[1]) if len(sys.argv) > 1 else REPO / "eval" / "results"
COMMON = ("google-analytics","googletagmanager","doubleclick","gstatic","google.com",
          "cloudflare","cloudfront","fbcdn","facebook","jsdelivr","unpkg","cdnjs","sentry",
          "bugsnag","amazonaws","googleapis","gvt1","gvt2","bing","microsoft","youtube")

domains, silent, n = Counter(), 0, 0
for d in sorted(results.iterdir()):
    ev = d / "output" / "events.json"
    if not ev.exists(): continue
    n += 1
    ext = json.loads(ev.read_text(encoding="utf-8")).get("summary", {}).get("external_domains", [])
    if not ext: silent += 1
    for h in ext: domains[h] += 1

lv = Counter()
sc = results / "summary.csv"
if sc.exists():
    for r in csv.DictReader(open(sc, encoding="utf-8")): lv[r["level"]] += 1

print(f"mau co events: {n} | im lang (0 external domain): {silent}")
print(f"level distribution: {dict(lv)}")
print(f"\nTOP 30 external domain (tan suat / {n} mau):")
for h, c in domains.most_common(30):
    tag = "   <-- common-infra (co the lam undeclared LONG)" if any(k in h for k in COMMON) else ""
    print(f"  {c:4d}  {h}{tag}")
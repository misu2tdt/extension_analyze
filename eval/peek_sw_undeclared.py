import csv, json, glob, sys
from collections import Counter
sys.path.insert(0, "worker")
from risk import detect_undeclared_domains

def only_und(r):
    try:
        if float(r.get("risk") or 0) < 40: return False
    except: return False
    if r["label"] != "malicious" or r.get("undeclared_domain_contact") != "1": return False
    for s in ("credential_exfil","beaconing","script_injection","local_harvest"):
        if r.get(s)=="1": return False
    return True

rows=[r for r in csv.DictReader(open("eval/results/summary.csv",encoding="utf-8")) if only_und(r)]
ndomain = Counter()   # phan bo so luong domain SW goi
sample_hosts = []     # vai vi du de doc
for r in rows:
    f=glob.glob(f"eval/results/{r['ext_id']}/output/events.json")
    if not f: continue
    d=detect_undeclared_domains(json.load(open(f[0],encoding="utf-8")))
    sw=d["undeclared_from_sw"]
    if sw and not d.get("undeclared_from_cs"):   # chi SW
        ndomain[len(sw)] += 1
        if len(sample_hosts) < 15:
            sample_hosts.append((r["ext_id"][:16], sw[:5]))

print("Phan bo so domain SW-undeclared moi mau (chi-SW):")
for n in sorted(ndomain):
    print(f"  {n} domain: {ndomain[n]} mau")
print("\n15 vi du (ext_id -> vai domain dau):")
for eid, hosts in sample_hosts:
    print(f"  {eid}: {hosts}")
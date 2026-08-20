import csv, json, glob, sys
from pathlib import Path

sys.path.insert(0, "worker")
from risk import detect_undeclared_domains

def flagged_only_undeclared(r):
    try:
        if float(r.get("risk") or 0) < 40: return False
    except: return False
    if r["label"] != "malicious": return False
    if r.get("undeclared_domain_contact") != "1": return False
    # khong co tin hieu manh khac
    for s in ("credential_exfil", "beaconing", "script_injection", "local_harvest"):
        if r.get(s) == "1": return False
    return True

rows = [r for r in csv.DictReader(open("eval/results/summary.csv", encoding="utf-8"))
        if flagged_only_undeclared(r)]

sw = cs = both = neither = 0
for r in rows:
    f = glob.glob(f"eval/results/{r['ext_id']}/output/events.json")
    if not f: continue
    ev = json.load(open(f[0], encoding="utf-8"))
    d = detect_undeclared_domains(ev)
    nsw = len(d["undeclared_from_sw"])
    ncs = len(d.get("undeclared_from_cs", []))
    if nsw and ncs: both += 1
    elif nsw: sw += 1
    elif ncs: cs += 1
    else: neither += 1

print(f"{len(rows)} mau chi-nho-undeclared, nguon:")
print(f"  chi SW  : {sw}")
print(f"  chi CS  : {cs}")
print(f"  ca hai  : {both}")
print(f"  khong ro: {neither}")
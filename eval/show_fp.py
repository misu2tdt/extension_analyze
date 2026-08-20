import csv
from pathlib import Path

SIGNALS = ["credential_exfil", "local_harvest", "script_injection",
           "beaconing", "undeclared_domain_contact", "unsolicited_tab"]
rows = [r for r in csv.DictReader(open("eval/results/summary.csv", encoding="utf-8"))
        if r["label"] == "benign"]

def risk_val(r):
    try: return float(r["risk"])
    except: return 0.0

flag = [r for r in rows if risk_val(r) >= 40]
print(f"benign: {len(rows)} mau | bi flag (risk>=40): {len(flag)}/{len(rows)}\n")
for r in sorted(rows, key=risk_val, reverse=True):
    on = [s for s in SIGNALS if r.get(s) == "1"]
    print(f"  {r['ext_id'][:22]:22} risk={r['risk']:>3} {r['level']:8} | " + (", ".join(on) or "(sach)"))

print("\n=== FP theo tung tin hieu (tren benign) ===")
for s in SIGNALS:
    c = sum(1 for r in rows if r.get(s) == "1")
    print(f"  {s:26}: {c}/{len(rows)}")
"""
pr_roc.py — Ve PR curve + ROC curve tu summary.csv, tinh AUC.
Chay: python eval/pr_roc.py
Yeu cau: matplotlib  (pip install matplotlib --break-system-packages)

Quy uoc: malicious = positive, benign = negative.
Quet nguong risk tu 0..100, moi nguong tinh recall / FPR / precision.
"""
import csv, sys
from pathlib import Path

CSV = "eval/results/summary.csv"

# --- doc du lieu, tu do cot risk + label ---
rows = list(csv.DictReader(open(CSV, encoding="utf-8")))
if not rows:
    print("summary.csv rong"); sys.exit()

cols = rows[0].keys()
risk_col  = next((c for c in cols if c.lower() in ("risk","risk_score","score")), None)
label_col = next((c for c in cols if c.lower() in ("label","ground_truth","truth","class")), None)
if not risk_col or not label_col:
    print("Khong tim thay cot risk/label. Header:", list(cols)); sys.exit()

status_col = next((c for c in cols if c.lower() == "run_status"), None)

data = []
n_excluded_status = 0
for r in rows:
    if status_col and (r.get(status_col) or "").strip() != "complete":
        n_excluded_status += 1
        continue
    try:
        risk = float(r[risk_col] or 0)
    except ValueError:
        continue
    lab = (r[label_col] or "").strip().lower()
    if lab not in ("malicious", "benign"):
        continue
    data.append((risk, lab == "malicious"))

print(f"Loc theo run_status=complete: dung {len(data)} row | loai {n_excluded_status} row (run_status != complete)")

P = sum(1 for _, m in data if m)      # tong malicious
N = sum(1 for _, m in data if not m)  # tong benign
print(f"Dataset: {len(data)} mau  |  malicious(P)={P}  benign(N)={N}")
if P == 0 or N == 0:
    print("Can ca malicious lan benign de ve duong cong"); sys.exit()

# --- quet nguong ---
thresholds = list(range(0, 101))
roc_pts, pr_pts, table = [], [], []
for t in thresholds:
    TP = sum(1 for risk, m in data if m and risk >= t)
    FP = sum(1 for risk, m in data if (not m) and risk >= t)
    FN = P - TP
    TN = N - FP
    recall    = TP / P if P else 0            # = TPR
    fpr       = FP / N if N else 0
    precision = TP / (TP + FP) if (TP + FP) else 1.0
    roc_pts.append((fpr, recall))
    pr_pts.append((recall, precision))
    table.append((t, TP, FP, FN, TN, recall, fpr, precision))

# --- AUC (trapezoidal) cho ROC: sap theo fpr tang ---
roc_sorted = sorted(roc_pts)
auc = 0.0
for i in range(1, len(roc_sorted)):
    x0, y0 = roc_sorted[i-1]; x1, y1 = roc_sorted[i]
    auc += (x1 - x0) * (y0 + y1) / 2
print(f"ROC AUC = {auc:.3f}")

# --- in bang vai nguong quan trong ---
print("\nnguong | TP  FP  FN  TN | recall  FPR   precision")
for t, TP, FP, FN, TN, rec, fpr, prec in table:
    if t % 10 == 0 or t in (15, 40, 70, 90):
        print(f"  {t:3}  | {TP:3} {FP:3} {FN:3} {TN:3} |  {rec:.2f}   {fpr:.2f}   {prec:.2f}")

# --- ve ---
try:
    import matplotlib
    matplotlib.use("Agg")
    import matplotlib.pyplot as plt
    fig, (ax1, ax2) = plt.subplots(1, 2, figsize=(12, 5))

    xs = [p[0] for p in roc_sorted]; ys = [p[1] for p in roc_sorted]
    ax1.plot(xs, ys, "-o", ms=2)
    ax1.plot([0,1],[0,1],"--",color="gray",lw=0.8)
    ax1.set_xlabel("False Positive Rate"); ax1.set_ylabel("Recall (TPR)")
    ax1.set_title(f"ROC (AUC={auc:.3f})"); ax1.grid(alpha=0.3)

    rs = [p[0] for p in pr_pts]; ps = [p[1] for p in pr_pts]
    ax2.plot(rs, ps, "-o", ms=2)
    ax2.set_xlabel("Recall"); ax2.set_ylabel("Precision")
    ax2.set_title("Precision-Recall"); ax2.grid(alpha=0.3)

    out = "eval/results/pr_roc.png"
    plt.tight_layout(); plt.savefig(out, dpi=130)
    print(f"\nDa luu bieu do: {out}")
except ImportError:
    print("\n(Chua co matplotlib — chi in bang. Cai: pip install matplotlib --break-system-packages)")

# --- luu diem duong cong ra csv de tu ve neu can ---
with open("eval/results/pr_roc_points.csv", "w", newline="", encoding="utf-8") as f:
    w = csv.writer(f)
    w.writerow(["threshold","TP","FP","FN","TN","recall","fpr","precision"])
    w.writerows(table)
print("Da luu diem: eval/results/pr_roc_points.csv")
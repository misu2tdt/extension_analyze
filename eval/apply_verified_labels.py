"""
apply_verified_labels.py — them cot verified_label + verified vao summary.csv tu
verdict da doc thu cong (eval/_verify/benign_fp/verdict.md +
eval/_verify/fn/fn_verdict.md). Mapping day du + ly do: eval/label_mapping.md (TRACKED,
xem file do de biet nguon goc tung ext_id). Bang chung chi tiet (doc CRX that, grep
own-code) nam o eval/_verify/*.md — thu muc do GITIGNORED (chua unpacked extension code
cua ben thu 3), khong co trong git history; can tai tao lai bang cach doc lai CRX theo
quy trinh mo ta trong eval/label_mapping.md neu can xem lai bang chung goc.

Chay SAU eval/rescore.py (rescore.py ghi lai summary.csv KHONG co 2 cot nay).
KHONG xoa row nao, KHONG doi cot label goc. Mau chua verify: verified_label=label goc,
verified=no.

Chay: python eval/apply_verified_labels.py
"""
import csv
from pathlib import Path

REPO = Path(__file__).resolve().parents[1]
CSV = REPO / "eval" / "results" / "summary.csv"

# nhan goc=benign, verdict tu eval/_verify/benign_fp/verdict.md
BENIGN_VERDICT = {
    # verified_benign -> benign
    "dashlane": "benign", "ghostery": "benign", "videodownloadhelper": "benign",
    "grammarly": "benign", "languagetool": "benign", "awesomescreenshot": "benign",
    "nordpass": "benign", "momentum": "benign", "evernotewebclipper": "benign",
    "sponsorblock": "benign", "editthiscookie": "benign",
    # grey_pup -> grey
    "capitaloneshopping": "grey", "rakuten": "grey", "honey": "grey",
}

# nhan goc=malicious, verdict tu eval/_verify/fn/fn_verdict.md
MALWARE_VERDICT = {
    # benign_mislabel -> benign_mislabel (giu rieng, KHONG gop "benign", xem eval/label_mapping.md)
    "ajfokipknlmjhcioemgnofkpmdnbaldi": "benign_mislabel",
    "beifiidafjobphnbhbbgmgnndjolfcho": "benign_mislabel",
    "eheagnmidghfknkcaehacggccfiidhik": "benign_mislabel",
    "gddonialdhbldcdbnbloangmjnpcnhhd": "benign_mislabel",
    "goiffchdhlcehhgdpdbocefkohlhmlom": "benign_mislabel",
    "hhlcpmdhlcoghhfgiiopcjbkfmdliknc": "benign_mislabel",
    "hodafefeincjlgijbiabbmaffambjeaa": "benign_mislabel",
    "pgejmpeimhjncennkkddmdknpgfblbcl": "benign_mislabel",
    "acmfnomgphggonodopogfbmkneepfgnh": "benign_mislabel",
    "apdfllckaahabafndbhieahigkjlhalf": "benign_mislabel",
    "ccgdboldgdlngcgfdolahmiilojmfndl": "benign_mislabel",
    "cdiohdbijdajffgccjmbblbikpnnnkeg": "benign_mislabel",
    "cimpffimgeipdhnhjohpbehjkcdpjolg": "benign_mislabel",
    "codgofkgobbmgglciccjabipdlgefnch": "benign_mislabel",
    "eggegjdejilddmnlglakcaigefefcdaf": "benign_mislabel",
    "abbngaojehjekanfdipifimgmppiojpl": "benign_mislabel",
    "adjiljljjoeielcjmafljkicjncjpbha": "benign_mislabel",
    # adware_pup -> grey
    "dnmfcojgjchpjcmjgpgonmhccibjopnb": "grey",
    "nfijbcmjagdmmkchgicfdidblofopkdp": "grey",
    "pfgpfmdiepmhhhkpnciogjhccppbcfhk": "grey",
    "ecocgofdjmiomgmgnchijbghkikolkkl": "grey",
    "aecccajigpipkpioaidignbgbeekglkd": "grey",
    "aikflfpejipbpjdlfabpgclhblkpaafo": "grey",
    "ajfanjhcdgaohcbphpaceglgpgaaohod": "grey",
    # obfuscated_unknown -> unknown_verify
    "bajoeadpdidoahbhphmhejmbdmgnbdci": "unknown_verify",
    "glckmpfajbjppappjlnhhlofhdhlcgaj": "unknown_verify",
    # malware_missed -> malicious (0 mau trong dataset hien tai, giu san cho tuong lai)

    # brand_impersonation -> benign_mislabel (verify rieng, phat sinh tu dot fix #2/#3:
    # 4 mau nay tung "rung" khoi flag risk>=40 khi Fix#3 (page_host-only) discount dung
    # tin hieu tren trang welcome noi bo. Kiem tra: KHONG co content_scripts, KHONG
    # host_permissions (permissions=["storage","sidePanel"]) -> VE MAT KY THUAT khong the
    # inject/doc bat ky trang nao nguoi dung dang xem. Toan bo "hanh vi" chi la tai nguyen
    # tu trang welcome.html noi bo cua chinh no goi bundle JS tu backend rieng
    # (*.easytool.dev). Day la clone gia danh thuong hieu AI dang hot (Grok/DeepSeek/
    # Perplexity), cung 1 "factory" (giong het asset filename: react-vendor-BLb8y8_B.js...).
    # Ban chat hai la BRAND IMPERSONATION (danh lua bang ten goi), KHONG phai injection/exfil
    # runtime - ngoai pham vi dynamic-behavior detector nay (xem LIMITATION trong risk.py).
    # Xem eval/_verify/fn/brand_impersonation_verdict.md.
    "aoemlgniakbojcecmjefonjkgnceklpg": "benign_mislabel",
    "fgbieegonkgdlkmeaapmkejdlfalonkb": "benign_mislabel",
    "hafhkoalnlpoifpidohfjlmeemfifndi": "benign_mislabel",
    "ifhigdhiifbnjanhacoedbadhmlkjgae": "benign_mislabel",
}

VERDICT = {}
VERDICT.update(BENIGN_VERDICT)
VERDICT.update(MALWARE_VERDICT)


def main():
    rows = list(csv.DictReader(open(CSV, encoding="utf-8")))
    if not rows:
        print("summary.csv rong"); return
    fieldnames = list(rows[0].keys())
    for extra in ("verified_label", "verified"):
        if extra not in fieldnames:
            fieldnames.append(extra)

    n_yes, n_no = 0, 0
    for r in rows:
        eid = r.get("ext_id", "")
        if eid in VERDICT:
            r["verified_label"] = VERDICT[eid]
            r["verified"] = "yes"
            n_yes += 1
        else:
            r["verified_label"] = r.get("label", "")
            r["verified"] = "no"
            n_no += 1

    with open(CSV, "w", newline="", encoding="utf-8") as f:
        w = csv.DictWriter(f, fieldnames=fieldnames, extrasaction="ignore")
        w.writeheader()
        w.writerows(rows)

    print(f"[apply_verified_labels] {len(rows)} row -> {CSV}")
    print(f"  verified=yes: {n_yes} (khop trong verdict.md/fn_verdict.md)")
    print(f"  verified=no : {n_no} (giu nguyen label goc, chua verify)")
    if n_yes != len(VERDICT):
        missing = set(VERDICT) - {r["ext_id"] for r in rows}
        print(f"  CANH BAO: {len(VERDICT) - n_yes} ext_id trong VERDICT khong khop row nao "
              f"trong summary.csv: {sorted(missing)}")


if __name__ == "__main__":
    main()

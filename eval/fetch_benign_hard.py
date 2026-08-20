"""Tai bo benign 'kho' (~40-50 extension pho bien, hanh vi giong malware nhung hop
phap) qua Google update-service, doc manifest THAT, tu loc MV3. Verify = tin manifest
cua file da tai, khong tin ID tu web. Chay tren Windows.

Nhom "grey_candidate" (Honey/Rakuten/Capital One Shopping): inject affiliate link/
redirect - hanh vi ranh gioi, co the cham diem cao chinh dang. Van --label benign khi
chay sandbox (dung nhan dung theo CWS) nhung duoc DANH DAU RIENG o day de bao cao khong
tron lan voi benign sach.
"""
import io, json, sys, time, urllib.request, zipfile
from pathlib import Path

REPO = Path(__file__).resolve().parents[1]
OUT = REPO / "eval" / "cws_benign_crx"
OUT.mkdir(parents=True, exist_ok=True)

# (ten_de_doc, extension_id, grey_candidate) - ID tra tu chromewebstore.google.com,
# uu tien ban chinh chu / nhieu nguoi dung nhat tim duoc qua tim kiem.
CANDIDATES = [
    # --- Ad/content blocker ---
    ("adblock", "gighmmpiobklfepjocnamgkkbiglidom", False),
    ("adguard_adblocker", "bgnkhhnnamicmpeenaelnjfhikgbkllg", False),
    ("ghostery", "mlomiejdfkolichcflejclcbmpeaniij", False),
    ("ublock_origin", "cjpalhdlnbpafiamejdnhcphjbkeiagm", False),       # ky vong MV2
    ("ublock_origin_lite", "ddkjiahejlhfcafbddmgiahcphecmpfh", False),  # MV3, thay the

    # --- Password manager ---
    ("1password", "aeblfdkhhhdcdjpifhhbdiojplfjncoa", False),
    ("dashlane", "fdjamakpfbbddfjaooikfcpapjohcfmg", False),
    ("keepassxc_browser", "oboonakemofpalcgghocfoadofidjkkk", False),
    ("nordpass", "eiaeiblijfjekdanodkjadfinkhbfgcd", False),

    # --- Privacy/anti-tracking ---
    ("duckduckgo_privacy_essentials", "bkdgflcldnnnapblkhphbgpggdiikppg", False),
    ("cookie_autodelete", "fhcgjolkccmbidfldomjliifgaodjagh", False),
    # ClearURLs: KHONG tim thay tren Chrome Web Store qua tim kiem - bo qua.

    # --- Dev tools ---
    ("vuejs_devtools", "iaajmlceplecbljialhhkmedjlpdblhp", False),
    ("wappalyzer", "gppongmhjkpfnbhagpmjfkannfbllamg", False),
    ("json_viewer", "aimiinbnnkboelefkjlenlgimcabobli", False),
    ("colorzilla", "bhlhnicpbhignbdhedgjhgdocnmhomnp", False),

    # --- Screenshot ---
    ("gofullpage", "fdpohaocaechififmbbbbbknoalclacl", False),
    ("awesome_screenshot", "nlipoenfbbikpbjkfpfillcgkoblgpmj", False),
    ("fireshot", "mcbpblocgmgfnpjjppndjkmgjaogfceg", False),

    # --- Cookie/storage ---
    ("editthiscookie", "ojfebgpkimhlhcblbalbfjblapadhbol", False),  # ban V3
    ("cookie_editor", "hlkenndednhfkekhgcdicdfddnkalmdm", False),

    # --- Tab manager ---
    ("onetab", "chphlpgkkbolifaimnlloiipkdnihall", False),
    ("session_buddy", "edacconmaakjimmfgnblocblbcdcpbko", False),

    # --- Grammar/writing ---
    ("grammarly", "kbfnbcaeplbcioakkpcpgfkobkghlhen", False),
    ("languagetool", "oldceeleldhonbafppcapldpdifcinji", False),

    # --- Video ---
    ("video_downloadhelper", "lmjnegcaeklhafolokijcfjliaokphfk", False),
    ("sponsorblock", "mnjggcdmjocbbbhaepdhchncahnbgone", False),
    ("enhancer_for_youtube", "ponfpcnoihfmfllpaingbgckeeldkhle", False),

    # --- Note/clipper ---
    ("evernote_web_clipper", "pioclpoplcdbaefihamjohnefbikjilc", False),
    ("notion_web_clipper", "knheggckgoiihginacbkhaalnibhilkk", False),
    ("save_to_pocket", "niloccemoadcdkdjlinkgdfekeahmflj", False),

    # --- Reader/misc ---
    # Dark Reader: da co san trong eval/results (02darkreader) - bo qua theo yeu cau.
    # Reader Mode: ten qua chung chung, nhieu ban trung ten khong ro ai la "chinh chu"
    # duy nhat - khong du tin cay de xac dinh, bo qua thay vi doan.
    ("momentum", "laookkfknpbbblfpciffpaejjkokdgca", False),

    # --- GREY CANDIDATE: inject affiliate link/redirect, khong mac dinh la benign ---
    ("honey", "bmnlcjabgnpnenekpadlanbbkooimhnj", True),
    ("rakuten", "chhjbpecpncaggjpdakmflnfcopglcmi", True),
    ("capital_one_shopping", "nenlahapcbofgnanklpelkaejcehkggg", True),
]

URL = ("https://clients2.google.com/service/update2/crx?response=redirect"
       "&acceptformat=crx2,crx3&prodversion=131&x=id%3D{id}%26installsource%3Dondemand%26uc")
# Luu y: prodversion=120 (qua cu) khien Google tra ve 204 (khong crx) cho mot so
# extension moi cap nhat gan day - da xac minh 131+ hoat dong on dinh.


def fetch(eid, retries=3):
    req = urllib.request.Request(URL.format(id=eid), headers={"User-Agent": "Mozilla/5.0"})
    last_err = None
    for attempt in range(retries):
        try:
            with urllib.request.urlopen(req, timeout=60) as r:
                b = r.read()
            if b:
                return b
            last_err = "empty_response"
        except Exception as e:
            last_err = str(e)
        time.sleep(2 + attempt * 3)  # backoff: 2s, 5s, 8s - tranh rate-limit cua CWS
    raise RuntimeError(last_err)


def main():
    only = set(sys.argv[1:]) or None   # vd: python fetch_benign_hard.py adblock wappalyzer
    rows = []
    print(f"{'name':30} {'grey':5} {'MV':3} {'perms':5} {'status'}")
    print("-" * 90)
    for name, eid, grey in CANDIDATES:
        if only and name not in only:
            continue
        try:
            b = fetch(eid)
            z = zipfile.ZipFile(io.BytesIO(b[b.index(b"PK\x03\x04"):]))
            m = json.loads(z.read("manifest.json"))
            mv = m.get("manifest_version")
            real = m.get("name", "?")
            nperm = len(m.get("permissions", []) or []) + len(m.get("host_permissions", []) or [])
            if mv == 3:
                path = OUT / f"{name}.crx"
                path.write_bytes(b)
                status = f"OK -> saved  (real name: {real[:34]})"
            else:
                status = f"SKIP MV{mv} khong luu  (real name: {real[:34]})"
            print(f"{name:30} {str(grey):5} {str(mv):3} {nperm:<5} {status}")
            rows.append({"name": name, "id": eid, "grey_candidate": grey,
                         "manifest_version": mv, "real_name": real, "saved": mv == 3})
        except Exception as e:
            print(f"{name:30} {str(grey):5} {'?':3} {'?':5} LOI: {str(e)[:50]}")
            rows.append({"name": name, "id": eid, "grey_candidate": grey,
                         "manifest_version": None, "real_name": None, "saved": False,
                         "error": str(e)[:200]})

    (OUT / "_fetch_log.json").write_text(
        json.dumps(rows, ensure_ascii=False, indent=2), encoding="utf-8")
    saved = [r for r in rows if r["saved"]]
    mv2 = [r for r in rows if r.get("manifest_version") not in (None, 3)]
    failed = [r for r in rows if r.get("manifest_version") is None]
    print(f"\n-> {len(saved)}/{len(CANDIDATES)} MV3 da luu vao {OUT}")
    print(f"-> {len(mv2)} MV2 bi loai: " + ", ".join(f"{r['name']}(MV{r['manifest_version']})" for r in mv2))
    print(f"-> {len(failed)} tai that bai: " + ", ".join(r["name"] for r in failed))
    print(f"-> grey_candidate da luu: " + ", ".join(r["name"] for r in saved if r["grey_candidate"]))


if __name__ == "__main__":
    main()

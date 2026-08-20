"""Tai CRX benign qua Google update-service, doc manifest THAT, tu loc MV3.
Verify = tin manifest cua file da tai, khong tin ID tu web. Chay tren Windows."""
import io, json, os, urllib.request, zipfile
from pathlib import Path

OUT = Path(r"C:\Users\Admin\Desktop\BachKhoa\4\HK252\DACN\sample\benign_samples")
OUT.mkdir(parents=True, exist_ok=True)

# (ten_de_doc, extension_id) — chi ID da verify qua repo chinh chu.
# Them dan: lay ID tu repo GitHub chinh thuc cua extension, dan vao day.
CANDIDATES = [
    ("dark_reader", "eimadpbcbfnmbkopoojfekhnkhdbieeh"),      # darkreader/darkreader
    ("tampermonkey", "dhdgffkkebhmkfjojejmpbldmpobfkfo"),     # Tampermonkey/tampermonkey (MV3)
    ("ublock_origin", "cjpalhdlnbpafiamejdnhcphjbkeiagm"),    # gorhill/uBlock (MV2 - se bi canh bao)
    # ("bitwarden", "<id>"),
    # ("privacy_badger", "<id>"),
    # ("stylus", "<id>"),
    # ("vimium", "<id>"),
    # ("ublock_origin_lite", "<id>"),
]

URL = ("https://clients2.google.com/service/update2/crx?response=redirect"
       "&acceptformat=crx3&prodversion=120&x=id%3D{id}%26installsource%3Dondemand%26uc")

def fetch(eid):
    req = urllib.request.Request(URL.format(id=eid), headers={"User-Agent": "Mozilla/5.0"})
    with urllib.request.urlopen(req, timeout=60) as r:
        return r.read()

print(f"{'name':22} {'MV':3} {'perms':5} {'status'}")
print("-" * 70)
for name, eid in CANDIDATES:
    if "<id>" in eid:
        continue
    try:
        b = fetch(eid)
        z = zipfile.ZipFile(io.BytesIO(b[b.index(b"PK\x03\x04"):]))
        m = json.loads(z.read("manifest.json"))
        mv = m.get("manifest_version")
        real = m.get("name", "?")
        nperm = len(m.get("permissions", []) or []) + len(m.get("host_permissions", []) or [])
        if mv == 3:
            path = OUT / f"{name}_{eid}.crx"
            path.write_bytes(b)
            status = f"OK -> saved  (real name: {real[:30]})"
        else:
            status = f"SKIP MV{mv} khong luu  (real name: {real[:30]})"
        print(f"{name:22} {str(mv):3} {nperm:<5} {status}")
    except Exception as e:
        print(f"{name:22} {'?':3} {'?':5} LOI: {str(e)[:40]}")
print("\n-> Chi mau MV3 duoc luu vao benign_samples/. Kiem cot 'real name' khop ten mong doi.")
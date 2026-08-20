import csv, io, json, zipfile
from pathlib import Path

REPO = Path(__file__).resolve().parents[1]
SAMPLE_DIRS = [
    Path(r"C:\Users\Admin\Desktop\BachKhoa\4\HK252\DACN\sample\AutomatedExtensions"),
    Path(r"C:\Users\Admin\Desktop\BachKhoa\4\HK252\DACN\sample\Malicious Browser Extensions"),
]

def find_crx(eid):
    for d in SAMPLE_DIRS:
        if d.is_dir():
            for f in d.glob("*.crx"):
                if f.stem.split("_")[0].lower() == eid.lower():
                    return f
    return None

def manifest_of(f):
    b = f.read_bytes()
    z = zipfile.ZipFile(io.BytesIO(b[b.index(b"PK\x03\x04"):]))
    return json.loads(z.read("manifest.json"))

ids = [r["ext_id"] for r in csv.DictReader(open(REPO / "eval" / "results" / "triage.csv", encoding="utf-8"))
       if r["bucket"] == "silent_capable"]

print(f"{len(ids)} mau silent_capable\n")
for eid in ids:
    f = find_crx(eid)
    if not f:
        print(f"{eid[:16]}  [KHONG TIM THAY CRX]"); continue
    try:
        m = manifest_of(f)
    except Exception as e:
        print(f"{eid[:16]}  [LOI: {str(e)[:40]}]"); continue
    matches = []
    for cs in (m.get("content_scripts") or []):
        matches += cs.get("matches", []) or []
    hosts = m.get("host_permissions", []) or []
    tag = "matches" if matches else "hostperm"
    site = (matches or hosts or ["(khong khai)"])[:5]
    print(f"{eid[:16]}  [{tag}]  {site}")
"""Chang 1 doi chung static/dynamic: giai nen CRX cua nhom target, tach CODE RIENG
cua extension (bo thu vien), quet chi bao tinh. KHONG ket luan - chi thu hep de
Claude Code doc sau nhung mau dang ngo.
Dùng: python eval/static_scan.py            # mac dinh: bucket=silent_capable tu triage.csv
      python eval/static_scan.py <bucket>
"""
import csv, io, json, re, sys, zipfile
from pathlib import Path

REPO = Path(__file__).resolve().parents[1]
# 2 thu muc CRX goc (chinh lai neu khac may)
SAMPLE_DIRS = [
    Path(r"C:\Users\Admin\Desktop\BachKhoa\4\HK252\DACN\sample\AutomatedExtensions"),
    Path(r"C:\Users\Admin\Desktop\BachKhoa\4\HK252\DACN\sample\Malicious Browser Extensions"),
]
LIB_HINTS = ("jquery", "bootstrap", "angular", "react", "vue", "lodash", "moment",
             "popper", "fontawesome", "tagsinput", "underscore", "axios", "d3",
             "chart", "polyfill", "webcomponents", "zone.min", "runtime.")
LIB_DIRS = ("/lib/", "/libs/", "/vendor/", "/third", "/node_modules/", "/dist/vendor")
IND = {
    "net": re.compile(r"fetch\(|XMLHttpRequest|\.ajax\(|new\s+WebSocket|sendBeacon", re.I),
    "eval": re.compile(r"\beval\(|new\s+Function\(|document\.write\(", re.I),
    "obf": re.compile(r"atob\(|fromCharCode|unescape\(|_0x[0-9a-f]{4}|\\x[0-9a-f]{2}", re.I),
    "cookie": re.compile(r"document\.cookie|chrome\.cookies", re.I),
    "storage": re.compile(r"localStorage|chrome\.storage\.local\.get", re.I),
    "webreq": re.compile(r"chrome\.webRequest|declarativeNetRequest", re.I),
    "inject": re.compile(r"chrome\.scripting|executeScript|createElement\(['\"]script|\.src\s*=", re.I),
    "redirect": re.compile(r"chrome\.tabs\.(create|update)|location\.(href|replace|assign)", re.I),
}
URL_RE = re.compile(r"https?://[a-zA-Z0-9._\-]+", re.I)

def find_crx(ext_id: str):
    for d in SAMPLE_DIRS:
        if not d.is_dir():
            continue
        for f in d.glob("*.crx"):
            if f.stem.split("_")[0].lower() == ext_id.lower():
                return f
    return None

def is_own_js(name: str) -> bool:
    n = name.lower()
    if not n.endswith(".js"):
        return False
    if any(d in "/" + n for d in LIB_DIRS):
        return False
    if any(h in n.rsplit("/", 1)[-1] for h in LIB_HINTS):
        return False
    return True

def looks_minified(text: str) -> bool:
    lines = text.split("\n")
    if not lines:
        return False
    longest = max((len(l) for l in lines), default=0)
    return longest > 800 or (len(text) > 3000 and text.count("\n") < len(text) / 200)

def scan_crx(path: Path) -> dict:
    b = path.read_bytes()
    z = zipfile.ZipFile(io.BytesIO(b[b.index(b"PK\x03\x04"):]))
    man = {}
    try:
        man = json.loads(z.read("manifest.json"))
    except Exception:
        pass
    own = [n for n in z.namelist() if is_own_js(n)]
    hits = {k: 0 for k in IND}
    urls, minified, own_bytes = set(), False, 0
    for n in own:
        try:
            t = z.read(n).decode("utf-8", "ignore")
        except Exception:
            continue
        own_bytes += len(t)
        if looks_minified(t):
            minified = True
        for k, rx in IND.items():
            if rx.search(t):
                hits[k] = 1
        for u in URL_RE.findall(t):
            h = u.split("//", 1)[-1]
            if not any(x in h for x in ("google", "cloudflare", "gstatic", "jquery",
                                        "bootstrap", "w3.org", "schema.org", "mozilla")):
                urls.add(h)
    suspicious = bool(hits["net"] and (hits["cookie"] or hits["storage"] or hits["obf"] or hits["eval"])) or minified
    return {"name": man.get("name", ""), "mv": man.get("manifest_version", ""),
            "own_js": len(own), "own_kb": round(own_bytes / 1024, 1),
            "minified": int(minified), **hits,
            "ext_urls": " ".join(sorted(urls)[:6]), "suspicious": int(suspicious),
            "own_files": " ".join(sorted(own)[:8])}

def main():
    bucket = sys.argv[1] if len(sys.argv) > 1 else "silent_capable"
    tri = REPO / "eval" / "results" / "triage.csv"
    ids = [r["ext_id"] for r in csv.DictReader(open(tri, encoding="utf-8"))
           if r["bucket"] == bucket]
    print(f"[static_scan] bucket={bucket}: {len(ids)} mau\n")
    rows = []
    for eid in ids:
        crx = find_crx(eid)
        if not crx:
            rows.append({"ext_id": eid, "found": 0}); continue
        try:
            r = scan_crx(crx); r["ext_id"] = eid; r["found"] = 1
        except Exception as e:
            r = {"ext_id": eid, "found": 1, "name": "SCAN_ERROR:" + str(e)[:60]}
        rows.append(r)
    cols = ["ext_id", "found", "name", "mv", "own_js", "own_kb", "minified",
            "net", "eval", "obf", "cookie", "storage", "webreq", "inject", "redirect",
            "suspicious", "ext_urls", "own_files"]
    out = REPO / "eval" / "results" / "static_scan.csv"
    with open(out, "w", newline="", encoding="utf-8") as f:
        w = csv.DictWriter(f, fieldnames=cols, extrasaction="ignore")
        w.writeheader()
        for r in rows:
            w.writerow(r)
    found = [r for r in rows if r.get("found")]
    susp = [r for r in found if r.get("suspicious")]
    mini = [r for r in found if r.get("minified")]
    print(f"tim thay CRX: {len(found)}/{len(ids)}")
    print(f"CAN DOC SAU (suspicious): {len(susp)}  | trong do minified/obfuscated: {len(mini)}")
    print(f"co ve sach (khong suspicious): {len(found)-len(susp)}  -> tam phan loai benign_or_dead")
    print(f"\n-> {out}")
    print("\nDANH SACH CAN DOC SAU:")
    for r in susp:
        tags = [k for k in IND if r.get(k)]
        print(f"  {r['ext_id']}  min={r['minified']}  [{','.join(tags)}]  urls: {r.get('ext_urls','')[:60]}")

if __name__ == "__main__":
    main()
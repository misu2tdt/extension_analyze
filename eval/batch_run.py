"""B2 batch runner: chay tung CRX qua sandbox container, luu events.json ra dia.
Bypass API/Celery/DB. Resumable. Goi cung container ma production goi."""
import argparse, json, shutil, subprocess, time
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path

IMAGE = "extanalyze-sandbox:latest"

def ext_id_from(path: Path) -> str:
    stem = path.stem
    head = stem.split("_")[0]
    cid = "".join(c for c in head if c.isalnum()).lower()
    return cid if len(cid) == 32 else "".join(c for c in stem if c.isalnum()).lower()

def run_one(crx: Path, results_dir: Path, label: str, timeout: int) -> dict:
    eid = ext_id_from(crx)
    out = results_dir / eid
    events_path = out / "output" / "events.json"
    if events_path.exists():
        return {"ext_id": eid, "status": "skipped"}          # resumable
    (out / "output").mkdir(parents=True, exist_ok=True)
    staged = out / "extension.crx"
    shutil.copy2(crx, staged)      # stage sang path ASCII sach -> tranh loi space/unicode khi mount
    host = str(out.resolve()).replace("\\", "/")             # Windows: forward-slash cho Docker Desktop
    cmd = ["docker", "run", "--rm", "-v", f"{host}:/work",
           IMAGE, "/work/extension.crx", "/work/output", str(timeout)]
    t0 = time.time()
    try:
        p = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout + 90)
        exit_code = p.returncode
        err = "" if exit_code == 0 else ((p.stderr or p.stdout) or "")[-300:]
    except subprocess.TimeoutExpired:
        exit_code, err = -1, "docker_wall_timeout"
    dur = round(time.time() - t0, 1)
    try:
        staged.unlink(missing_ok=True)
        shutil.rmtree(out / "output" / "extension_unpacked", ignore_errors=True)
    except Exception:
        pass
    meta = {"ext_id": eid, "source_path": str(crx), "source_folder": crx.parent.name,
            "source_filename": crx.name, "label": label, "timeout": timeout,
            "docker_exit": exit_code, "duration_s": dur, "error": err}
    (out / "meta.json").write_text(json.dumps(meta, ensure_ascii=False, indent=2), encoding="utf-8")
    return {"ext_id": eid, "status": "ok" if events_path.exists() else "no_events",
            "exit": exit_code, "dur": dur}

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--samples", nargs="+", required=True, help="thu muc chua .crx")
    ap.add_argument("--results", default="eval/results")
    ap.add_argument("--label", required=True, choices=["malicious", "benign"])
    ap.add_argument("--workers", type=int, default=2)
    ap.add_argument("--timeout", type=int, default=180)
    ap.add_argument("--limit", type=int, default=0, help="chi chay N mau dau (validate)")
    a = ap.parse_args()

    crxs = []
    for s in a.samples:
        crxs += sorted(Path(s).rglob("*.crx"))
    if a.limit:
        crxs = crxs[:a.limit]
    results = Path(a.results); results.mkdir(parents=True, exist_ok=True)
    print(f"[batch] {len(crxs)} CRX | label={a.label} | workers={a.workers} | timeout={a.timeout}s")
    done = 0
    with ThreadPoolExecutor(max_workers=a.workers) as ex:
        futs = {ex.submit(run_one, c, results, a.label, a.timeout): c for c in crxs}
        for f in as_completed(futs):
            r = f.result(); done += 1
            tail = "" if r["status"] == "skipped" else f" exit={r.get('exit')} {r.get('dur')}s"
            print(f"[{done}/{len(crxs)}] {r['ext_id']}: {r['status']}{tail}")
    print("[batch] xong. Chay tiep: python eval/rescore.py")

if __name__ == "__main__":
    main()

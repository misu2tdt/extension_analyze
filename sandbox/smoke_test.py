#!/usr/bin/env python3
"""
Smoke test: chay canary qua analyze.py, khang dinh cac cam bien deu song.
Chay trong container sandbox:
    docker run --rm --entrypoint python3 extanalyze-sandbox:latest /sandbox/smoke_test.py
Exit 0 = tat ca OK. Exit 1 = co sensor chet.
"""
import io
import json
import struct
import subprocess
import sys
import time
import zipfile
from pathlib import Path

SANDBOX = Path(__file__).resolve().parent
CANARY_DIR = SANDBOX / "canary"
HONEY_DIR = SANDBOX / "honey_pages"
OUTPUT_DIR = Path("/tmp/smoke_out")
CRX_PATH = Path("/tmp/canary.crx")


def build_crx(src_dir: Path, crx_path: Path):
    """Zip canary + prepend CRX3 prefix toi thieu (extract_crx chi bo qua header)."""
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as z:
        for f in sorted(src_dir.iterdir()):
            if f.is_file():
                z.writestr(f.name, f.read_bytes())
    crx = b"Cr24" + struct.pack("<I", 3) + struct.pack("<I", 0) + buf.getvalue()
    crx_path.write_bytes(crx)


def run_timeout_check():
    """Ep honeypot_pages timeout (budget=1s) de kiem chung lifecycle bao partial dung."""
    import os
    out2 = Path("/tmp/smoke_out_timeout")
    env = dict(os.environ, PHASE_BUDGET_HONEYPOT_PAGES="1")
    subprocess.run(
        ["xvfb-run", "-a", "--server-args=-screen 0 1280x720x24",
         "python3", str(SANDBOX / "analyze.py"),
         "--crx", str(CRX_PATH), "--output", str(out2), "--timeout", "90"],
        check=True, timeout=200, env=env,
    )
    events = json.loads((out2 / "events.json").read_text(encoding="utf-8"))
    rs = events.get("run_status", {})
    phases = {p["name"]: p["status"] for p in events.get("phases", [])}

    checks = [
        ("run_status = partial", rs.get("status") == "partial"),
        ("honeypot_pages = timed_out", phases.get("honeypot_pages") == "timed_out"),
        ("load = completed", phases.get("load") == "completed"),
    ]
    print("\n=== LIFECYCLE TIMEOUT CHECK ===")
    failed = 0
    for name, ok in checks:
        print(f"  [{'PASS' if ok else 'FAIL'}] {name}")
        failed += 0 if ok else 1
    if failed:
        print("  run_status:", json.dumps(rs, ensure_ascii=False))
        print("  phases:", json.dumps(phases, ensure_ascii=False))
    return failed


def main():
    honey = subprocess.Popen(
        ["python3", "-m", "http.server", "8888", "--directory", str(HONEY_DIR)],
        stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
    )
    time.sleep(1)
    try:
        build_crx(CANARY_DIR, CRX_PATH)
        print(f"[smoke] built {CRX_PATH} ({CRX_PATH.stat().st_size} bytes)")

        subprocess.run(
            ["xvfb-run", "-a", "--server-args=-screen 0 1280x720x24",
             "python3", str(SANDBOX / "analyze.py"),
             "--crx", str(CRX_PATH), "--output", str(OUTPUT_DIR),
             "--timeout", "90"],
            check=True, timeout=200,
        )

        events = json.loads((OUTPUT_DIR / "events.json").read_text(encoding="utf-8"))
        s = events["summary"]
        reqs = events.get("network_requests", [])

        # Beacon positive control: dung 4 request toi host rieng, deu (cv nho).
        beacon_reqs = [r for r in reqs if r.get("host") == "canary-beacon.invalid"]
        beacon_ts = sorted(r["t"] for r in beacon_reqs if r.get("t") is not None)

        tm_hosts = events.get("target_matched_hosts", [])
        tm_hit = any(r.get("host") == "canary-target-hit.invalid" for r in reqs)

        checks = [
            ("1  network: SW fetch bat duoc",
             any(r.get("host") == "canary-c2.invalid" for r in reqs)),
            ("1b SW-origin gan dung",
             s.get("service_worker_requests", 0) >= 1),
            ("2  payload: honeypot trong POST body",
             events.get("honeypot_exfil") is True),
            ("3  tab moi tu service worker",
             s.get("new_tabs_opened", 0) >= 1),
            ("4  DOM injection (script/iframe)",
             s.get("scripts_injected", 0) >= 1),
            ("5  honeypot trong storage",
             events.get("honeypot_stored") is True),
            ("6  service worker duoc thay",
             s.get("service_worker_count", 0) >= 1),
            ("7  beacon: dung 4 request toi canary-beacon.invalid",
             len(beacon_reqs) == 4),
            ("7b beacon: co timestamp t (A1.0 - CDP SW stamp)",
             len(beacon_ts) == 4),
            ("8  target_matched doc dung host tu manifest",
             "canary-target.invalid" in tm_hosts),
            ("8b target_matched spoof => content script tiem (beacon canary-target-hit)",
             tm_hit),
        ]

        print("\n=== SMOKE TEST ===")
        failed = 0
        for name, ok in checks:
            print(f"  [{'PASS' if ok else 'FAIL'}] {name}")
            failed += 0 if ok else 1

        if failed:
            print("\n--- beacon reqs (chan doan A1) ---")
            print(f"  count={len(beacon_reqs)} timestamps={beacon_ts}")
            print("\n--- target_matched (chan doan B3) ---")
            print(f"  hosts={tm_hosts} hit={tm_hit}")
            print(f"  visited={events.get('target_matched_visited')} note={events.get('target_matched_note')}")
            print("\n--- summary (de debug) ---")
            print(json.dumps(s, indent=2, ensure_ascii=False))
            print("\n--- storage hits (chan doan beacon) ---")
            hits = events.get("extension_storage", {}).get("honeypot_hits", [])
            print(json.dumps(hits, indent=2, ensure_ascii=False))

        tf = run_timeout_check()
        print(f"\n{len(checks) - failed}/{len(checks)} sensor OK, "
              f"lifecycle timeout check: {'PASS' if tf == 0 else 'FAIL'}")
        sys.exit(1 if (failed or tf) else 0)
    finally:
        honey.terminate()


if __name__ == "__main__":
    main()
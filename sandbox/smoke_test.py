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
        ]

        print("\n=== SMOKE TEST ===")
        failed = 0
        for name, ok in checks:
            print(f"  [{'PASS' if ok else 'FAIL'}] {name}")
            failed += 0 if ok else 1

        if failed:
            print("\n--- summary (de debug) ---")
            print(json.dumps(s, indent=2, ensure_ascii=False))
            print("\n--- storage hits (chan doan beacon) ---")
            hits = events.get("extension_storage", {}).get("honeypot_hits", [])
            print(json.dumps(hits, indent=2, ensure_ascii=False))

        print(f"\n{len(checks) - failed}/{len(checks)} sensor OK")
        sys.exit(1 if failed else 0)
    finally:
        honey.terminate()


if __name__ == "__main__":
    main()
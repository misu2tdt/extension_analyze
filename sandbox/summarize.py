import json
from pathlib import Path

results_dir = Path("batch_results")

print(f"{'Sample':<40} {'Requests':>10} {'Pages':>7} {'Errors':>7} {'Honeypot':>10}")
print("-" * 80)

HONEYPOT_MARKERS = ["HONEYPOT", "sk-HONEYPOT", "ghp_HONEYPOT", "AKIAHONEYPOT"]

for sample_dir in sorted(results_dir.iterdir()):
    events_file = sample_dir / "events.json"
    if not events_file.exists():
        print(f"{sample_dir.name:<40} {'NO OUTPUT':>10}")
        continue

    with open(events_file, encoding="utf-8") as f:
        events = json.load(f)

    reqs = events.get("network_requests", [])
    pages = events.get("pages_visited", [])
    errors = events.get("errors", [])

    # Check honeypot exfil trong URL request
    honeypot_hit = "NO"
    for req in reqs:
        url = req.get("url", "")
        if any(m in url for m in HONEYPOT_MARKERS):
            honeypot_hit = "YES!"
            break

    # Rut gon ten (bo tien to MALWARE_)
    name = sample_dir.name.replace("MALWARE_", "")[:38]
    print(f"{name:<40} {len(reqs):>10} {len(pages):>7} {len(errors):>7} {honeypot_hit:>10}")

# Liet ke domain ngoai (khong phai localhost) tung sample goi
print("\n=== External domains contacted ===")
from urllib.parse import urlparse
for sample_dir in sorted(results_dir.iterdir()):
    events_file = sample_dir / "events.json"
    if not events_file.exists():
        continue
    with open(events_file, encoding="utf-8") as f:
        events = json.load(f)
    domains = set()
    for req in events.get("network_requests", []):
        host = urlparse(req.get("url", "")).hostname
        if host and "localhost" not in host and "127.0.0.1" not in host:
            domains.add(host)
    name = sample_dir.name.replace("MALWARE_", "")[:30]
    if domains:
        print(f"\n[{name}]")
        for d in sorted(domains):
            print(f"    {d}")
"""
Test tang phan tich TACH KHOI sandbox: khong can Docker/browser,
chi can du lieu events -> kiem tra dien giai dung.
Chay: python worker/test_undeclared.py
"""
from risk import detect_undeclared_domains, build_behavioral_report, compute_risk_score

# events toi gian mo phong canary: SW goi domain la, page goi domain la,
# khai bao rong, co ca example.com (harness) de kiem tra loc.
fake_events = {
    "manifest": {"name": "canary", "host_permissions": [], "permissions": []},
    "network_requests": [
        {"url": "https://canary-c2.invalid/collect", "origin": "service_worker"},
        {"url": "https://canary-inject.invalid/x.js", "origin": "page"},
        {"url": "https://canary-frame.invalid/y.html", "origin": "page"},
        {"url": "https://example.com/", "origin": "page"},          # harness -> phai loc
    ],
    "honeypot_exfil": True,
    "page_hang_count": 0,
}

r = detect_undeclared_domains(fake_events)
assert r["has_undeclared"] is True, "phai phat hien undeclared"
assert "canary-c2.invalid" in r["undeclared_from_sw"], "SW C2 phai bi bat"
assert "canary-inject.invalid" in r["undeclared_from_page"], "page domain phai bi bat"
assert "example.com" not in r["undeclared_total"], "harness phai bi loc"
print("detect PASS:", r)

report = build_behavioral_report(fake_events)
score, level = compute_risk_score(report)
assert report["indicators"]["undeclared_domain_contact"] is True, "indicator phai bat"
assert "dynamic" in report, "report phai co khoi dynamic"
print(f"score PASS: {score} ({level})")
print("dynamic block:", report["dynamic"])

"""
Test tang phan tich TACH KHOI sandbox: khong can Docker/browser,
chi can du lieu events -> kiem tra dien giai dung.
Chay: python worker/test_undeclared.py
"""
from risk import (
    detect_undeclared_domains, detect_unsolicited_tabs, detect_script_injection,
    build_behavioral_report, compute_risk_score,
)

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
score, level, _ = compute_risk_score(report)
assert report["indicators"]["undeclared_domain_contact"] is True, "indicator phai bat"
assert "dynamic" in report, "report phai co khoi dynamic"
print(f"score PASS: {score} ({level})")
print("dynamic block:", report["dynamic"])


print("\n=== TEST TACH STATIC/DYNAMIC ===")

def score_of(events):
    rep = build_behavioral_report(events)
    return compute_risk_score(rep)

# KB1: manifest xau, runtime im lang => static cao, dynamic ~0
kb1 = {
    "manifest": {"name": "x", "permissions": ["cookies", "tabs", "history", "webRequest", "scripting"],
                 "host_permissions": ["<all_urls>"],
                 "content_scripts": [{"matches": ["<all_urls>"], "js": ["a.js"]}]},
    "network_requests": [], "honeypot_exfil": False, "page_hang_count": 0,
}
r1, l1, b1 = score_of(kb1)
print(f"KB1 manifest xau, runtime im: risk={r1} ({l1}) | static={b1['static_score']} dynamic={b1['dynamic_score']}")
assert b1["static_score"] > 0 and b1["dynamic_score"] == 0

# KB2: manifest SACH, runtime goi C2 tu SW => static ~0, dynamic cao  <-- DYNAMIC TOA SANG
kb2 = {
    "manifest": {"name": "y", "permissions": [], "host_permissions": []},
    "network_requests": [{"url": "https://evil-c2.xyz/beacon", "origin": "service_worker"}],
    "honeypot_exfil": False, "page_hang_count": 0,
}
r2, l2, b2 = score_of(kb2)
print(f"KB2 manifest sach, runtime C2: risk={r2} ({l2}) | static={b2['static_score']} dynamic={b2['dynamic_score']}")
assert b2["dynamic_score"] > 0, "dynamic phai bat duoc C2 du manifest sach"
assert b2["static_score"] == 0, "manifest sach thi static phai ~0"

# KB3: ca hai cung xau => corroboration
kb3 = {
    "manifest": {"name": "z", "permissions": ["cookies", "webRequest", "scripting", "tabs"],
                 "host_permissions": ["<all_urls>"]},
    "network_requests": [{"url": "https://evil-c2.xyz/x", "origin": "service_worker"}],
    "honeypot_exfil": True, "page_hang_count": 0,
}
r3, l3, b3 = score_of(kb3)
print(f"KB3 ca hai xau:              risk={r3} ({l3}) | static={b3['static_score']} dynamic={b3['dynamic_score']}")
assert r3 >= max(b3["static_score"], b3["dynamic_score"]), "corroboration phai >= max"

print("\n=== TEST UNSOLICITED TAB ===")
ev_tab = {
    "manifest": {"name": "t", "host_permissions": [], "permissions": []},
    "network_requests": [],
    "new_tabs": [
        {"url": "https://evil.site/pop", "phase": "load"},          # extension mo -> tinh
        {"url": "about:blank", "phase": "honeypot_pages"},          # harness -> bo
        {"url": "https://ad.site/x", "phase": "extension_pages"},   # harness phase -> bo
    ],
    "honeypot_exfil": False, "page_hang_count": 0,
}
res = detect_unsolicited_tabs(ev_tab)
assert res["has_unsolicited"] is True
assert res["count"] == 1, f"chi 1 tab extension, duoc {res['count']}"
assert res["unsolicited_tabs"][0]["url"] == "https://evil.site/pop"
print("PASS:", res)

print("\n=== TEST SCRIPT INJECTION ===")
ev_inj = {
    "manifest": {"name": "i", "host_permissions": [], "permissions": []},
    "network_requests": [],
    "dom_activity": [
        {"type": "node_injected", "tag": "SCRIPT",
         "src": "https://evil-cdn.xyz/x.js", "page_url": "http://localhost:8888/bank.html"},  # cross-origin -> tinh
        {"type": "node_injected", "tag": "FORM",
         "src": "http://localhost:8888/bank.html", "page_url": "http://localhost:8888/bank.html"},  # same-origin -> bo
        {"type": "node_injected", "tag": "SCRIPT",
         "src": "(inline)", "page_url": "http://localhost:8888/bank.html"},  # inline -> bo
        {"type": "mutation_summary", "injected_nodes": 5, "page_url": "x"},  # khong phai node_injected -> bo
    ],
    "honeypot_exfil": False, "page_hang_count": 0,
}
res = detect_script_injection(ev_inj)
assert res["has_injection"] is True
assert res["count"] == 1, f"chi 1 node cross-origin, duoc {res['count']}"
assert res["injected_nodes"][0]["host"] == "evil-cdn.xyz"
print("PASS:", res)

print("\nTAT CA PASS")
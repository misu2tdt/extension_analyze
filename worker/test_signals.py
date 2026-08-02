"""
Test tang phan tich TACH KHOI sandbox: khong can Docker/browser,
chi can du lieu events -> kiem tra dien giai dung.
Chay: python worker/test_undeclared.py
"""
from risk import (
    detect_undeclared_domains, detect_unsolicited_tabs, detect_script_injection,
    detect_local_harvest, detect_beaconing, build_behavioral_report, compute_risk_score,
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

print("\n=== TEST LOCAL HARVEST ===")
ev_harvest = {
    "manifest": {"name": "h", "host_permissions": [], "permissions": []},
    "network_requests": [],           # KHONG gui ra network
    "extension_storage": {
        "total_bytes": 200,
        "honeypot_hits": [
            {"ext_id": "abc", "file": "000003.log",
             "markers": ["HONEYPOT", "HONEYPOT-PASSWORD"], "snippet": "..."},
        ],
    },
    "honeypot_exfil": False,          # exfil = False (chua gui)
    "page_hang_count": 0,
}
res = detect_local_harvest(ev_harvest)
assert res["has_harvest"] is True, "phai phat hien harvest trong storage"
assert "HONEYPOT-PASSWORD" in res["harvested_markers"]
print("PASS:", res)

# Kiem tra: harvest bat duoc DU exfil=False (storage thay cai network bo sot)
rep = build_behavioral_report(ev_harvest)
score, level, bd = compute_risk_score(rep)
assert rep["indicators"]["local_harvest"] is True
assert rep["indicators"]["credential_exfil"] is False, "network khong thay gi"
assert bd["dynamic_score"] >= 30, "harvest phai dong gop diem dynamic"
print(f"score PASS: dynamic={bd['dynamic_score']} (harvest bat duoc du network im lang)")

print("\n=== TEST BEACONING ===")

def _req(url, t, phase="honeypot_pages", origin="service_worker"):
    return {"url": url, "host": url.split("/")[2], "t": t, "phase": phase, "origin": origin}

# (1) DUONG: SW beacon deu tuyet doi toi host KHONG khai bao => C2.
ev_beacon = {
    "manifest": {"name": "b", "host_permissions": [], "permissions": []},
    "network_requests": [
        _req("https://beacon-c2.invalid/p", 1.0, "honeypot_pages"),
        _req("https://beacon-c2.invalid/p", 3.0, "honeypot_pages"),
        _req("https://beacon-c2.invalid/p", 5.0, "target_matched"),
        _req("https://beacon-c2.invalid/p", 7.0, "extension_pages"),
        _req("https://beacon-c2.invalid/p", 9.0, "delayed_observation"),
    ],
    "honeypot_exfil": False, "page_hang_count": 0,
}
res = detect_beaconing(ev_beacon)
assert res["has_beaconing"] is True
assert res["count"] == 1, f"chi 1 beacon, duoc {res['count']}"
b0 = res["beacons"][0]
assert b0["host"] == "beacon-c2.invalid"
assert b0["count"] == 5, f"5 request, duoc {b0['count']}"
assert b0["cv"] == 0.0, f"deu tuyet doi cv phai 0.0, duoc {b0['cv']}"
assert b0["interval_mean_s"] == 2.0
assert b0["host_undeclared"] is True, "host la phai bi danh dau undeclared"
assert b0["spans_phases"] == 4, f"trai 4 phase, duoc {b0['spans_phases']}"
assert res["has_undeclared_beacon"] is True
print("PASS undeclared beacon:", b0)

rep = build_behavioral_report(ev_beacon)
_, _, bd = compute_risk_score(rep)
assert rep["indicators"]["beaconing"] is True
assert bd["dynamic_score"] == 50, f"undeclared_sw(30)+beacon(20)=50, duoc {bd['dynamic_score']}"
print(f"score PASS: dynamic={bd['dynamic_score']} (undeclared_sw 30 + beacon 20)")

# (2) AM - jitter: interval khong deu => cv > nguong => KHONG phai beacon.
ev_jitter = {
    "manifest": {"name": "j", "host_permissions": [], "permissions": []},
    "network_requests": [
        _req("https://jitter.invalid/x", 1.0),
        _req("https://jitter.invalid/x", 1.5),
        _req("https://jitter.invalid/x", 4.0),
        _req("https://jitter.invalid/x", 4.2),
        _req("https://jitter.invalid/x", 9.0),
    ],
    "honeypot_exfil": False, "page_hang_count": 0,
}
assert detect_beaconing(ev_jitter)["has_beaconing"] is False, "traffic khong deu khong duoc tinh beacon"
print("PASS jitter -> khong beacon")

# (3) AM - it mau: 3 request (<MIN_BEACON_REQUESTS) => khong phan quyet.
ev_sparse = {
    "manifest": {"name": "s", "host_permissions": [], "permissions": []},
    "network_requests": [
        _req("https://sparse.invalid/x", 2.0),
        _req("https://sparse.invalid/x", 4.0),
        _req("https://sparse.invalid/x", 6.0),
    ],
    "honeypot_exfil": False, "page_hang_count": 0,
}
assert detect_beaconing(ev_sparse)["has_beaconing"] is False, "3 request thi chua ket luan"
print("PASS sparse -> insufficient samples")

# (4) AM - tight loop: interval 0.1s < MIN_PERIOD_S du cv=0 => khong phai beacon.
ev_loop = {
    "manifest": {"name": "l", "host_permissions": [], "permissions": []},
    "network_requests": [_req("https://loop.invalid/x", 1.0 + i * 0.1) for i in range(5)],
    "honeypot_exfil": False, "page_hang_count": 0,
}
assert detect_beaconing(ev_loop)["has_beaconing"] is False, "tight loop khong phai beacon"
print("PASS tight loop -> khong beacon")

# (5) AM ve DE DOA - beacon toi host DA KHAI BAO (telemetry lanh tinh): chi base(8).
ev_telemetry = {
    "manifest": {"name": "t", "host_permissions": ["https://api.myext.io/*"], "permissions": []},
    "network_requests": [
        _req("https://api.myext.io/ping", 1.0),
        _req("https://api.myext.io/ping", 3.0),
        _req("https://api.myext.io/ping", 5.0),
        _req("https://api.myext.io/ping", 7.0),
        _req("https://api.myext.io/ping", 9.0),
    ],
    "honeypot_exfil": False, "page_hang_count": 0,
}
res = detect_beaconing(ev_telemetry)
assert res["has_beaconing"] is True, "van phat hien nhip"
assert res["has_undeclared_beacon"] is False, "host da khai bao => khong phai C2"
assert res["beacons"][0]["host_undeclared"] is False
rep = build_behavioral_report(ev_telemetry)
_, _, bd = compute_risk_score(rep)
assert bd["dynamic_score"] == 8, f"beacon toi host khai bao chi base 8, duoc {bd['dynamic_score']}"
print(f"score PASS: telemetry host khai bao => dynamic={bd['dynamic_score']} (chi base, khong phat oan)")

print("\nTAT CA PASS")
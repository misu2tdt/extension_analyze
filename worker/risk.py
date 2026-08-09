"""
Risk scoring + behavioral report builder.
Signal thiet ke dua tren hanh vi THAT tu 4 malware sample (chien dich 108-extension):
  - Overprivilege, suspicious host, broad content-script scope, page hang, honeypot exfil
"""
import statistics
from urllib.parse import urlparse

DANGEROUS_PERMISSIONS = {
    "webRequest", "webRequestBlocking", "declarativeNetRequest",
    "downloads", "scripting", "management", "cookies", "history",
    "tabs", "clipboardRead", "clipboardWrite", "debugger", "proxy",
    "<all_urls>",
}

BROAD_MATCH_PATTERNS = {"<all_urls>", "http://*/*", "https://*/*", "*://*/*"}

KNOWN_INFRA_HOSTS = {
    # Google infra / analytics / ads / fonts
    "clients2.google.com", "www.google.com", "google.com", "accounts.google.com",
    "apis.google.com", "gstatic.com", "fonts.googleapis.com", "fonts.gstatic.com",
    "googleapis.com", "googletagmanager.com", "google-analytics.com",
    "analytics.google.com", "doubleclick.net", "googleadservices.com",
    "googlesyndication.com", "gvt1.com", "gvt2.com",
    # CDN / thu vien tinh (chi subdomain lanh, KHONG whitelist cloud chung chung)
    "jsdelivr.net", "unpkg.com", "cdnjs.cloudflare.com", "fontawesome.com",
    "challenges.cloudflare.com", "cloudflareinsights.com",
    # Social pixel / analytics / error-reporting (dual-use nhe, nhung khong phan biet duoc)
    "connect.facebook.net", "www.facebook.com", "facebook.com", "fbcdn.net",
    "sentry.io", "bat.bing.com", "c.bing.com", "bing.com", "mc.yandex.ru",
    # Harness / local
    "example.com", "localhost", "127.0.0.1",
    # LUU Y: KHONG whitelist amazonaws (S3 hay bi dung exfil) hay cloudflare-workers
    # (hay bi dung C2). Chi liet ke subdomain chac chan lanh.
}

# ==================== TIN HIEU DYNAMIC ====================
# Host do HARNESS chu dong ghe (khong phai extension goi) => loai khoi undeclared.
# Nang cap sau: thay bang loc theo phase thay vi danh sach cung.
HARNESS_HOSTS = {
    "localhost", "127.0.0.1", "example.com", "www.example.com",
}

# Phase ma HARNESS chu dong mo tab => tab o day khong phai extension tu mo.
HARNESS_PHASES = {"honeypot_pages", "extension_pages"}

# Trong so cham diem dynamic. Gom mot cho de tinh chinh o chuong thuc nghiem.
DYNAMIC_WEIGHTS = {
    "undeclared_domain_sw": 30,     # SW goi domain la => C2 ngam, nang hon
    "undeclared_domain_page": 15,   # page goi domain la => nhe hon
    "undeclared_per_extra": 5,      # moi domain la them
    "undeclared_cap": 40,           # tran cho nhom undeclared
    "unsolicited_tab": 15,
    "script_injection": 15,
    "local_harvest": 30,
    # Beaconing: nhip deu tu than YEU (telemetry lanh tinh cung beacon: GA/Sentry).
    # Chi leo thang khi beacon toi host KHONG khai bao => cung co gia thuyet C2.
    # Bang chung field: Palo Alto DeepSeek case - C2 la mot host RIENG, khong khai bao.
    "beaconing_base": 8,               # co nhip, toi host bat ky
    "beaconing_undeclared_bonus": 12,  # nhip toi host la => tong 20, duoi undeclared_sw(30)
}

# Nguong beaconing. Don vi phan tich la INTERVAL (khoang cach 2 request lien tiep
# cung host), khong phai request => k request cho k-1 interval.
MIN_BEACON_REQUESTS = 4     # >=3 interval moi noi duoc ve do deu; san than trong
BEACON_CV_MAX = 0.25        # coefficient of variation toi da; tunable [0.15-0.35],
                            # KHONG claim toi uu. C2 that jitter ~10-20% => cv ~0.06-0.12.
MIN_PERIOD_S = 0.5          # mean interval duoi nguong nay = tight loop, khong phai beacon


def _host_of(url: str) -> str:
    try:
        return (urlparse(url).hostname or "").lower()
    except Exception:
        return ""


# Scheme noi bo / khong phai lien lac mang ra ngoai => bo qua khi tinh domain.
_INTERNAL_SCHEMES = ("chrome-extension://", "chrome://", "moz-extension://",
                     "edge://", "about:", "data:", "blob:", "filesystem:")


def _is_real_domain(host: str) -> bool:
    """Domain thuc su ra ngoai: co dau '.' (loai extension-id 32 ky tu, localhost-like)."""
    return bool(host) and "." in host


def _extract_suspicious_hosts(manifest: dict) -> list:
    name = (manifest.get("name", "") or "").lower()
    desc = (manifest.get("description", "") or "").lower()

    hosts = set()
    for hp in manifest.get("host_permissions", []):
        h = _host_of(hp.replace("*://", "https://").replace("*", "x"))
        if h:
            hosts.add(h)
    for cs in manifest.get("content_scripts", []):
        for m in cs.get("matches", []):
            h = _host_of(m.replace("*://", "https://").replace("*", "x"))
            if h:
                hosts.add(h)

    suspicious = []
    for h in hosts:
        if any(known in h for known in KNOWN_INFRA_HOSTS):
            continue
        if "amazon" in h or "google" in h or "facebook" in h:
            continue
        core = h.split(".")[-2] if "." in h else h
        if core and core not in name and core not in desc:
            suspicious.append(h)
    return sorted(set(suspicious))


def _manifest_declared_hosts(manifest: dict) -> set:
    """Host ma extension KHAI BAO trong manifest (host_permissions + content_scripts)."""
    declared = set()
    for hp in manifest.get("host_permissions", []):
        h = _host_of(hp.replace("*://", "https://").replace("*", "x"))
        if h:
            declared.add(h)
    for cs in manifest.get("content_scripts", []):
        for m in cs.get("matches", []):
            h = _host_of(m.replace("*://", "https://").replace("*", "x"))
            if h:
                declared.add(h)
    return declared


def detect_undeclared_domains(events: dict) -> dict:
    """
    TIN HIEU DYNAMIC: domain extension GOI luc chay ma KHONG khai bao trong manifest.
    Tach rieng nguon service_worker vs page (SW dang ngo hon).
    Loc bo host do harness ghe.
    """
    manifest = events.get("manifest", {})
    declared = _manifest_declared_hosts(manifest)

    from_sw, from_page = set(), set()
    for r in events.get("network_requests", []):
        url = r.get("url", "")
        if url.startswith(_INTERNAL_SCHEMES):      # Fix A: bo request noi bo extension
            continue
        host = _host_of(url)
        if not _is_real_domain(host) or host in HARNESS_HOSTS or host in declared:
            continue
        if any(known in host for known in KNOWN_INFRA_HOSTS):
            continue
        if r.get("origin") == "service_worker":
            from_sw.add(host)
        else:
            from_page.add(host)

    return {
        "undeclared_from_sw": sorted(from_sw),
        "undeclared_from_page": sorted(from_page),
        "undeclared_total": sorted(from_sw | from_page),
        "has_undeclared": bool(from_sw or from_page),
    }


def detect_unsolicited_tabs(events: dict) -> dict:
    """
    TIN HIEU DYNAMIC: tab do EXTENSION tu mo (khong phai harness).
    Loc bang PHASE: harness chi mo tab trong honeypot_pages/extension_pages.
    """
    ext_tabs = []
    for tab in events.get("new_tabs", []):
        phase = tab.get("phase")
        url = tab.get("url", "")
        if phase in HARNESS_PHASES:      # tab do harness mo
            continue
        if url in ("", "about:blank"):   # tab rong, bo qua (nang cap sau: theo redirect)
            continue
        ext_tabs.append({"url": url, "phase": phase})
    return {
        "unsolicited_tabs": ext_tabs,
        "count": len(ext_tabs),
        "has_unsolicited": len(ext_tabs) > 0,
    }


def detect_script_injection(events: dict) -> dict:
    """
    TIN HIEU DYNAMIC: extension chen SCRIPT/IFRAME co src CROSS-ORIGIN vao trang.
    Heuristic: node co src tro toi domain KHAC voi trang dang xem => dang ngo.
    Node inline / same-origin => bo (khong phan biet duoc voi node cua chinh trang).
    Gioi han: khong bat duoc inline injection (can taint tracking nhu Arcanum).
    """
    injected = []
    for act in events.get("dom_activity", []):
        if act.get("type") != "node_injected":
            continue
        src = act.get("src", "")
        if not src or src == "(inline)":
            continue
        node_host = _host_of(src)
        if not node_host or node_host in HARNESS_HOSTS:
            continue
        page_host = _host_of(act.get("page_url", ""))
        if node_host == page_host:
            continue
        injected.append({"tag": act.get("tag"), "src": src, "host": node_host})
    return {
        "injected_nodes": injected,
        "count": len(injected),
        "has_injection": len(injected) > 0,
    }


def detect_local_harvest(events: dict) -> dict:
    """
    TIN HIEU DYNAMIC: honeypot bi cat vao storage cua extension (LevelDB).
    = "da thu thap du chua kip gui" (MITRE T1074.001 Local Data Staging).
    Bo tro cho credential_exfil (T1041, da gui ra) - hai giai doan kill-chain khac nhau.
    Storage doc theo ext_id => khong lan harness, khong can loc.
    """
    storage = events.get("extension_storage", {})
    hits = storage.get("honeypot_hits", [])
    markers = sorted({m for hit in hits for m in hit.get("markers", [])})
    return {
        "harvested_markers": markers,
        "hit_count": len(hits),
        "has_harvest": len(hits) > 0,
    }


def detect_beaconing(events: dict) -> dict:
    """
    TIN HIEU DYNAMIC: nhip request DEU DAN toi cung mot host (C2 beaconing).
    Khac 5 tin hieu kia o CHAT: day la temporal pattern, phai do bang metric
    (coefficient of variation) chu khong boolean/count don thuan.

    Do do: gom request CO timestamp 't' theo HOST (khong theo path - exfil hay ma
    hoa data vao path nen path bien thien, host on dinh). Tinh interval giua cac
    request lien tiep => cv = pstdev/mean. Beacon neu cv <= BEACON_CV_MAX.

    Dung 't' TUONG DOI (hieu giua 2 request) => mien nhiem voi warm-up jitter va
    do KHONG neo vao _t0. Nhom PAGE + SW (SW la noi C2 hay xay ra nhat).

    Cross-ref undeclared: gan host_undeclared cho moi beacon. Trong so leo thang
    theo co qua _dynamic_score, KHONG double-count o day.
    spans_phases: tinh & report (nen cho Ex-Ray L0 sau), chua dua vao trong so.
    """
    undeclared_hosts = set(detect_undeclared_domains(events)["undeclared_total"])

    by_host = {}
    for r in events.get("network_requests", []):
        url = r.get("url", "")
        if url.startswith(_INTERNAL_SCHEMES):
            continue
        t = r.get("t")
        host = r.get("host") or _host_of(url)
        if t is None or not _is_real_domain(host) or host in HARNESS_HOSTS:
            continue
        by_host.setdefault(host, []).append(
            {"t": t, "phase": r.get("phase"), "origin": r.get("origin")})

    beacons = []
    for host, reqs in by_host.items():
        if len(reqs) < MIN_BEACON_REQUESTS:      # chua du mau => khong phan quyet
            continue
        ts = sorted(x["t"] for x in reqs)
        intervals = [round(ts[i + 1] - ts[i], 3) for i in range(len(ts) - 1)]
        mean = statistics.fmean(intervals)
        if mean < MIN_PERIOD_S:                  # tight loop, khong phai beacon
            continue
        cv = round(statistics.pstdev(intervals) / mean, 3) if mean > 0 else 0.0
        if cv > BEACON_CV_MAX:                    # khong du deu
            continue
        phases = sorted({x["phase"] for x in reqs if x["phase"]})
        origins = sorted({x["origin"] for x in reqs if x["origin"]})
        beacons.append({
            "host": host,
            "count": len(reqs),
            "interval_mean_s": round(mean, 3),
            "cv": cv,
            "jitter_pct": round(cv * 100, 1),
            "host_undeclared": host in undeclared_hosts,
            "spans_phases": len(phases),
            "phases": phases,
            "origins": origins,
        })

    # undeclared beacon len dau (dang ngo nhat), roi den do deu tang dan.
    beacons.sort(key=lambda b: (not b["host_undeclared"], b["cv"]))
    return {
        "beacons": beacons,
        "count": len(beacons),
        "has_beaconing": len(beacons) > 0,
        "has_undeclared_beacon": any(b["host_undeclared"] for b in beacons),
    }


# ---- A2: MITRE ATT&CK mapping ----
# Dan nhan CHUAN NGANH len tin hieu OBSERVED. Chi map technique QUAN SAT DUOC luc chay;
# cac heuristic tinh (overprivileged, has_suspicious_host, broad_injection,
# causes_page_hang) CO Y khong co o day - chung la thuoc tinh rui ro, khong phai
# technique doi thu => khong fit ep.
# severity = muc nghiem trong VON CO cua technique neu confirmed; truc KHAC voi weight
# trong scoring (weight co tinh FP). Hai truc doc lap, co tai lieu hoa.
SIGNAL_MITRE = {
    "credential_exfil": {
        "technique_id": "T1041",
        "technique_name": "Exfiltration Over C2 Channel",
        "tactic": "Exfiltration", "severity": "CRITICAL", "layer": "dynamic"},
    "local_harvest": {
        "technique_id": "T1074.001",
        "technique_name": "Local Data Staging",
        "tactic": "Collection", "severity": "HIGH", "layer": "dynamic"},
    "script_injection": {
        "technique_id": "T1059.007",
        "technique_name": "Command and Scripting Interpreter: JavaScript",
        "tactic": "Execution", "severity": "HIGH", "layer": "dynamic"},
    "beaconing": {
        "technique_id": "T1071.001",
        "technique_name": "Application Layer Protocol: Web Protocols",
        "tactic": "Command and Control", "severity": "MEDIUM", "layer": "dynamic"},
    "undeclared_domain_contact": {
        "technique_id": "T1071",
        "technique_name": "Application Layer Protocol",
        "tactic": "Command and Control", "severity": "MEDIUM", "layer": "dynamic"},
    # Thanh that KHONG map: ATT&CK Enterprise khong co technique khop cho browser
    # tab abuse (ad/redirect). Van emit finding de report BE LO khoang trong nay
    # (mot luan diem thesis) thay vi giau di hoac ep sang ma gan-gan.
    "unsolicited_tab": {
        "technique_id": None,
        "technique_name": None,
        "tactic": "Impact", "severity": "LOW", "layer": "dynamic",
        "note": "Browser tab abuse chua co technique khop trong ATT&CK Enterprise"},
}

_SEVERITY_ORDER = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3}


def build_findings(report: dict) -> list:
    """
    Dan nhan MITRE len cac tin hieu OBSERVED dang bat. ADDITIVE - KHONG feed score.
    Chi emit cho indicator co trong SIGNAL_MITRE. Sap xep severity giam dan.
    """
    ind = report.get("indicators", {})
    findings = [{"signal": sig, **meta}
                for sig, meta in SIGNAL_MITRE.items() if ind.get(sig)]
    findings.sort(key=lambda f: _SEVERITY_ORDER.get(f["severity"], 9))
    return findings


def build_behavioral_report(events: dict) -> dict:
    manifest = events.get("manifest", {})
    requests = events.get("network_requests", [])

    ext_domains = set()
    for r in requests:
        h = _host_of(r.get("url", ""))
        if h and h not in ("localhost", "127.0.0.1"):
            ext_domains.add(h)

    perms = set(manifest.get("permissions", []))
    host_perms = manifest.get("host_permissions", [])
    dangerous_perms = sorted(perms & DANGEROUS_PERMISSIONS)
    if "<all_urls>" in host_perms:
        dangerous_perms.append("<all_urls>")

    broad_scope = False
    for cs in manifest.get("content_scripts", []):
        if any(m in BROAD_MATCH_PATTERNS for m in cs.get("matches", [])):
            broad_scope = True
            break

    suspicious_hosts = _extract_suspicious_hosts(manifest)
    undeclared = detect_undeclared_domains(events)
    unsolicited = detect_unsolicited_tabs(events)
    injection = detect_script_injection(events)
    harvest = detect_local_harvest(events)
    beaconing = detect_beaconing(events)

    report = {
        "static": {
            "manifest_version": manifest.get("manifest_version"),
            "declared_permissions": sorted(perms),
            "dangerous_permissions": dangerous_perms,
            "dangerous_permission_count": len(dangerous_perms),
            "host_permission_count": len(host_perms),
            "broad_content_script_scope": broad_scope,
            "suspicious_hosts": suspicious_hosts,
        },
        "network": {
            "total_requests": len(requests),
            "external_domains": sorted(ext_domains),
            "external_domain_count": len(ext_domains),
        },
        "runtime": {
            "pages_visited": len(events.get("pages_visited", [])),
            "page_hang_count": events.get("page_hang_count", 0),
            "honeypot_exfil": events.get("honeypot_exfil", False),
            "console_log_count": len(events.get("console_logs", [])),
            "error_count": len(events.get("errors", [])),
        },
        "dynamic": {
            "undeclared_domains": undeclared,
            "unsolicited_tabs": unsolicited,
            "script_injection": injection,
            "local_harvest": harvest,
            "beaconing": beaconing,
        },
        "indicators": {
            "credential_exfil": events.get("honeypot_exfil", False),
            "overprivileged": len(dangerous_perms) >= 4,
            "has_suspicious_host": len(suspicious_hosts) > 0,
            "broad_injection": broad_scope,
            "causes_page_hang": events.get("page_hang_count", 0) > 0,
            "undeclared_domain_contact": undeclared["has_undeclared"],
            "unsolicited_tab": unsolicited["has_unsolicited"],
            "script_injection": injection["has_injection"],
            "local_harvest": harvest["has_harvest"],
            "beaconing": beaconing["has_beaconing"],
        },
    }
    report["findings"] = build_findings(report)
    return report


# Trong so corroboration khi ket hop static & dynamic.
# Chon trong khoang defensible [0.2, 0.4]: du de thuong "ca hai truc cung xau"
# nhung < 0.5 nen khong lan at truc chinh. Tham so tunable, kiem o chuong thuc nghiem.
CORROBORATION_COEF = 0.3

# Static la PRIOR yeu: capability (quyen rong) KHAC hanh vi doc hai. Cong cu lanh
# (password manager, ad blocker) cung xin quyen rong => static MOT MINH khong duoc
# tu day len MEDIUM+. Chi khi dynamic corroborate (quan sat duoc hanh vi thuc) static
# moi phat huy day du. Phat hien tu FP benign: Privacy Badger/Vimium/SingleFile co
# static cao nhung dynamic=0 => bi flag oan chi vi xin quyen rong.
STATIC_ALONE_CAP = 35       # tran cho static khi dynamic im (giu o muc LOW, khong flag)
DYNAMIC_PRESENT_MIN = 15    # nguong coi dynamic "co hanh vi quan sat duoc"

# Nguong muc do, neo theo dai CVSS v3 (x10 sang thang 100).
LEVEL_THRESHOLDS = [(90, "CRITICAL"), (70, "HIGH"), (40, "MEDIUM"), (15, "LOW")]


def _static_score(report: dict) -> int:
    """Diem chi tu tin hieu doc MANIFEST."""
    score = 0
    ind = report["indicators"]
    static = report["static"]
    if ind["has_suspicious_host"]:
        score += 25 + min(len(static["suspicious_hosts"]) * 5, 15)
    if ind["overprivileged"]:
        score += 20
    score += min(static["dangerous_permission_count"] * 3, 15)
    if ind["broad_injection"]:
        score += 15
    return min(score, 100)


def _dynamic_score(report: dict) -> int:
    """Diem chi tu tin hieu QUAN SAT LUC CHAY."""
    score = 0
    ind = report["indicators"]
    if ind["credential_exfil"]:
        score += 80
    if ind["causes_page_hang"]:
        score += 10

    dyn = report.get("dynamic", {}).get("undeclared_domains", {})
    sw_hosts = dyn.get("undeclared_from_sw", [])
    page_hosts = dyn.get("undeclared_from_page", [])
    if sw_hosts or page_hosts:
        base = (DYNAMIC_WEIGHTS["undeclared_domain_sw"] if sw_hosts
                else DYNAMIC_WEIGHTS["undeclared_domain_page"])
        extra = (len(sw_hosts) + len(page_hosts) - 1) * DYNAMIC_WEIGHTS["undeclared_per_extra"]
        score += min(base + max(0, extra), DYNAMIC_WEIGHTS["undeclared_cap"])

    if ind.get("unsolicited_tab"):
        score += DYNAMIC_WEIGHTS["unsolicited_tab"]

    if ind.get("script_injection"):
        score += DYNAMIC_WEIGHTS["script_injection"]

    if ind.get("local_harvest"):
        score += DYNAMIC_WEIGHTS["local_harvest"]

    # Beaconing: base yeu; leo thang khi nhip toi host KHONG khai bao (nghi C2).
    # Phan "host la" da duoc undeclared_domain cham rieng => o day chi cham phan NHIP.
    beac = report.get("dynamic", {}).get("beaconing", {})
    if beac.get("has_beaconing"):
        b = DYNAMIC_WEIGHTS["beaconing_base"]
        if beac.get("has_undeclared_beacon"):
            b += DYNAMIC_WEIGHTS["beaconing_undeclared_bonus"]
        score += b

    return min(score, 100)


def _level_of(score: int) -> str:
    for threshold, name in LEVEL_THRESHOLDS:
        if score >= threshold:
            return name
    return "MINIMAL"


def compute_risk_score(report: dict) -> tuple:
    """
    Tra ve (risk_score, level, breakdown).
    static va dynamic tinh RIENG (moi cai tu cat tran 100) roi ket hop:
      risk = max(s, d) + CORROBORATION_COEF * min(s, d)
    Bao cao GIU CA HAI so rieng => thay duoc dong gop cua dynamic (khong bi tran che).
    """
    s = _static_score(report)
    d = _dynamic_score(report)
    # Khi dynamic im (khong quan sat duoc hanh vi), chan static khong tu day len MEDIUM+.
    # Khi co dynamic corroborate, static phat huy day du.
    s_eff = min(s, STATIC_ALONE_CAP) if d < DYNAMIC_PRESENT_MIN else s
    risk = round(min(max(s_eff, d) + CORROBORATION_COEF * min(s_eff, d), 100))
    level = _level_of(risk)
    breakdown = {"static_score": s, "static_effective": s_eff,
                 "dynamic_score": d, "corroboration_coef": CORROBORATION_COEF}
    return risk, level, breakdown
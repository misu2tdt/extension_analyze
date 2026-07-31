"""
Risk scoring + behavioral report builder.
Signal thiet ke dua tren hanh vi THAT tu 4 malware sample (chien dich 108-extension):
  - Overprivilege, suspicious host, broad content-script scope, page hang, honeypot exfil
"""
from urllib.parse import urlparse

DANGEROUS_PERMISSIONS = {
    "webRequest", "webRequestBlocking", "declarativeNetRequest",
    "downloads", "scripting", "management", "cookies", "history",
    "tabs", "clipboardRead", "clipboardWrite", "debugger", "proxy",
    "<all_urls>",
}

BROAD_MATCH_PATTERNS = {"<all_urls>", "http://*/*", "https://*/*", "*://*/*"}

KNOWN_INFRA_HOSTS = {
    "clients2.google.com", "www.google.com", "google.com",
    "example.com", "localhost", "127.0.0.1",
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
}


def _host_of(url: str) -> str:
    try:
        return (urlparse(url).hostname or "").lower()
    except Exception:
        return ""


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
        host = _host_of(r.get("url", ""))
        if not host or host in HARNESS_HOSTS or host in declared:
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

    return {
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
        },
        "indicators": {
            "credential_exfil": events.get("honeypot_exfil", False),
            "overprivileged": len(dangerous_perms) >= 4,
            "has_suspicious_host": len(suspicious_hosts) > 0,
            "broad_injection": broad_scope,
            "causes_page_hang": events.get("page_hang_count", 0) > 0,
            "undeclared_domain_contact": undeclared["has_undeclared"],
            "unsolicited_tab": unsolicited["has_unsolicited"],
        },
    }


# Trong so corroboration khi ket hop static & dynamic.
# Chon trong khoang defensible [0.2, 0.4]: du de thuong "ca hai truc cung xau"
# nhung < 0.5 nen khong lan at truc chinh. Tham so tunable, kiem o chuong thuc nghiem.
CORROBORATION_COEF = 0.3

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
    risk = round(min(max(s, d) + CORROBORATION_COEF * min(s, d), 100))
    level = _level_of(risk)
    breakdown = {"static_score": s, "dynamic_score": d,
                 "corroboration_coef": CORROBORATION_COEF}
    return risk, level, breakdown
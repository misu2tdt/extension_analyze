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
        "indicators": {
            "credential_exfil": events.get("honeypot_exfil", False),
            "overprivileged": len(dangerous_perms) >= 4,
            "has_suspicious_host": len(suspicious_hosts) > 0,
            "broad_injection": broad_scope,
            "causes_page_hang": events.get("page_hang_count", 0) > 0,
        },
    }


def compute_risk_score(report: dict) -> tuple:
    """Rule-based scoring. Tra ve (score 0-100, level)."""
    score = 0
    ind = report["indicators"]
    static = report["static"]

    if ind["credential_exfil"]:
        score += 80

    if ind["has_suspicious_host"]:
        score += 25 + min(len(static["suspicious_hosts"]) * 5, 15)

    if ind["overprivileged"]:
        score += 20
    score += min(static["dangerous_permission_count"] * 3, 15)

    if ind["broad_injection"]:
        score += 15

    if ind["causes_page_hang"]:
        score += 10

    score = min(score, 100)

    if score >= 70:
        level = "HIGH"
    elif score >= 40:
        level = "MEDIUM"
    elif score >= 15:
        level = "LOW"
    else:
        level = "MINIMAL"

    return score, level
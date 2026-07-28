HONEYPOT_MARKERS = [
    "HONEYPOT", "sk-HONEYPOT", "ghp_HONEYPOT", "AKIAHONEYPOT",
    "HONEYPOT-PASSWORD", "HONEYPOT-OTP", "HONEYPOT-ACCT", "honeyuser",
]


def _find_honeypot(text: str):
    if not text:
        return []
    return [m for m in HONEYPOT_MARKERS if m in text]
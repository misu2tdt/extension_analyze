# ==================== CAU HINH ====================
PER_PAGE_TIMEOUT_MS = 6000
SOFT_TIMEOUT_MARGIN_S = 30       # tru hao de kip ghi ket qua + doc storage
BROWSER_SOFT_TIMEOUT_S = 90      # mac dinh, se bi ghi de boi --timeout
DWELL_MS = 3000                  # thoi gian o lai moi trang cho extension hanh dong
PROFILE_DIR = "/tmp/chrome-profile"
REMOTE_DEBUG_PORT = 9222         # cho CDP session bat network service worker MV3
MAX_BODY_LEN = 2000

# Cac phase cua mot luot phan tich, theo dung thu tu.
PHASE_NAMES = ["load", "honeypot_pages", "target_matched",
               "extension_pages", "delayed_observation"]

TEST_URLS = [
    "http://localhost:8888/fake_bank.html",
    "http://localhost:8888/fake_gmail.html",
    "https://example.com",
]

INTERESTING_HEADERS = ["authorization", "cookie", "x-api-key", "x-auth-token"]
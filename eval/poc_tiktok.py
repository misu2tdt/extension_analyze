"""PoC: kiem gia thuyet "mo trang ma Chrome coi la tiktok.com se danh thuc
content script cua cac mau malware nham TikTok".

Co che spoof: Playwright context.route() + route.fulfill() - chan request
navigation toi *.tiktok.com va tra ve HTML gia truc tiep, KHONG can DNS
override (--host-resolver-rules) hay HTTPS server tu ky.

Script DOC LAP, khong dung sandbox/ pipeline that (khong Docker, khong CDP
sensor cua analyze.py). Chay truc tiep tren host can Playwright + Chromium.
Dung: python eval/poc_tiktok.py
"""
import asyncio
import sys
from pathlib import Path

REPO = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO / "sandbox"))
from crx import extract_crx  # noqa: E402
from playwright.async_api import async_playwright  # noqa: E402

SAMPLE_DIRS = [
    Path(r"C:\Users\Admin\Desktop\BachKhoa\4\HK252\DACN\sample\AutomatedExtensions"),
    Path(r"C:\Users\Admin\Desktop\BachKhoa\4\HK252\DACN\sample\Malicious Browser Extensions"),
]

TIKTOK_IDS = [
    "cfbgdmiobbicgjnaegnenlcgbdabkcli",
    "ehdkeonoccndeaggbnolijnmmeohkbpf",
    "injnjbcogjhcjhnhcbmlahgikemedbko",
    "jacilgchggenbmgbfnehcegalhlgpnhf",
    "kbifpojhlkdoidmndacedmkbjopeekgl",
    "kkhjihaeddnhknninbekkhaklnailngh",
    "mpalaahimeigibehbocnjipjfakekfia",
    "pfpijacnpangmkfdpgodlbokpkhpkeka",
]

POC_DIR = REPO / "eval" / "_poc"
REMOTE_DEBUG_PORT_BASE = 9300  # cong rieng, khong dam voi worker/sandbox that

FAKE_TIKTOK = (
    "<!doctype html><html><head><title>TikTok</title></head><body>"
    "<div id='app'><div class='video-feed'></div>"
    "<form><input name='username'><input name='password' type='password'>"
    "<button>Login</button></form><a href='/foryou'>For You</a></div></body></html>"
)


def find_crx(ext_id: str):
    for d in SAMPLE_DIRS:
        if not d.is_dir():
            continue
        for f in d.glob("*.crx"):
            if f.stem.split("_")[0].lower() == ext_id.lower():
                return f
    return None


async def run_one(ext_id: str, port: int) -> dict:
    result = {"ext_id": ext_id}

    crx = find_crx(ext_id)
    if not crx:
        result["verdict"] = "CRX_NOT_FOUND"
        return result

    ext_dir = POC_DIR / ext_id
    try:
        manifest = extract_crx(str(crx), ext_dir)
        result["name"] = manifest.get("name", "")
    except Exception as e:
        result["verdict"] = f"EXTRACT_ERROR: {str(e)[:100]}"
        return result

    events = {
        "new_requests": [],
        "console_msgs": [],
        "new_tabs": 0,
        "route_hit": False,
        "route_error": None,
        "goto_error": None,
    }

    async with async_playwright() as p:
        context = await p.chromium.launch_persistent_context(
            user_data_dir=str(POC_DIR / f"_profile_{ext_id}"),
            headless=False,
            args=[
                f"--disable-extensions-except={ext_dir}",
                f"--load-extension={ext_dir}",
                "--no-sandbox",
                "--disable-dev-shm-usage",
                "--disable-blink-features=AutomationControlled",
                f"--remote-debugging-port={port}",
            ],
        )

        def on_request(req):
            events["new_requests"].append({
                "url": req.url,
                "origin": "page" if _has_frame(req) else "service_worker",
            })

        def _has_frame(req):
            try:
                _ = req.frame
                return True
            except Exception:
                return False

        context.on("request", on_request)

        # Tao page CUA TA truoc, dang ky listener "page" SAU => khong tu dem chinh minh.
        page = await context.new_page()
        page.on("console", lambda msg: events["console_msgs"].append(
            {"type": msg.type, "text": msg.text[:200]}))

        def on_new_page(p_):
            if p_ is not page:            # chi dem tab do EXTENSION tu mo, khong dem tab cua script
                events["new_tabs"] += 1

        context.on("page", on_new_page)

        async def fulfill_tiktok(route):
            events["route_hit"] = True
            try:
                await route.fulfill(status=200, content_type="text/html", body=FAKE_TIKTOK)
            except Exception as e:
                events["route_error"] = str(e)[:150]

        await context.route("**://*.tiktok.com/**", fulfill_tiktok)

        dom_before = None
        dom_after = None
        injected_nodes_info = []
        try:
            dom_before = await page.evaluate("document.querySelectorAll('script,iframe').length")
        except Exception:
            pass

        try:
            await page.goto("https://www.tiktok.com/", wait_until="commit", timeout=8000)
        except Exception as e:
            events["goto_error"] = str(e)[:200]

        # cho content script kip chay
        await page.wait_for_timeout(7000)

        try:
            dom_after = await page.evaluate("document.querySelectorAll('script,iframe').length")
            # Bang chung TRUC TIEP: liet ke tung node script/iframe hien co (tag+src)
            # de xac nhan node moi la do extension chen, khong phai artifact do.
            injected_nodes_info = await page.evaluate(
                "Array.from(document.querySelectorAll('script,iframe'))"
                ".map(n => ({tag:n.tagName, src:n.src||'(inline)'}))"
            )
        except Exception:
            pass

        try:
            await page.close()
        except Exception:
            pass
        try:
            await context.close()
        except Exception:
            pass

    ext_requests = [r for r in events["new_requests"]
                    if not r["url"].startswith(("chrome-extension://", "devtools://"))]
    tiktok_requests = [r for r in events["new_requests"] if "tiktok.com" in r["url"]]

    injected_dom = None
    if dom_before is not None and dom_after is not None:
        injected_dom = dom_after - dom_before

    awake = bool(
        (injected_dom and injected_dom > 0)
        or len(ext_requests) > len(tiktok_requests)  # co request KHAC ngoai tiktok gia
        or events["new_tabs"] > 0
    )

    result.update({
        "route_hit": events["route_hit"],
        "route_error": events["route_error"],
        "goto_error": events["goto_error"],
        "injected_dom": injected_dom,
        "total_requests": len(events["new_requests"]),
        "non_tiktok_requests": len(ext_requests) - len(tiktok_requests),
        "hosts": sorted({_host(r["url"]) for r in ext_requests}),
        "new_tabs": events["new_tabs"],
        "console_msgs": len(events["console_msgs"]),
        "injected_nodes_info": injected_nodes_info,
        "raw_requests": [r["url"] for r in events["new_requests"]],
        "verdict": "AWAKE" if awake else "silent",
    })
    return result


def _host(url: str) -> str:
    try:
        from urllib.parse import urlparse
        return urlparse(url).hostname or ""
    except Exception:
        return ""


async def main():
    POC_DIR.mkdir(parents=True, exist_ok=True)
    print(f"[poc_tiktok] {len(TIKTOK_IDS)} mau TikTok\n")
    for i, ext_id in enumerate(TIKTOK_IDS):
        print(f"--- [{i+1}/{len(TIKTOK_IDS)}] {ext_id} ---")
        try:
            r = await run_one(ext_id, REMOTE_DEBUG_PORT_BASE + i)
        except Exception as e:
            print(f"  FATAL: {str(e)[:200]}")
            continue

        if r.get("verdict") in ("CRX_NOT_FOUND",) or "EXTRACT_ERROR" in str(r.get("verdict", "")):
            print(f"  {r['ext_id']}: {r['verdict']}")
            continue

        print(f"  route_hit={r['route_hit']}  route_error={r['route_error']}  goto_error={r['goto_error']}")
        print(f"  injected_dom={r['injected_dom']:+d}" if r['injected_dom'] is not None
              else "  injected_dom=N/A")
        print(f"  new_requests={r['total_requests']} (non-tiktok={r['non_tiktok_requests']}, "
              f"hosts={r['hosts']})")
        print(f"  raw_requests={r['raw_requests']}")
        print(f"  new_tabs={r['new_tabs']}  console_msgs={r['console_msgs']}")
        print(f"  dom_nodes={r['injected_nodes_info']}")
        print(f"  => {r['ext_id']}: {r['verdict']}\n")


if __name__ == "__main__":
    asyncio.run(main())

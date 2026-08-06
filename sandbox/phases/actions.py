import asyncio
from config import TEST_URLS, PER_PAGE_TIMEOUT_MS, DWELL_MS, MAX_TARGET_HOSTS
from utils import _host_of
from sensors.network import _setup_context_observers
from sensors.dom import _setup_dom_sensor


async def _phase_load(context, events):
    """Phase load: gan sensor, cho service worker dang ky."""
    await _setup_context_observers(context, events)
    await _setup_dom_sensor(context, events)
    await asyncio.sleep(3)                    # cho SW kip dang ky
    seen_sw = {s.get("url") for s in events["service_workers"]}
    for sw in context.service_workers:
        if sw.url not in seen_sw:
            events["service_workers"].append({"url": sw.url})
            seen_sw.add(sw.url)


_GENERIC_HOSTS = {"<all_urls>", "*", ""}


def _host_from_match(m):
    """Rut host tu content_scripts match pattern (vd 'https://*.tiktok.com/*' -> 'tiktok.com')."""
    if "://" not in m:
        return ""
    host = m.split("://", 1)[1].split("/", 1)[0]
    if host.startswith("*."):
        host = host[2:]
    return host


def _concrete_target_hosts(manifest):
    """Cac host CU THE ma extension nham (bo <all_urls>, *://*/*, host thuan wildcard,
    va host khong co dau cham nhu 'localhost' - khong spoof duoc/khong nen)."""
    hosts = []
    for cs in (manifest.get("content_scripts") or []):
        for m in (cs.get("matches") or []):
            if m == "<all_urls>":
                continue
            h = _host_from_match(m)
            if not h or h in _GENERIC_HOSTS or "*" in h or "." not in h:
                continue
            if h not in hosts:
                hosts.append(h)
    return hosts


async def _phase_target_matched(context, events):
    """Hulk-style honey page (ref: Kapravelos et al. 2014). Doc content_scripts.matches,
    spoof tung host dich bang route.fulfill(honey page van nang) => content script cua
    extension (chi chay tren site do) duoc tiem => 6 sensor bat hanh vi. Malware tuong
    dang o dung site nen ra tay; honey page co san form login/payment (kem honeypot
    marker) de no 'thay cai no tim'."""
    import os
    manifest = events.get("manifest", {}) or {}
    hosts = _concrete_target_hosts(manifest)
    events["target_matched_hosts"] = hosts
    if not hosts:
        events["target_matched_note"] = "no_concrete_target"
        return
    honey_path = os.path.join(os.path.dirname(__file__), "..", "honey_pages", "universal.html")
    try:
        with open(honey_path, encoding="utf-8") as f:
            honey = f.read()
    except Exception:
        honey = "<!doctype html><html><body><form><input type=password value=HONEYPOT-PASSWORD></form></body></html>"

    events.setdefault("target_matched_visited", [])
    for host in hosts[:MAX_TARGET_HOSTS]:
        glob = f"**://*{host}/**"

        async def _fulfill(route):
            try:
                await route.fulfill(status=200, content_type="text/html", body=honey)
            except Exception:
                try:
                    await route.continue_()
                except Exception:
                    pass

        tab = None
        try:
            await context.route(glob, _fulfill)
            tab = await context.new_page()
            tab.on("console", lambda msg: events["console_logs"].append(
                {"type": msg.type, "text": msg.text[:200]}))
            tab.on("pageerror", lambda err: events["errors"].append(str(err)[:200]))
            await tab.goto(f"https://{host}/", wait_until="commit", timeout=PER_PAGE_TIMEOUT_MS)
            await tab.wait_for_timeout(DWELL_MS)
            try:
                await tab.evaluate("window.scrollBy(0, 400)")
                await tab.evaluate("""(() => {
                    const el = document.querySelector('input[type=password], input');
                    if (el) { el.focus(); el.dispatchEvent(new Event('input', {bubbles:true})); }
                })()""")
            except Exception:
                pass
            await tab.wait_for_timeout(1500)
            events["target_matched_visited"].append(host)
            print(f"[Analyze] target_matched spoofed {host}", flush=True)
        except Exception as e:
            events["errors"].append(f"target_matched {host}: {str(e).split(chr(10))[0][:150]}")
        finally:
            if tab:
                try:
                    await tab.close()
                except Exception:
                    pass
            try:
                await context.unroute(glob)
            except Exception:
                pass


async def _visit_pages(context, events, output, save_events):
    for i, url in enumerate(TEST_URLS):
        tab = None
        try:
            print(f"[Analyze] Visiting {url}", flush=True)
            tab = await context.new_page()
            tab.on("console", lambda msg: events["console_logs"].append(
                {"type": msg.type, "text": msg.text[:200]}))
            tab.on("pageerror", lambda err: events["errors"].append(str(err)[:200]))

            await tab.goto(url, wait_until="commit", timeout=PER_PAGE_TIMEOUT_MS)
            await tab.wait_for_timeout(DWELL_MS)

            # Kich thich nhe: scroll + cham vao o input (du extension doc form)
            try:
                await tab.evaluate("window.scrollBy(0, 400)")
                await tab.evaluate("""
                    (() => {
                      const el = document.querySelector('input[type=password], input');
                      if (el) { el.focus();
                                el.dispatchEvent(new Event('input', {bubbles:true})); }
                    })()
                """)
            except Exception:
                pass
            await tab.wait_for_timeout(1500)

            await tab.screenshot(path=str(output / f"screenshot_{i}.png"))
            events["pages_visited"].append(url)
            save_events()              # GHI TANG DAN: song sot qua timeout
        except Exception as e:
            msg = str(e).split("\n")[0][:150]
            print(f"[Analyze] Error at {url}: {msg}", flush=True)
            events["errors"].append(f"navigate {url}: {msg}")
            events["page_hang_count"] += 1
            save_events()
        finally:
            if tab:
                try:
                    await tab.close()   # dong tab => cat hanh vi tich luy
                except Exception:
                    pass


async def _probe_extension_pages(context, events, output):
    """Mo popup/options cua extension - nhieu extension chi chay logic khi popup mo."""
    ext_ids = set()
    for sw in events.get("service_workers", []):
        h = _host_of(sw.get("url", ""))
        if h:
            ext_ids.add(h)
    for r in events.get("network_requests", []):
        if r.get("url", "").startswith("chrome-extension://"):
            h = _host_of(r["url"])
            if h:
                ext_ids.add(h)
    events["extension_ids_seen"] = sorted(ext_ids)

    for ext_id in list(ext_ids)[:2]:
        for page_name in ["popup.html", "popup/popup.html", "options.html"]:
            tab = None
            try:
                tab = await context.new_page()
                await tab.goto(f"chrome-extension://{ext_id}/{page_name}",
                               wait_until="commit", timeout=4000)
                await tab.wait_for_timeout(2500)
                await tab.screenshot(
                    path=str(output / f"ext_{page_name.replace('/', '_')}.png"))
                events["extension_pages_opened"].append(f"{ext_id}/{page_name}")
                print(f"[Analyze] Opened extension page: {page_name}", flush=True)
                break
            except Exception:
                pass
            finally:
                if tab:
                    try:
                        await tab.close()
                    except Exception:
                        pass

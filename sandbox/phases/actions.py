import asyncio
from config import TEST_URLS, PER_PAGE_TIMEOUT_MS, DWELL_MS
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


async def _phase_target_matched(context, events):
    """KHUNG RONG - block sau se cai logic chon trang khop manifest.
    Hien tai return ngay de cau truc phase hoan chinh."""
    events["target_matched_note"] = "not_implemented_yet"
    return


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

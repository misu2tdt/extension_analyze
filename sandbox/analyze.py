import asyncio
import urllib.request
import websockets
import time
import os
import argparse
import json
from crx import extract_crx
import re
import config
from pathlib import Path
from urllib.parse import urlparse
from playwright.async_api import async_playwright
from config import (
    PER_PAGE_TIMEOUT_MS, SOFT_TIMEOUT_MARGIN_S,
    DWELL_MS, PROFILE_DIR, REMOTE_DEBUG_PORT, MAX_BODY_LEN,
    PHASE_NAMES, TEST_URLS, INTERESTING_HEADERS,
)
from honeypot import HONEYPOT_MARKERS, _find_honeypot


def _host_of(url: str) -> str:
    try:
        return (urlparse(url).hostname or "").lower()
    except Exception:
        return ""




# ============ CAM BIEN 1+2: NETWORK + PAYLOAD SAU ============
def _record_request(req, events, origin: str):
    entry = {
        "url": req.url,
        "method": req.method,
        "resource_type": req.resource_type,
        "origin": origin,
        "host": _host_of(req.url),
    }
    entry["phase"] = events.get("_current_phase")

    if events.get("_t0") is not None:
        entry["t"] = round(time.monotonic() - events["_t0"], 3)

    body = None
    try:
        body = req.post_data
        if body is None:
            raw = req.post_data_buffer           # bytes -- luon co neu request co body
            if raw:
                entry["post_data_binary_len"] = len(raw)
                body = raw.decode("utf-8", "replace")
    except Exception:
        body = None
    if body:
        entry["post_data"] = body[:MAX_BODY_LEN]
        entry["post_data_len"] = len(body)

    try:
        picked = {k: v[:200] for k, v in (req.headers or {}).items()
                  if k.lower() in INTERESTING_HEADERS}
        if picked:
            entry["headers_of_interest"] = picked
    except Exception:
        pass

    surface = req.url + " " + (body or "") + " " + \
              json.dumps(entry.get("headers_of_interest", {}))
    hits = _find_honeypot(surface)
    if hits:
        entry["honeypot_markers"] = hits
        events["honeypot_exfil"] = True
        events["honeypot_exfil_details"].append({
            "url": req.url, "method": req.method, "markers": hits,
            "where": "post_data" if (body and _find_honeypot(body)) else "url_or_header",
        })
        print(f"[Analyze] !!! HONEYPOT EXFIL: {hits} -> {req.url[:80]}", flush=True)

    events["network_requests"].append(entry)


async def _setup_context_observers(context, events):
    """Gan cam bien o CAP CONTEXT => phu ca page lan service worker."""

    def on_request(req):
        # Request tu service worker khong co frame => truy cap se nem loi
        try:
            _ = req.frame
            origin = "page"
        except Exception:
            origin = "service_worker"
        _record_request(req, events, origin)

    context.on("request", on_request)

    def on_response(res):
        try:
            events["responses"].append({"url": res.url[:300], "status": res.status})
        except Exception:
            pass

    context.on("response", on_response)

    # CAM BIEN 3: tab/popup moi (dau hieu backdoor tu mo URL)
    def on_page(p):
        try:
            events["new_tabs"].append({"url": p.url})
            print(f"[Analyze] * New tab opened: {p.url[:100]}", flush=True)
            p.on("framenavigated",
                 lambda f: events["navigations"].append({"url": f.url[:300]}))
        except Exception:
            pass

    context.on("page", on_page)

    def on_sw(sw):
        try:
            events["service_workers"].append({"url": sw.url})
            print(f"[Analyze] * Service worker: {sw.url[:100]}", flush=True)
        except Exception:
            pass

    context.on("serviceworker", on_sw)

# ============ CAM BIEN 1b: NETWORK SERVICE WORKER QUA CDP ============
# context.on("request") cua Playwright MU voi network cua SW MV3 (da kiem chung
# bang canary). CDP o cap browser + auto-attach flatten moi bat duoc.
def _record_cdp_request(rq, events):
    url = rq.get("url", "")
    body = rq.get("postData")
    entry = {
        "url": url,
        "method": rq.get("method"),
        "resource_type": rq.get("_cdp_type", "cdp"),
        "origin": "service_worker",
        "host": _host_of(url),
    }
    entry["phase"] = events.get("_current_phase")
    if body:
        entry["post_data"] = body[:MAX_BODY_LEN]
        entry["post_data_len"] = len(body)
    hdrs = rq.get("headers", {}) or {}
    picked = {k: str(v)[:200] for k, v in hdrs.items()
            if k.lower() in INTERESTING_HEADERS}
    if picked:
        entry["headers_of_interest"] = picked

    surface = url + " " + (body or "") + " " + json.dumps(picked)
    hits = _find_honeypot(surface)
    if hits:
        entry["honeypot_markers"] = hits
        events["honeypot_exfil"] = True
        events["honeypot_exfil_details"].append({
            "url": url, "method": rq.get("method"), "markers": hits,
            "where": "post_data" if (body and _find_honeypot(body)) else "url_or_header",
            "via": "cdp_service_worker",
        })
        print(f"[Analyze] !!! HONEYPOT EXFIL (SW/CDP): {hits} -> {url[:80]}", flush=True)

    events["network_requests"].append(entry)


async def _cdp_sw_sensor(events, stop_evt, port=REMOTE_DEBUG_PORT):
    """Nghe network cua service worker qua CDP tho o cap browser."""
    burl = None
    for _ in range(20):                       # doi remote-debugging endpoint san sang
        try:
            ver = json.loads(urllib.request.urlopen(
                f"http://localhost:{port}/json/version", timeout=1).read())
            burl = ver["webSocketDebuggerUrl"]
            break
        except Exception:
            await asyncio.sleep(0.3)
    if not burl:
        events["errors"].append("cdp_endpoint_unavailable")
        return

    try:
        async with websockets.connect(burl, max_size=None) as ws:
            _id = [1000]

            async def send(method, params=None, sid=None):
                _id[0] += 1
                m = {"id": _id[0], "method": method, "params": params or {}}
                if sid:
                    m["sessionId"] = sid
                await ws.send(json.dumps(m))

            sw_sessions = set()
            await send("Target.setAutoAttach",
                    {"autoAttach": True, "waitForDebuggerOnStart": True, "flatten": True})

            while not stop_evt.is_set():
                try:
                    msg = json.loads(await asyncio.wait_for(ws.recv(), timeout=1))
                except asyncio.TimeoutError:
                    continue
                except Exception:
                    break
                method = msg.get("method")
                pr = msg.get("params", {})
                if method == "Target.attachedToTarget":
                    info = pr.get("targetInfo", {})
                    sid = pr.get("sessionId")
                    ttype = info.get("type")
                    if ttype in ("service_worker", "worker"):
                        sw_sessions.add(sid)
                    if ttype in ("service_worker", "worker", "page", "iframe"):
                        # Phai bat Network + tha debugger cho MOI target de no chay tiep.
                        await send("Network.enable", {}, sid=sid)
                        await send("Runtime.runIfWaitingForDebugger", {}, sid=sid)
                elif method == "Network.requestWillBeSent" and msg.get("sessionId") in sw_sessions:
                    r = pr.get("request", {})
                    r["_cdp_type"] = pr.get("type", "")
                    _record_cdp_request(r, events)
    except Exception as e:
        events["errors"].append(f"cdp_sw_sensor_error: {str(e)[:120]}")


# ============ CAM BIEN 4: DOM MUTATION ============
async def _setup_dom_sensor(context, events):
    """
    MutationObserver dat o MAIN WORLD.
    Content script chay o isolated world (JS rieng) NHUNG DOM la CHUNG
    => van thay duoc moi thay doi DOM do content script gay ra.
    """
    async def _report(source, payload):
        try:
            payload = dict(payload or {})
            try:
                payload["page_url"] = source["page"].url
            except Exception:
                pass
            events["dom_activity"].append(payload)
            if payload.get("type") == "node_injected":
                print(f"[Analyze] * DOM inject: <{payload.get('tag')}> "
                      f"{str(payload.get('src'))[:80]}", flush=True)
        except Exception:
            pass

    await context.expose_binding("__extanalyze_report", _report)

    await context.add_init_script("""
    (() => {
      const seen = new Set();
      let injectedCount = 0;
      const send = (d) => { try { window.__extanalyze_report(d); } catch (e) {} };

      const handle = (muts) => {
        for (const m of muts) {
          for (const n of m.addedNodes) {
            if (!n || n.nodeType !== 1) continue;
            injectedCount++;
            const tag = n.tagName;
            if (tag === 'SCRIPT' || tag === 'IFRAME' || tag === 'FORM') {
              const src = n.src || n.action || '(inline)';
              const key = tag + '|' + src;
              if (!seen.has(key)) {
                seen.add(key);
                send({ type: 'node_injected', tag: tag,
                       src: String(src).slice(0, 300) });
              }
            }
          }
        }
      };

      try {
        const obs = new MutationObserver(handle);
        const start = () => {
          try { obs.observe(document.documentElement || document,
                            { childList: true, subtree: true }); } catch (e) {}
        };
        start();
        document.addEventListener('DOMContentLoaded', start);
      } catch (e) {}

      setTimeout(() => send({ type: 'mutation_summary',
                              injected_nodes: injectedCount }), 2500);
    })();
    """)


# ============ CAM BIEN 5: STORAGE CUA EXTENSION ============
def dump_extension_storage(events):
    """
    Doc chrome.storage.local (LevelDB trong profile).
    Malware thuong cat tam du lieu harvest o day truoc khi gui di
    => thay honeypot o day = bang chung DA THU THAP (du chua kip gui).
    """
    profile = Path(PROFILE_DIR)
    candidates = [profile / "Default" / "Local Extension Settings",
                  profile / "Local Extension Settings"]
    base = next((c for c in candidates if c.exists()), None)
    if base is None:
        return

    total_bytes, hits = 0, []
    for ext_dir in base.iterdir():
        if not ext_dir.is_dir():
            continue
        for f in ext_dir.glob("*"):
            try:
                data = f.read_bytes()
            except Exception:
                continue
            total_bytes += len(data)
            for raw in re.findall(rb"[\x20-\x7e]{8,}", data):
                s = raw.decode("ascii", "ignore")
                found = _find_honeypot(s)
                if found:
                    hits.append({"ext_id": ext_dir.name, "file": f.name,
                                 "markers": found, "snippet": s[:200]})

    events["extension_storage"] = {
        "total_bytes": total_bytes,
        "honeypot_hits": hits[:20],
        "honeypot_found": len(hits) > 0,
    }
    if hits:
        events["honeypot_stored"] = True
        print(f"[Analyze] !!! HONEYPOT IN STORAGE: {len(hits)} hits", flush=True)


# ==================== DUYET TRANG ====================
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

def _phase_budget(name, default):
    """Ngan sach phase, cho phep override qua bien moi truong (khong can rebuild)."""
    try:
        return int(os.environ.get(f"PHASE_BUDGET_{name.upper()}", default))
    except ValueError:
        return default


async def _run_phase(name, coro, budget_s, events):
    """Boc mot phase: cap ngan sach, bat loi/timeout, ghi trang thai."""
    rec = {"name": name, "status": "running", "budget_s": budget_s,
           "t_start": round(time.monotonic() - events["_t0"], 2), "t_end": None, "reason": None}
    events["phases"].append(rec)
    events["_current_phase"] = name          # de sensor gan "phase" vao event
    try:
        await asyncio.wait_for(coro, timeout=budget_s)
        rec["status"] = "completed"
    except asyncio.TimeoutError:
        rec["status"] = "timed_out"
        rec["reason"] = f"vuot ngan sach {budget_s}s"
    except Exception as e:
        rec["status"] = "failed"
        rec["reason"] = str(e)[:150]
    finally:
        rec["t_end"] = round(time.monotonic() - events["_t0"], 2)
    print(f"[Phase] {name}: {rec['status']} "
          f"({rec['t_start']}s - {rec['t_end']}s)", flush=True)
    return rec["status"]


def _finalize_run_status(events):
    """Suy ra run_status tong tu trang thai cac phase."""
    phases = events.get("phases", [])
    by = {p["name"]: p for p in phases}
    load = by.get("load")
    completed = sum(1 for p in phases if p["status"] == "completed")
    if load and load["status"] == "failed":
        status, reason = "failed", "load failed: " + (load.get("reason") or "")
    elif len(phases) == len(PHASE_NAMES) and all(p["status"] == "completed" for p in phases):
        status, reason = "complete", None
    else:
        bad = [p["name"] for p in phases if p["status"] in ("timed_out", "failed", "skipped")]
        status, reason = "partial", ", ".join(f"{n} {by[n]['status']}" for n in bad)
    events["run_status"] = {"status": status, "reason": reason,
                            "phases_completed": completed,
                            "phases_total": len(PHASE_NAMES)}
    print(f"[Run] status={status} ({completed}/{len(PHASE_NAMES)} phases) reason={reason}",
          flush=True)

async def _run_browser(ext_dir, events, output, save_events):
    async with async_playwright() as p:
        events["_t0"] = time.monotonic()
        context = await p.chromium.launch_persistent_context(
            user_data_dir=PROFILE_DIR,
            headless=False,
            args=[
                f"--disable-extensions-except={ext_dir}",
                f"--load-extension={ext_dir}",
                "--no-sandbox",
                "--disable-dev-shm-usage",
                "--disable-blink-features=AutomationControlled",
                f"--remote-debugging-port={REMOTE_DEBUG_PORT}",
            ],
        )
        events["phases"] = []

        # CDP SW sensor chay nen suot ca luot (vuot qua ranh gioi cac phase).
        stop_cdp = asyncio.Event()
        cdp_task = asyncio.create_task(_cdp_sw_sensor(events, stop_cdp))

        try:
            status = await _run_phase(
                "load", _phase_load(context, events),
                _phase_budget("load", 15), events)

            if status != "failed":
                await _run_phase(
                    "honeypot_pages",
                    _visit_pages(context, events, output, save_events),
                    _phase_budget("honeypot_pages", 60), events)
                await _run_phase(
                    "target_matched",
                    _phase_target_matched(context, events),
                    _phase_budget("target_matched", 40), events)
                await _run_phase(
                    "extension_pages",
                    _probe_extension_pages(context, events, output),
                    _phase_budget("extension_pages", 30), events)
                await _run_phase(
                    "delayed_observation",
                    asyncio.sleep(3),
                    _phase_budget("delayed_observation", 15), events)
        finally:
            stop_cdp.set()
            try:
                await asyncio.wait_for(cdp_task, timeout=5)
            except Exception:
                cdp_task.cancel()
            _finalize_run_status(events)
            await context.close()


# ==================== TONG HOP ====================
def summarize(events):
    reqs = events["network_requests"]
    sw_reqs = [r for r in reqs if r.get("origin") == "service_worker"]
    ext_hosts = {r["host"] for r in reqs
                 if r.get("host") and r["host"] not in ("localhost", "127.0.0.1")}

    events["summary"] = {
        "total_requests": len(reqs),
        "service_worker_requests": len(sw_reqs),
        "external_domains": sorted(ext_hosts),
        "external_domain_count": len(ext_hosts),
        "post_requests": len([r for r in reqs if r.get("method") == "POST"]),
        "requests_with_body": len([r for r in reqs if r.get("post_data")]),
        "new_tabs_opened": len(events["new_tabs"]),
        "scripts_injected": len([d for d in events["dom_activity"]
                                 if d.get("type") == "node_injected"]),
        "dom_nodes_injected": sum(d.get("injected_nodes", 0)
                                  for d in events["dom_activity"]
                                  if d.get("type") == "mutation_summary"),
        "page_hang_count": events["page_hang_count"],
        "honeypot_exfil": events["honeypot_exfil"],
        "honeypot_stored": events.get("honeypot_stored", False),
        "service_worker_count": len(events["service_workers"]),
    }


# ==================== MAIN ====================
async def analyze_extension(crx_path: str, output_dir: str):
    output = Path(output_dir)
    output.mkdir(parents=True, exist_ok=True)

    events = {
        "schema_version": "1.0",
        "manifest": {},
        "network_requests": [],
        "responses": [],
        "console_logs": [],
        "errors": [],
        "pages_visited": [],
        "new_tabs": [],
        "navigations": [],
        "service_workers": [],
        "dom_activity": [],
        "extension_pages_opened": [],
        "extension_ids_seen": [],
        "extension_storage": {},
        "honeypot_exfil": False,
        "honeypot_exfil_details": [],
        "honeypot_stored": False,
        "page_hang_count": 0,
        "summary": {},
    }

    def save_events():
        summarize(events)
        with open(output / "events.json", "w", encoding="utf-8") as f:
            json.dump(events, f, indent=2, ensure_ascii=False, default=str)

    ext_dir = output / "extension_unpacked"
    events["manifest"] = extract_crx(crx_path, ext_dir)
    print(f"[Analyze] Extension: {events['manifest'].get('name')} "
          f"v{events['manifest'].get('version')} "
          f"(MV{events['manifest'].get('manifest_version')})", flush=True)
    save_events()

    try:
        await asyncio.wait_for(
            _run_browser(ext_dir, events, output, save_events),
            timeout=config.BROWSER_SOFT_TIMEOUT_S,
        )
    except asyncio.TimeoutError:
        print(f"[Analyze] Browser SOFT TIMEOUT ({config.BROWSER_SOFT_TIMEOUT_S}s)", flush=True)
        events["errors"].append(f"browser_soft_timeout_{config.BROWSER_SOFT_TIMEOUT_S}s")
    except Exception as e:
        print(f"[Analyze] Browser error: {str(e)[:150]}", flush=True)
        events["errors"].append(f"browser_error: {str(e)[:150]}")

    # Doc storage SAU khi browser dong (du lieu da duoc flush xuong dia)
    try:
        dump_extension_storage(events)
    except Exception as e:
        print(f"[Analyze] Storage dump failed: {str(e)[:100]}", flush=True)

    save_events()
    s = events["summary"]
    print(f"[Analyze] DONE. requests={s['total_requests']} "
          f"(SW={s['service_worker_requests']}, POST={s['post_requests']}) | "
          f"domains={s['external_domain_count']} | tabs={s['new_tabs_opened']} | "
          f"injected={s['scripts_injected']} | hangs={s['page_hang_count']} | "
          f"exfil={s['honeypot_exfil']} stored={s['honeypot_stored']}", flush=True)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--crx", required=True)
    parser.add_argument("--output", required=True)
    parser.add_argument("--timeout", type=int, default=120,
                        help="Ngan sach thoi gian TONG (giay) do shell cap")
    args = parser.parse_args()

    config.BROWSER_SOFT_TIMEOUT_S = max(30, args.timeout - SOFT_TIMEOUT_MARGIN_S)
    print(f"[Analyze] Budget={args.timeout}s, soft={config.BROWSER_SOFT_TIMEOUT_S}s",
          flush=True)

    asyncio.run(analyze_extension(args.crx, args.output))


if __name__ == "__main__":
    main()
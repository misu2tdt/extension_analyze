import asyncio
import json
import time
import urllib.request
import websockets

from config import MAX_BODY_LEN, INTERESTING_HEADERS, REMOTE_DEBUG_PORT
from honeypot import _find_honeypot
from utils import _host_of


def _initiator_is_extension(initiator: dict) -> bool:
    """True neu request do code EXTENSION khoi tao (initiator stack co chrome-extension://).
    Isolated world dam bao content script de lai URL chrome-extension:// trong stack."""
    urls = []
    if initiator.get("url"):
        urls.append(initiator["url"])
    stack = initiator.get("stack")
    hops = 0
    while stack and hops < 50:
        for cf in stack.get("callFrames", []):
            u = cf.get("url", "")
            if u:
                urls.append(u)
            hops += 1
        stack = stack.get("parent")
    return any(u.startswith("chrome-extension://") for u in urls)


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
    # Dong dau timestamp tuong doi giong network.py => beaconing tinh duoc interval
    # tren network SW (noi C2 hay xay ra). Latency websocket la HANG SO => triet tieu
    # khi lay hieu giua 2 request; chi variance moi anh huong, ma no ~vai ms << interval.
    if events.get("_t0") is not None:
        entry["t"] = round(time.monotonic() - events["_t0"], 3)
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
                elif method == "Network.requestWillBeSent":
                    sid = msg.get("sessionId")
                    if sid in sw_sessions:
                        r = pr.get("request", {})
                        r["_cdp_type"] = pr.get("type", "")
                        _record_cdp_request(r, events)
                    else:
                        # Session page/iframe: GHI PROVENANCE (additive), KHONG dung network_requests.
                        req = pr.get("request", {})
                        url = req.get("url", "")
                        if url.startswith("http"):
                            host = _host_of(url)
                            if host and "." in host:
                                ext = _initiator_is_extension(pr.get("initiator", {}))
                                prov = events.setdefault("request_provenance", {})
                                # host duoc extension khoi tao du 1 lan => danh dau True
                                prov[host] = bool(prov.get(host, False) or ext)
    except Exception as e:
        events["errors"].append(f"cdp_sw_sensor_error: {str(e)[:120]}")

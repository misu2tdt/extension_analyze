import json
import time
from config import MAX_BODY_LEN, INTERESTING_HEADERS
from honeypot import _find_honeypot
from utils import _host_of


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
            events["new_tabs"].append({
                "url": p.url,
                "phase": events.get("_current_phase"),   # THEM: tab mo o phase nao
            })
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
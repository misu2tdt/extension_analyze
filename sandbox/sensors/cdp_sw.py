import asyncio
import json
import time
import urllib.request
import websockets

from config import MAX_BODY_LEN, INTERESTING_HEADERS, REMOTE_DEBUG_PORT
from honeypot import _find_honeypot
from utils import _host_of


# ============ CAM BIEN 7 (GD1): API-CALL CAPTURE TRONG SERVICE WORKER ============
# Wrap mot tap Chrome API nguy hiem TRUOC khi SW chay (luc con waitForDebuggerOnStart),
# moi lan goi phat console.log('__APICALL__'+json) - dung console vi SW MV3 co the bi
# terminate/restart giua chung, console duoc CDP bat "live" nen khong mat du lieu (khac
# global array se mat khi SW restart). CHI capture, KHONG cham diem (worker/risk.py
# khong doc field nay o GD1).
# Gioi han da biet: self.eval chi bat duoc INDIRECT eval (eval dung nhu 1 gia tri, vd
# `const e = self.eval; e(...)`), KHONG bat direct eval (`eval(...)` trong scope rieng
# cua extension co the dung eval goc do V8 optimize truoc khi wrapper kip gan) - chap
# nhan o GD1, se can CDP Debugger.setInstrumentationBreakpoint hoac tuong tu neu can bat.
#
# Gioi han da biet #2 (kiem chung bang malware that, khong phai ly thuyet): cac API goi
# NGAY O TOP-LEVEL cua service worker (vd `chrome.runtime.setUninstallURL(...)` viet
# thang dau file, khong nam trong onMessage/onInstalled/alarm) co the chay xong TRUOC
# khi inject nay kip patch - vi phien CDP rieng cua cdp_sw.py phai tu ket noi
# (urllib polling /json/version) trong khi Playwright co the da attach/tha SW rieng
# cho muc dich theo doi cua no truoc. Da xac nhan qua canary (marker debug rieng) va
# qua 1 mau malware that (adjiljljjoeielcjmafljkicjncjpbha, goi setUninstallURL o dong
# dau background.js) => sensor nay bat CHAC CHAN cac API goi tu event handler (message/
# alarm/webRequest callback...), KHONG dam bao bat cac API goi dong bo o top-level luc
# SW vua khoi dong. Vi vay canary_apihook.js trigger qua onMessage (giong content.js
# cua canary cu), khong goi truc tiep o top-level.
_API_HOOK_JS = """
(function(){
  if (self.__apihook) return; self.__apihook = true;
  function L(r){ try{ console.log('__APICALL__'+JSON.stringify(r)); }catch(e){} }
  // Nhom 1: self-defense
  try{ if(self.chrome&&chrome.management&&chrome.management.uninstall){
    const o=chrome.management.uninstall.bind(chrome.management);
    chrome.management.uninstall=function(id){ L({api:'management.uninstall',args:[id]}); return o.apply(this,arguments); };
  }}catch(e){}
  try{ if(self.chrome&&chrome.tabs&&chrome.tabs.remove){
    const o=chrome.tabs.remove.bind(chrome.tabs);
    chrome.tabs.remove=function(ids){ L({api:'tabs.remove',args:[ids]}); return o.apply(this,arguments); };
  }}catch(e){}
  // Nhom 3: beacon luc uninstall
  try{ if(self.chrome&&chrome.runtime&&chrome.runtime.setUninstallURL){
    const o=chrome.runtime.setUninstallURL.bind(chrome.runtime);
    chrome.runtime.setUninstallURL=function(u){ L({api:'runtime.setUninstallURL',args:[u]}); return o.apply(this,arguments); };
  }}catch(e){}
  // Nhom 2: chan request (webRequest blocking)
  try{ if(self.chrome&&chrome.webRequest&&chrome.webRequest.onBeforeRequest&&chrome.webRequest.onBeforeRequest.addListener){
    const o=chrome.webRequest.onBeforeRequest.addListener.bind(chrome.webRequest.onBeforeRequest);
    chrome.webRequest.onBeforeRequest.addListener=function(cb,filter,extra){ L({api:'webRequest.onBeforeRequest.addListener',filter:filter,extra:extra}); return o.apply(this,arguments); };
  }}catch(e){}
  // Nhom 4: dynamic code
  try{ const oF=self.Function; self.Function=new Proxy(oF,{
    apply(t,ta,a){ L({api:'Function',preview:String(a[a.length-1]||'').slice(0,120)}); return Reflect.apply(t,ta,a); },
    construct(t,a){ L({api:'Function',preview:String(a[a.length-1]||'').slice(0,120)}); return Reflect.construct(t,a); }
  }); }catch(e){}
  try{ const oE=self.eval; self.eval=function(c){ L({api:'eval',preview:String(c||'').slice(0,120)}); return oE.call(this,c); }; }catch(e){}
})();
"""


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
            events.setdefault("api_calls", [])  # sensor #7 GD1: luon co key, du rong
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
                if method is None and "error" in msg:
                    # Chan doan CDP: log loi cua cac lenh gui bang send() (vd Runtime.evaluate
                    # that bai do context chua san sang). Chi ghi log, khong doi hanh vi.
                    events["errors"].append(f"cdp_error: {json.dumps(msg['error'])[:200]}")
                if method == "Target.attachedToTarget":
                    info = pr.get("targetInfo", {})
                    sid = pr.get("sessionId")
                    ttype = info.get("type")
                    if ttype in ("service_worker", "worker"):
                        sw_sessions.add(sid)
                    if ttype in ("service_worker", "worker", "page", "iframe"):
                        # Phai bat Network + tha debugger cho MOI target de no chay tiep.
                        await send("Network.enable", {}, sid=sid)
                    if ttype == "service_worker":
                        # Sensor #7 GD1: inject wrapper TRUOC khi tha debugger, de bat
                        # duoc moi API call ngay tu dong dau SW (vd onInstalled/onStartup).
                        # Loi inject KHONG duoc lam hong phien - chi mat api_calls cua mau nay.
                        try:
                            await send("Runtime.enable", {}, sid=sid)
                            await send("Runtime.evaluate", {"expression": _API_HOOK_JS}, sid=sid)
                        except Exception as e:
                            events["errors"].append(f"api_hook_inject_error: {str(e)[:120]}")
                    if ttype in ("service_worker", "worker", "page", "iframe"):
                        await send("Runtime.runIfWaitingForDebugger", {}, sid=sid)
                elif method == "Runtime.consoleAPICalled":
                    # Sensor #7 GD1: bat log '__APICALL__<json>' phat ra tu _API_HOOK_JS.
                    sid = msg.get("sessionId")
                    if sid in sw_sessions:
                        try:
                            args = pr.get("args", [])
                            v = args[0].get("value") if args else None
                            if isinstance(v, str) and v.startswith("__APICALL__"):
                                call = json.loads(v[len("__APICALL__"):])
                                events["api_calls"].append(call)
                        except Exception:
                            pass  # JSON hong / dinh dang la -> bo qua, khong lam hong phien
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

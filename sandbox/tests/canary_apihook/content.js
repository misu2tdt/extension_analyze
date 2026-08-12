// trigger cac API call trong service_worker.js SAU khi trang da load, dam bao
// cdp_sw.py da co du thoi gian attach + inject truoc khi cac API do duoc goi
try { chrome.runtime.sendMessage({ cmd: 'apicall' }); } catch (e) {}

// service worker cua canary apihook - kiem chung sensor #7 (GD1: api_calls).
// Goi 3 API trong onMessage (KHONG o top-level) vi top-level SW code chay qua nhanh -
// dua vao waitForDebuggerOnStart don le se bi race voi Playwright tu attach/release SW
// truoc khi sensor cdp_sw.py kip inject (da kiem chung bang marker debug rieng, xem
// comment Limitation trong sensors/cdp_sw.py). Day la cung 1 ly do content.js (canary
// cu) dung sendMessage thay vi cho onInstalled.
chrome.runtime.onMessage.addListener((msg) => {
  if (!msg || msg.cmd !== 'apicall') return;
  chrome.runtime.setUninstallURL('https://canary-beacon.invalid/x');
  try { new Function('return 1')(); } catch (e) {}
  try { self.eval('1+1'); } catch (e) {}
});

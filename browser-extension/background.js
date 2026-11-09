/**
 * Aegis AI Shield - Background Service Worker
 * Manages blocked threat telemetry and declarative request protection.
 */

chrome.runtime.onInstalled.addListener(() => {
  console.log("🛡️ Aegis AI Shield active: Negative-gate AI protection enabled.");
  chrome.storage.local.set({
    blockedCount: 0,
    threatHistory: [],
    protectionActive: true
  });
});

chrome.runtime.onMessage.addListener((message, sender, sendResponse) => {
  if (message.type === "AEGIS_THREAT_BLOCKED") {
    chrome.storage.local.get(["blockedCount", "threatHistory"], (data) => {
      const count = (data.blockedCount || 0) + 1;
      const history = (data.threatHistory || []);
      history.unshift(message.threat);
      if (history.length > 50) history.pop();

      chrome.storage.local.set({ blockedCount: count, threatHistory: history });
      chrome.action.setBadgeText({ text: String(count) });
      chrome.action.setBadgeBackgroundColor({ color: "#ef4444" });
    });
    sendResponse({ received: true });
  }
});

/**
 * Aegis AI Shield — Background Service Worker
 * Tracks per-tab and total blocked threats, manages pause/allowlist state,
 * and toggles declarativeNetRequest beacon blocking rules.
 */

const tabThreats = new Map();

function syncRuleset(active) {
  if (!chrome.declarativeNetRequest?.updateEnabledRulesets) return;
  const opts = active
    ? { enableRulesetIds: ["aegis_beacons"], disableRulesetIds: [] }
    : { enableRulesetIds: [], disableRulesetIds: ["aegis_beacons"] };
  chrome.declarativeNetRequest.updateEnabledRulesets(opts).catch(() => {});
}

function updateBadgeForTab(tabId, count, active) {
  if (!chrome.action?.setBadgeText) return;
  if (!active) {
    chrome.action.setBadgeText({ text: "OFF" });
    chrome.action.setBadgeBackgroundColor({ color: "#64748b" });
    return;
  }
  const text = count > 0 ? String(count) : "";
  const target = typeof tabId === "number" ? { tabId, text } : { text };
  chrome.action.setBadgeText(target);
  chrome.action.setBadgeBackgroundColor(
    typeof tabId === "number" ? { tabId, color: "#ef4444" } : { color: "#ef4444" }
  );
}

chrome.runtime.onInstalled.addListener(() => {
  chrome.storage.local.get(
    ["blockedCount", "threatHistory", "protectionActive", "allowlist"],
    (existing) => {
      const active = existing.protectionActive !== false;
      chrome.storage.local.set({
        blockedCount: existing.blockedCount || 0,
        threatHistory: Array.isArray(existing.threatHistory) ? existing.threatHistory : [],
        protectionActive: active,
        allowlist: Array.isArray(existing.allowlist) ? existing.allowlist : []
      });
      syncRuleset(active);
    }
  );
});

if (chrome.tabs?.onRemoved) {
  chrome.tabs.onRemoved.addListener((tabId) => {
    tabThreats.delete(tabId);
  });
}

if (chrome.tabs?.onUpdated) {
  chrome.tabs.onUpdated.addListener((tabId, changeInfo) => {
    if (changeInfo.status === "loading") {
      tabThreats.delete(tabId);
      chrome.storage.local.get(["protectionActive"], (data) => {
        if (data.protectionActive !== false) {
          updateBadgeForTab(tabId, 0, true);
        }
      });
    }
  });
}

chrome.runtime.onMessage.addListener((message, sender, sendResponse) => {
  if (!message || typeof message !== "object") return;

  if (message.type === "AEGIS_THREAT_BLOCKED") {
    const tabId = sender?.tab?.id;
    const threat = Object.assign({ tabId }, message.threat || {});
    if (typeof tabId === "number") {
      const list = tabThreats.get(tabId) || [];
      list.unshift(threat);
      if (list.length > 50) list.pop();
      tabThreats.set(tabId, list);
    }
    chrome.storage.local.get(["blockedCount", "threatHistory", "protectionActive"], (data) => {
      const count = (data.blockedCount || 0) + 1;
      const history = Array.isArray(data.threatHistory) ? data.threatHistory : [];
      history.unshift(threat);
      if (history.length > 100) history.pop();

      chrome.storage.local.set({ blockedCount: count, threatHistory: history }, () => {
        const active = data.protectionActive !== false;
        const tabCount = typeof tabId === "number" ? (tabThreats.get(tabId) || []).length : count;
        updateBadgeForTab(tabId, tabCount, active);
        sendResponse({ received: true, blockedCount: count, tabCount });
      });
    });
    return true;
  }

  if (message.type === "AEGIS_GET_STATE") {
    chrome.storage.local.get(["blockedCount", "threatHistory", "protectionActive", "allowlist"], (data) => {
      const tabList = typeof message.tabId === "number" ? (tabThreats.get(message.tabId) || []) : [];
      sendResponse({
        blockedCount: data.blockedCount || 0,
        threatHistory: Array.isArray(data.threatHistory) ? data.threatHistory : [],
        protectionActive: data.protectionActive !== false,
        allowlist: Array.isArray(data.allowlist) ? data.allowlist : [],
        tabThreats: tabList
      });
    });
    return true;
  }

  if (message.type === "AEGIS_SET_PROTECTION") {
    const active = Boolean(message.active);
    chrome.storage.local.set({ protectionActive: active }, () => {
      syncRuleset(active);
      updateBadgeForTab(undefined, 0, active);
      sendResponse({ ok: true, protectionActive: active });
    });
    return true;
  }

  if (message.type === "AEGIS_TOGGLE_ALLOWLIST") {
    const host = String(message.hostname || "").toLowerCase().trim();
    if (!host) {
      sendResponse({ ok: false, error: "Invalid hostname" });
      return;
    }
    chrome.storage.local.get(["allowlist"], (data) => {
      const list = Array.isArray(data.allowlist) ? [...data.allowlist] : [];
      const idx = list.indexOf(host);
      let allowlisted = false;
      if (idx >= 0) {
        list.splice(idx, 1);
      } else {
        list.push(host);
        allowlisted = true;
      }
      chrome.storage.local.set({ allowlist: list }, () => {
        sendResponse({ ok: true, allowlisted, allowlist: list });
      });
    });
    return true;
  }

  if (message.type === "AEGIS_CLEAR_HISTORY") {
    tabThreats.clear();
    chrome.storage.local.set({ blockedCount: 0, threatHistory: [] }, () => {
      chrome.storage.local.get(["protectionActive"], (data) => {
        updateBadgeForTab(undefined, 0, data.protectionActive !== false);
        sendResponse({ ok: true });
      });
    });
    return true;
  }
});

document.addEventListener("DOMContentLoaded", () => {
  const toggleBtn = document.getElementById("toggleProtection");
  const siteBar = document.getElementById("siteBar");
  const siteHostEl = document.getElementById("siteHost");
  const toggleSiteBtn = document.getElementById("toggleSiteBtn");
  const tabCountEl = document.getElementById("tabThreatCount");
  const totalCountEl = document.getElementById("totalThreatCount");
  const listTitleEl = document.getElementById("listTitle");
  const listEl = document.getElementById("threatList");
  const clearBtn = document.getElementById("clearHistoryBtn");

  let activeTabId = null;
  let currentHostname = "";
  let protectionActive = true;

  function render(state) {
    protectionActive = state.protectionActive !== false;
    toggleBtn.textContent = protectionActive ? "SHIELD ON" : "PAUSED";
    toggleBtn.classList.toggle("paused", !protectionActive);

    const allowlist = Array.isArray(state.allowlist) ? state.allowlist : [];
    if (currentHostname) {
      siteBar.style.display = "flex";
      const trusted = allowlist.includes(currentHostname);
      siteHostEl.textContent = trusted ? `${currentHostname} (Trusted)` : currentHostname;
      toggleSiteBtn.textContent = trusted ? "Re-enable Here" : "Trust This Site";
      toggleSiteBtn.classList.toggle("muted", trusted);
    }

    const tabItems = Array.isArray(state.tabThreats) ? state.tabThreats : [];
    const globalItems = Array.isArray(state.threatHistory) ? state.threatHistory : [];
    tabCountEl.textContent = String(tabItems.length);
    totalCountEl.textContent = String(state.blockedCount || 0);

    const items = tabItems.length > 0 ? tabItems : globalItems;
    listTitleEl.textContent = tabItems.length > 0 ? "Blocked on This Tab" : "Recent Blocked Traps (All Tabs)";
    listEl.textContent = "";

    if (items.length === 0) {
      const li = document.createElement("li");
      li.className = "empty";
      li.textContent = protectionActive
        ? "No hidden traps detected yet."
        : "Shield is paused — click PAUSED above to re-enable.";
      listEl.appendChild(li);
      return;
    }

    items.slice(0, 8).forEach((t) => {
      const li = document.createElement("li");
      li.className = "threat-item";
      const prefix = t.kind === "beacon" ? "[Beacon] " : "[Prompt Trap] ";
      li.textContent = prefix + (t.reason || "Blocked suspicious element");
      listEl.appendChild(li);
    });
  }

  function loadState() {
    if (!chrome.runtime?.sendMessage) return;
    chrome.runtime.sendMessage({ type: "AEGIS_GET_STATE", tabId: activeTabId }, (res) => {
      if (res) render(res);
    });
  }

  toggleBtn.addEventListener("click", () => {
    chrome.runtime.sendMessage({ type: "AEGIS_SET_PROTECTION", active: !protectionActive }, () => {
      loadState();
    });
  });

  toggleSiteBtn.addEventListener("click", () => {
    if (!currentHostname) return;
    chrome.runtime.sendMessage({ type: "AEGIS_TOGGLE_ALLOWLIST", hostname: currentHostname }, () => {
      loadState();
    });
  });

  clearBtn.addEventListener("click", () => {
    chrome.runtime.sendMessage({ type: "AEGIS_CLEAR_HISTORY" }, () => {
      loadState();
    });
  });

  if (chrome.tabs?.query) {
    chrome.tabs.query({ active: true, currentWindow: true }, (tabs) => {
      const tab = tabs && tabs[0];
      if (tab) {
        activeTabId = tab.id;
        try {
          const parsed = new URL(tab.url || "");
          if (parsed.protocol === "http:" || parsed.protocol === "https:") {
            currentHostname = parsed.hostname.toLowerCase();
          }
        } catch (_) {
          currentHostname = "";
        }
      }
      loadState();
    });
  } else {
    loadState();
  }
});

document.addEventListener("DOMContentLoaded", () => {
  const countEl = document.getElementById("threatCount");
  const listEl = document.getElementById("threatList");

  if (chrome.storage?.local) {
    chrome.storage.local.get(["blockedCount", "threatHistory"], (data) => {
      if (countEl) countEl.textContent = String(data.blockedCount || 0);

      const history = data.threatHistory || [];
      if (listEl && history.length > 0) {
        listEl.innerHTML = "";
        history.slice(0, 5).forEach((t) => {
          const li = document.createElement("li");
          li.className = "threat-item";
          li.textContent = `🛑 ${t.reason}`;
          listEl.appendChild(li);
        });
      }
    });
  }
});

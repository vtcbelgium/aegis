/**
 * Aegis AI Shield - In-Page Content Script
 * Scans web pages for hidden prompt injections, zero-font traps, and exfiltration beacons.
 */

(function () {
  "use strict";

  const INJECTION_TRIGGERS = [
    /ignore\s+(all\s+)?(previous|prior)\s+instructions/i,
    /system\s+prompt\s*:/i,
    /you\s+are\s+now\s+in\s+DAN\s+mode/i,
    /new\s+instructions\s+follow/i,
    /send\s+(the\s+)?(cookies|passwords|history|tokens)\s+to/i,
    /exfiltrate/i
  ];

  let quarantinedThreats = 0;

  function scanElement(el) {
    if (!el || el.nodeType !== Node.ELEMENT_NODE) return;

    // Check visibility styles
    const style = window.getComputedStyle(el);
    const isHidden = (
      style.fontSize === "0px" ||
      style.opacity === "0" ||
      style.visibility === "hidden" ||
      style.display === "none" ||
      (style.color === style.backgroundColor && style.color !== "rgba(0, 0, 0, 0)")
    );

    const text = el.textContent || "";
    if (text.length > 5) {
      for (const pattern of INJECTION_TRIGGERS) {
        if (pattern.test(text)) {
          quarantineElement(el, `Prompt injection signature [${pattern}]: "${text.slice(0, 60)}..."`, isHidden);
          break;
        }
      }
    }
  }

  function quarantineElement(el, reason, wasHidden) {
    quarantinedThreats++;
    console.warn(`[Aegis AI Shield] BLOCKED threat: ${reason}`);

    // Neutralize the threat text
    el.setAttribute("data-aegis-quarantined", "true");
    el.style.border = "2px dashed #ef4444";
    el.style.backgroundColor = "rgba(239, 68, 68, 0.15)";
    el.style.color = "#ef4444";
    el.style.fontSize = "11px";
    el.style.display = "block";
    el.style.visibility = "visible";
    el.style.opacity = "1";
    el.title = `🛡️ Aegis Blocked: ${reason}`;

    // Send threat notification to extension storage
    if (chrome.runtime?.sendMessage) {
      chrome.runtime.sendMessage({
        type: "AEGIS_THREAT_BLOCKED",
        threat: {
          url: window.location.href,
          reason,
          wasHidden,
          timestamp: new Date().toISOString()
        }
      }).catch(() => {});
    }
  }

  // Initial scan
  const allElements = document.querySelectorAll("p, span, div, b, i, strong, em, pre, code");
  for (let i = 0; i < allElements.length; i++) {
    scanElement(allElements[i]);
  }

  // MutationObserver for dynamic single-page apps
  const observer = new MutationObserver((mutations) => {
    for (const mutation of mutations) {
      for (const node of mutation.addedNodes) {
        if (node.nodeType === Node.ELEMENT_NODE) {
          scanElement(node);
          const children = node.querySelectorAll?.("p, span, div, b, i, strong, em, pre, code") || [];
          for (let j = 0; j < children.length; j++) scanElement(children[j]);
        }
      }
    }
  });

  observer.observe(document.body || document.documentElement, { childList: true, subtree: true });
})();

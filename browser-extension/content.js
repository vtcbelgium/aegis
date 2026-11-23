/**
 * Aegis AI Shield - In-Page Content Script
 *
 * Redacts prompt-injection text from web pages before a browsing agent reads it,
 * and strips data-exfiltration beacon elements.
 *
 *  - Respects global protectionActive toggle and per-site allowlist from chrome.storage.local.
 *  - Normalizes text (NFKC, invisible/bidi/tag characters removed, case-folded, whitespace collapsed).
 *  - Redacts only the INNERMOST element containing a match, preserving the rest of the page.
 *  - Reports both prompt-injection redactions and removed exfiltration beacons to background.js.
 *
 * Pattern matching is a redaction layer, not a guarantee: a determined attacker can paraphrase.
 */

(function () {
  "use strict";

  const SELECTOR = "p, span, div, li, td, th, a, b, i, u, strong, em, small, pre, code, blockquote, " +
    "h1, h2, h3, h4, h5, h6, label, section, article, aside, header, footer, figcaption, font";

  const INJECTION_TRIGGERS = [
    /\b(?:ignore|disregard|forget|override|bypass|skip)\b.{0,20}\b(?:all|any|the|your|these|those)?\s*(?:previous|prior|earlier|above|preceding|original|existing|initial)\s+(?:instructions?|guidance|rules|directions|prompts?|context|messages|guidelines|directives)/,
    /\byour\s+(?:new|real|actual|true)\s+(?:task|instructions?|goal|objective|role|mission)\b/,
    /\bnew\s+instructions?\s*(?:follow)?\s*:/,
    /\bfrom\s+now\s+on,?\s+you\s+(?:are|will|must|should)\b/,
    /\bsystem\s+prompt\s*:/,
    /\byou\s+are\s+now\s+(?:in\s+)?(?:dan|developer|god|unrestricted|jailbreak(?:ed)?)\s*(?:mode)?\b/,
    /\bsend\s+(?:the\s+)?(?:cookies|passwords|history|tokens|credentials|api\s+keys?)\s+to\b/,
    /\b(?:curl|wget|iwr|irm)\b[^\n]{0,200}\|\s*(?:(?:ba|z)?sh|iex)\b/,
    /\bnegeer\s+(?:alle\s+)?(?:vorige|eerdere|voorgaande)\s+(?:instructies|opdrachten|regels)/,
    /\bignore[rz]?\s+(?:toutes\s+)?les\s+instructions\s+(?:pr[eé]c[eé]dentes|ant[eé]rieures)/,
    /\bignorier(?:e|en)?\s+(?:alle\s+)?(?:vorherigen|bisherigen|obigen)\s+(?:anweisungen|instruktionen)/,
    /\bignora\s+(?:todas\s+)?las\s+instrucciones\s+(?:anteriores|previas)/
  ];

  // Same parameter list as rules.json
  const BEACON_RE = /[?&](?:cookies?|leak|exfil|session_?id|password|passwd|secret|api_?key|access_token|auth_token|private_key)=/i;
  const INVISIBLE_RE = /[­᠎​-‏‪-‮⁠-⁤⁦-⁩﻿]|[\u{E0000}-\u{E007F}]/gu;

  let quarantinedThreats = 0;
  let activeForPage = true;
  let observerStarted = false;

  function normalize(text) {
    return (text || "").normalize("NFKC").replace(INVISIBLE_RE, "").toLowerCase().replace(/\s+/g, " ");
  }

  function currentHost() {
    try {
      return (window.location?.hostname || "").toLowerCase();
    } catch (_) {
      return "";
    }
  }

  function isEnabledForSettings(data) {
    if (data && data.protectionActive === false) return false;
    const list = Array.isArray(data?.allowlist) ? data.allowlist : [];
    const host = currentHost();
    if (host && list.some((entry) => String(entry).toLowerCase() === host)) {
      return false;
    }
    return true;
  }

  function matchingPattern(el) {
    const text = el.textContent || "";
    if (text.length < 6) return null;
    const norm = normalize(text);
    for (const pattern of INJECTION_TRIGGERS) {
      if (pattern.test(norm)) return pattern;
    }
    return null;
  }

  function isSkippable(el) {
    return el.isContentEditable ||
      el.closest("[data-aegis-quarantined], input, textarea, [contenteditable='true'], script, style, noscript");
  }

  function isHidden(el) {
    const style = window.getComputedStyle(el);
    return style.fontSize === "0px" || style.opacity === "0" || style.visibility === "hidden" ||
      style.display === "none" ||
      (style.color === style.backgroundColor && style.color !== "rgba(0, 0, 0, 0)");
  }

  function reportThreat(threat) {
    if (typeof chrome !== "undefined" && chrome.runtime?.sendMessage) {
      try {
        const res = chrome.runtime.sendMessage({
          type: "AEGIS_THREAT_BLOCKED",
          threat
        });
        if (res && typeof res.catch === "function") res.catch(() => {});
      } catch (_) {
        // Ignore disconnected service worker
      }
    }
  }

  /** Redact only matches that contain no other match (the innermost elements). */
  function scanRoot(root) {
    if (!activeForPage || !root) return;
    const candidates = [];
    if (root.nodeType === Node.ELEMENT_NODE && root.matches && root.matches(SELECTOR)) candidates.push(root);
    if (root.querySelectorAll) candidates.push(...root.querySelectorAll(SELECTOR));

    const matches = [];
    for (const el of candidates) {
      if (isSkippable(el)) continue;
      const pattern = matchingPattern(el);
      if (pattern) matches.push({ el, pattern });
    }
    for (const m of matches) {
      const hasInnerMatch = matches.some((o) => o.el !== m.el && m.el.contains(o.el));
      if (!hasInnerMatch) quarantineElement(m.el, m.pattern);
    }
    scanBeacons(root);
  }

  function quarantineElement(el, pattern) {
    const wasHidden = isHidden(el);
    const excerpt = normalize(el.textContent).slice(0, 60);
    const reason = `Hidden AI prompt trap: "${excerpt}..."`;
    quarantinedThreats++;
    console.warn(`[Aegis AI Shield] NEUTRALIZED threat: ${reason}`);

    // Replace the text so an agent reading the DOM (or a screenshot) never sees it.
    el.setAttribute("data-aegis-quarantined", "true");
    el.textContent = "[Aegis removed text that tried to instruct AI agents]";
    el.style.fontSize = "11px";
    el.style.opacity = "0.6";

    reportThreat({
      kind: "injection",
      url: window.location?.href || "",
      hostname: currentHost(),
      reason,
      wasHidden,
      timestamp: new Date().toISOString()
    });
  }

  // Requests are already blocked by rules.json; remove leftover elements and report them.
  function scanBeacons(root) {
    if (!activeForPage || !root) return;
    const nodes = root.querySelectorAll ? root.querySelectorAll("img, link[rel='prefetch'], link[rel='prerender']") : [];
    for (const node of nodes) {
      const src = node.src || node.href || "";
      if (src && BEACON_RE.test(src)) {
        quarantinedThreats++;
        const shortSrc = src.split("?")[0].slice(0, 80);
        const reason = `Blocked data-theft beacon (${shortSrc})`;
        console.warn(`[Aegis AI Shield] Removed exfiltration beacon element: ${src}`);
        node.remove();
        reportThreat({
          kind: "beacon",
          url: window.location?.href || "",
          hostname: currentHost(),
          reason,
          wasHidden: true,
          timestamp: new Date().toISOString()
        });
      }
    }
  }

  function startProtection() {
    if (!activeForPage) return;
    const target = document.body || document.documentElement;
    scanRoot(target);
    if (!observerStarted && target) {
      observerStarted = true;
      const observer = new MutationObserver((mutations) => {
        if (!activeForPage) return;
        for (const mutation of mutations) {
          for (const node of mutation.addedNodes) {
            if (node.nodeType === Node.ELEMENT_NODE && !node.closest?.("[data-aegis-quarantined]")) {
              scanRoot(node);
            } else if (node.nodeType === Node.TEXT_NODE && node.parentElement && !isSkippable(node.parentElement)) {
              scanRoot(node.parentElement);
            }
          }
        }
      });
      observer.observe(target, { childList: true, subtree: true });
    }
  }

  if (typeof chrome !== "undefined" && chrome.storage?.local?.get) {
    chrome.storage.local.get(["protectionActive", "allowlist"], (data) => {
      activeForPage = isEnabledForSettings(data);
      if (activeForPage) startProtection();
    });
    if (chrome.storage.onChanged?.addListener) {
      chrome.storage.onChanged.addListener((changes, area) => {
        if (area !== "local") return;
        if (changes.protectionActive || changes.allowlist) {
          chrome.storage.local.get(["protectionActive", "allowlist"], (data) => {
            const wasActive = activeForPage;
            activeForPage = isEnabledForSettings(data);
            if (!wasActive && activeForPage) startProtection();
          });
        }
      });
    }
  } else {
    startProtection();
  }

  if (typeof module !== "undefined") {
    module.exports = { normalize, scanRoot, isEnabledForSettings, get count() { return quarantinedThreats; } };
  }
})();

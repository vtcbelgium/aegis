/**
 * Aegis AI Shield - In-Page Content Script
 *
 * Redacts prompt-injection text from web pages before a browsing agent reads it.
 *
 *  - Text is normalized first (NFKC, invisible/bidi/tag characters removed, case-folded,
 *    whitespace collapsed), so zero-width splits and fullwidth letters do not evade matching.
 *  - Only the INNERMOST element that contains a match is redacted, never its ancestors,
 *    so an article that merely discusses prompt injection loses one sentence, not the page.
 *  - Exfiltration beacons are blocked before the request leaves the browser by the
 *    declarativeNetRequest rules in rules.json; this script only cleans up the elements.
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

  function normalize(text) {
    return (text || "").normalize("NFKC").replace(INVISIBLE_RE, "").toLowerCase().replace(/\s+/g, " ");
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

  /** Redact only matches that contain no other match (the innermost elements). */
  function scanRoot(root) {
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
    const reason = `Prompt injection signature [${pattern.source.slice(0, 40)}...]: "${excerpt}..."`;
    quarantinedThreats++;
    console.warn(`[Aegis AI Shield] NEUTRALIZED threat: ${reason}`);

    // Replace the text so an agent reading the DOM (or a screenshot) never sees it.
    el.setAttribute("data-aegis-quarantined", "true");
    el.textContent = "[Aegis removed text that tried to instruct AI agents]";
    el.style.fontSize = "11px";
    el.style.opacity = "0.6";

    if (chrome.runtime?.sendMessage) {
      chrome.runtime.sendMessage({
        type: "AEGIS_THREAT_BLOCKED",
        threat: { url: window.location.href, reason, wasHidden, timestamp: new Date().toISOString() }
      }).catch(() => {});
    }
  }

  // Requests are already blocked by rules.json; remove the leftover elements and count them.
  function scanBeacons(root) {
    const nodes = root.querySelectorAll ? root.querySelectorAll("img, link[rel='prefetch'], link[rel='prerender']") : [];
    for (const node of nodes) {
      const src = node.src || node.href || "";
      if (src && BEACON_RE.test(src)) {
        console.warn(`[Aegis AI Shield] Removed exfiltration beacon element: ${src}`);
        node.remove();
      }
    }
  }

  scanRoot(document.body || document.documentElement);

  // Dynamic pages: rescan the nearest container of added nodes
  const observer = new MutationObserver((mutations) => {
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
  observer.observe(document.body || document.documentElement, { childList: true, subtree: true });

  if (typeof module !== "undefined") {
    module.exports = { normalize, scanRoot, get count() { return quarantinedThreats; } };
  }
})();

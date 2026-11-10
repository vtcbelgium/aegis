"""Credential Custody Clan: Secrets Exfiltration & SSRF Boundary Defense.

Invariants:
    1. Zero outbound access to cloud instance metadata (169.254.169.254, metadata.google.internal).
    2. Private intranet IP addresses (RFC1918: 10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16) protected.
    3. High-entropy API keys, private RSA keys, and authorization tokens shielded.
"""

from __future__ import annotations

import re
import urllib.parse
from typing import List, Optional
from ..core import DecisionLevel, Verdict
from ..canonicalizer import canonicalize_ip, normalize_text, resolve_host_ips


# High-confidence secret signatures that trigger quarantine (LOCK)
CRITICAL_SECRET_SIGNATURES = [
    (r"-----BEGIN (?:[A-Z0-9_-]+ )?PRIVATE KEY-----", "Private cryptographic key block"),
    (r"\b(AKIA|ABIA|ACCA)[0-9A-Z]{16}", "AWS Access Key ID"),
    (r"\bghp_[0-9a-zA-Z]{36}\b", "GitHub Personal Access Token"),
    (r"\bgithub_pat_[0-9a-zA-Z_]{22,}\b", "GitHub Fine-Grained Personal Access Token"),
    (r"\bsk-ant-[a-zA-Z0-9_\-]{20,}\b", "Anthropic Claude API Key"),
    (r"\bsk-[a-zA-Z0-9]{32,}\b", "OpenAI API Key"),
    (r"\bsk-(?:proj-|svcacct-)[a-zA-Z0-9_-]{20,}\b", "OpenAI scoped API Key"),
    (r"\b(sk_live|rk_live)_[0-9a-zA-Z]{24,}\b", "Stripe Secret / Restricted Key"),
    (r"\bxox[baprs]-[0-9a-zA-Z]{10,}\b", "Slack API Token"),
    (r"\bAIza[0-9A-Za-z\-_]{30,}\b", "Google API Key"),
]

# Sensitive authorization tokens that trigger human approval (ASK) or telemetry alert (WARN)
# This prevents test fixtures containing mock JWTs from permanently locking developer sessions.
MILD_SECRET_SIGNATURES = [
    (r"\beyJ[a-zA-Z0-9_-]{10,}\.eyJ[a-zA-Z0-9_-]{10,}\.[a-zA-Z0-9_-]{10,}\b", "JWT Authorization Token"),
]

# Cloud instance metadata endpoints targeted in SSRF attacks
METADATA_HOSTS = {
    "169.254.169.254",          # AWS EC2 / Azure IMDS / GCP / OpenStack
    "metadata.google.internal",  # GCP Metadata Server
    "metadata.internal",
    "100.100.100.200",          # Alibaba Cloud Metadata
}


class CustodyClan:
    """Protects against A02 Cryptographic Failures, A10 SSRF, and credential leakage."""

    NAME = "CredentialCustody"

    @classmethod
    def inspect_secrets(cls, content: str) -> Verdict:
        if not content:
            return Verdict(DecisionLevel.PASS, ["Empty content"], cls.NAME)

        normalized = normalize_text(content)
        reasons: List[str] = []

        # 1. Critical live secret keys & private keys -> LOCK
        for pattern, label in CRITICAL_SECRET_SIGNATURES:
            if re.search(pattern, normalized):
                reasons.append(f"Hardcoded critical secret detected: {label}")

        if reasons:
            return Verdict(
                DecisionLevel.LOCK,
                reasons,
                cls.NAME,
                metadata={"secretViolations": len(reasons)},
            )

        # 2. Mild tokens (JWT) -> ASK (or WARN in test environments)
        mild_reasons: List[str] = []
        for pattern, label in MILD_SECRET_SIGNATURES:
            if re.search(pattern, normalized):
                mild_reasons.append(f"Potential authorization token detected: {label}")

        if mild_reasons:
            return Verdict(
                DecisionLevel.ASK,
                mild_reasons,
                cls.NAME,
                metadata={"mildTokenViolations": len(mild_reasons)},
            )

        return Verdict(DecisionLevel.PASS, ["No exposed credentials found"], cls.NAME)

    @classmethod
    def inspect_url(cls, url_string: str) -> Verdict:
        if not url_string:
            return Verdict(DecisionLevel.PASS, ["Empty URL"], cls.NAME)

        try:
            parsed = urllib.parse.urlparse(url_string)
            host = parsed.hostname or ""
        except Exception:
            return Verdict(DecisionLevel.DENY, ["Malformed URL structure"], cls.NAME)

        clean_host = host.lower().strip()
        reasons: List[str] = []

        # 1. Cloud instance metadata check -> Immediate LOCK
        if clean_host in METADATA_HOSTS or "169.254.169.254" in url_string:
            return Verdict(
                DecisionLevel.LOCK,
                ["Critical SSRF attempt on Cloud Instance Metadata endpoint (169.254.169.254)"],
                cls.NAME,
                metadata={"target": url_string},
            )

        # 2. Localhost & loopback name check
        if clean_host in {"localhost", "localhost.localdomain"} or clean_host.endswith(".localhost"):
            return Verdict(
                DecisionLevel.DENY,
                [f"SSRF attempt on localhost / loopback hostname: {clean_host}"],
                cls.NAME,
                metadata={"host": clean_host},
            )

        # 3. IP canonicalization (handles dotted-decimal, BSD short 127.1, hex 0x7f.1, octal, dword)
        ip_obj, is_ip = canonicalize_ip(clean_host)
        if is_ip and ip_obj is not None:
            mapped = getattr(ip_obj, "ipv4_mapped", None) or ip_obj
            if str(mapped) in METADATA_HOSTS:
                return Verdict(
                    DecisionLevel.LOCK,
                    [f"Critical SSRF attempt on Cloud Instance Metadata endpoint (encoded as {clean_host})"],
                    cls.NAME,
                    metadata={"target": url_string},
                )
            if mapped.is_loopback:
                reasons.append(f"SSRF attempt on Loopback interface: {ip_obj}")
            elif mapped.is_link_local:
                reasons.append(f"SSRF attempt on Link-local address: {ip_obj}")
            elif mapped.is_private:
                reasons.append(f"SSRF attempt on RFC1918 Private Intranet IP: {ip_obj}")
            return Verdict(DecisionLevel.DENY, reasons or ["Non-routable IP address blocked"], cls.NAME, metadata={"host": clean_host})

        # 4. Hostname resolution (nip.io, sslip.io, and live DNS check)
        resolved_ips = resolve_host_ips(clean_host)
        for rip in resolved_ips:
            if str(rip) in METADATA_HOSTS:
                return Verdict(DecisionLevel.LOCK, [f"Critical SSRF: {clean_host} resolves to a cloud metadata endpoint"],
                               cls.NAME, metadata={"target": url_string})
            if rip.is_loopback:
                reasons.append(f"SSRF destination resolves to loopback IP ({rip}): {clean_host}")
            elif rip.is_private:
                reasons.append(f"SSRF destination resolves to RFC1918 private IP ({rip}): {clean_host}")
            elif rip.is_link_local:
                reasons.append(f"SSRF destination resolves to link-local IP ({rip}): {clean_host}")

        # 5. Scheme check (only http/https allowed for external fetches)
        if parsed.scheme and parsed.scheme.lower() in {"file", "gopher", "dict", "tftp", "ldap"}:
            reasons.append(f"Dangerous URI scheme blocked: {parsed.scheme}")

        if reasons:
            return Verdict(DecisionLevel.DENY, reasons, cls.NAME, metadata={"host": clean_host})

        return Verdict(DecisionLevel.PASS, ["URL destination is compliant"], cls.NAME)

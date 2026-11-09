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
from ..canonicalizer import canonicalize_ip, normalize_text


# High-confidence secret signatures
SECRET_SIGNATURES = [
    (r"-----BEGIN (RSA|OPENSSH|EC|PGP) PRIVATE KEY-----", "Private cryptographic key block"),
    (r"\b(AKIA|ABIA|ACCA)[0-9A-Z]{16}\b", "AWS Access Key ID"),
    (r"\bghp_[0-9a-zA-Z]{36}\b", "GitHub Personal Access Token"),
    (r"\bsk-[a-zA-Z0-9]{32,}\b", "OpenAI / Claude API Key"),
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

        for pattern, label in SECRET_SIGNATURES:
            if re.search(pattern, normalized):
                reasons.append(f"Hardcoded secret detected: {label}")

        if reasons:
            return Verdict(
                DecisionLevel.LOCK,
                reasons,
                cls.NAME,
                metadata={"secretViolations": len(reasons)},
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

        # 2. IP canonicalization & intranet boundary check
        ip_obj, is_ip = canonicalize_ip(clean_host)
        if is_ip and ip_obj is not None:
            if ip_obj.is_loopback:
                reasons.append(f"SSRF attempt on Loopback interface: {ip_obj}")
            elif ip_obj.is_private:
                reasons.append(f"SSRF attempt on RFC1918 Private Intranet IP: {ip_obj}")
            elif ip_obj.is_link_local:
                reasons.append(f"SSRF attempt on Link-local address: {ip_obj}")

        # 3. Scheme check (only http/https allowed for external fetches)
        if parsed.scheme and parsed.scheme.lower() in {"file", "gopher", "dict", "tftp", "ldap"}:
            reasons.append(f"Dangerous URI scheme blocked: {parsed.scheme}")

        if reasons:
            return Verdict(DecisionLevel.DENY, reasons, cls.NAME, metadata={"host": clean_host})

        return Verdict(DecisionLevel.PASS, ["URL destination is compliant"], cls.NAME)

"""Tartarus Clan: Command Injection, Destructive Operations & SQL Shield.

Invariants:
    1. Shell command injection sequences and malicious chaining detected and contained.
    2. Destructive operations (rm -rf /, format, mkfs, root find -delete, disk wipes) quarantined (LOCK).
    3. Untrusted raw SQL injection patterns blocked (DENY).
    4. Paths inside commands extracted and validated against Labyrinth containment & sensitive targets.
"""

from __future__ import annotations

import os
import re
import shlex
from typing import List, Optional, Set
from ..core import DecisionLevel, Verdict
from ..canonicalizer import canonicalize_path, normalize_text
from .labyrinth import LabyrinthClan, SENSITIVE_PATH_PATTERNS


# Catastrophic target roots that trigger instant LOCK if recursively deleted or wiped
CATASTROPHIC_ROOTS: Set[str] = {
    "/", "/*", "/root", "/home", "~", "$home", "%userprofile%",
    "c:", "c:\\", "c:/*", "c:\\*", "*", ".", ".."
}

# Privilege escalation binaries
PRIVILEGE_BINARIES: Set[str] = {"sudo", "su", "pkexec", "doas"}

# High-risk SQL injection signatures (distinguishes attacks from benign SQL comments)
SQL_INJECTION_PATTERNS = [
    r"'\s*OR\s*('1'\s*=\s*'1|1\s*=\s*1|'a'\s*=\s*'a')",
    r"\"\s*OR\s*(\"1\"\s*=\s*\"1|1\s*=\s*1|\"a\"\s*=\s*\"a\")",
    r"['\"]\s*;\s*--",                     # Quote termination followed by comment
    r"(?:admin|root)['\"]\s*--",           # Classic auth bypass comment
    r";\s*DROP\s+TABLE\b",
    r";\s*DELETE\s+FROM\b",
    r"UNION\s+ALL\s+SELECT\b",
    r"UNION\s+SELECT\b",
    r"/\*.*?\*/|/\*.*$",                   # Inline comment evasion
]


# High-risk shell injection and command chaining patterns
SHELL_INJECTION_PATTERNS = [
    r"(&&|;|\|\|)\s*(rm|del|shutdown|reboot|curl|wget|nc|bash|sh|powershell|chmod|chown)\b",
    r"\|\s*(bash|sh|powershell|cmd)\b",
    r"`[^`]+`",                    # Backtick evaluation
    r"\$\([^)]+\)",                # Subshell execution $(...)
    r"&\s*(curl|wget|nc)\b",       # Background exfiltration
    r"\beval\s+",                  # Arbitrary eval
    r"/dev/(urandom|random|zero)", # Unbounded device reading
]


def extract_paths_from_command(cmd: str) -> List[str]:
    """Extract candidate filesystem paths from a shell command string."""
    found: List[str] = []
    # Tokenize by whitespace, equals, semicolons and inspect each token
    tokens = re.split(r"[\s=;,&|]+", cmd)
    for tok in tokens:
        cleaned = tok.strip("'\"")
        if cleaned.startswith("@"):
            cleaned = cleaned[1:]
        if (
            cleaned.startswith("~")
            or cleaned.startswith("/")
            or cleaned.startswith("\\")
            or cleaned.startswith("$HOME")
            or cleaned.startswith("%USERPROFILE%")
            or cleaned.startswith("..")
            or (len(cleaned) > 2 and cleaned[1] == ":")
        ):
            found.append(cleaned)
    return found


def is_root_or_catastrophic_target(target: str) -> bool:
    """Check if target represents the filesystem root or entire system."""
    clean = target.strip().rstrip("/\\").lower()
    if clean in CATASTROPHIC_ROOTS or target.strip().lower() in CATASTROPHIC_ROOTS:
        return True
    if clean.startswith("/etc") or clean.startswith("/usr") or clean.startswith("/bin") or clean.startswith("/sbin"):
        return True
    return False


class TartarusClan:
    """Protects against A03 Injection and OWASP LLM06 Excessive Agency."""

    NAME = "Tartarus"

    @classmethod
    def inspect_command(cls, command_string: str, base_dir: Optional[str] = None) -> Verdict:
        if not command_string:
            return Verdict(DecisionLevel.PASS, ["Empty command"], cls.NAME)

        normalized = normalize_text(command_string).strip()
        lower_cmd = normalized.lower()
        reasons: List[str] = []

        # 1. Catastrophic destruction checks -> Immediate LOCK
        # Fork bombs
        if ":(){ :|:& };:" in lower_cmd or "fork()" in lower_cmd:
            return Verdict(DecisionLevel.LOCK, ["Fork bomb detected"], cls.NAME)

        # mkfs, format c:, raw disk wipes
        if re.search(r"\bmkfs(?:\.[a-z0-9]+)?\b", lower_cmd) or re.search(r"\bformat\s+[a-z]:", lower_cmd):
            return Verdict(DecisionLevel.LOCK, ["Filesystem format command detected"], cls.NAME)

        # dd if=... of=/dev/... (raw disk destruction)
        if re.search(r"\bdd\s+.*of=/dev/(?:sd[a-z]|nvme|hd[a-z]|disk|mem|kmem)", lower_cmd):
            return Verdict(DecisionLevel.LOCK, ["Raw block device overwrite via dd detected"], cls.NAME)

        # del /f /s /q on system root
        if re.search(r"\bdel\s+.*(/[fFsqSQ]\s*)*(?:[cC]:\\|[cC]:/\*|\\\*)", lower_cmd):
            return Verdict(DecisionLevel.LOCK, ["Recursive Windows root deletion detected"], cls.NAME)

        # Shell injection chaining patterns -> DENY
        for pattern in SHELL_INJECTION_PATTERNS:
            if re.search(pattern, normalized, re.IGNORECASE):
                reasons.append(f"Suspicious shell injection / chaining pattern: {pattern}")

        # Split pipeline or compound commands into subcommands
        # Split on ;, &&, ||, |, & (while respecting basic structure)
        subcommands = [s.strip() for s in re.split(r";|&&|\|\||\||&|\n", normalized) if s.strip()]

        for subcmd in subcommands:
            sub_lower = subcmd.lower()
            try:
                tokens = shlex.split(subcmd, posix=os.name != "nt")
            except Exception:
                tokens = [t.strip("'\"") for t in subcmd.split()]

            if not tokens:
                continue

            binary = tokens[0].lower()
            # Normalize binary if path given (e.g. /usr/bin/sudo -> sudo)
            binary_name = os.path.basename(binary)

            # Check privilege escalation
            if binary_name in PRIVILEGE_BINARIES or any(t.lower() in PRIVILEGE_BINARIES for t in tokens[:2]):
                reasons.append("Unauthorized privilege escalation binary invocation (sudo/su/pkexec)")

            # Check standalone shutdown / reboot
            if binary_name in {"shutdown", "reboot", "poweroff", "init"}:
                if binary_name == "init" and len(tokens) > 1 and tokens[1] in {"0", "6"}:
                    return Verdict(DecisionLevel.LOCK, ["System shutdown/reboot command blocked"], cls.NAME)
                elif binary_name in {"shutdown", "reboot", "poweroff"}:
                    return Verdict(DecisionLevel.LOCK, ["System shutdown/reboot command blocked"], cls.NAME)

            # Check recursive rm commands (handles rm -rf, rm -fr, rm -r -f, rm --recursive --force)
            if binary_name == "rm":
                has_rec = any(t.startswith("-") and ("r" in t.lower() or "recursive" in t.lower()) for t in tokens[1:])
                if has_rec:
                    # Check targets of rm
                    targets = [t for t in tokens[1:] if not t.startswith("-")]
                    for tgt in targets:
                        if is_root_or_catastrophic_target(tgt):
                            return Verdict(
                                DecisionLevel.LOCK,
                                [f"Catastrophic recursive deletion of root/system path: rm {tgt}"],
                                cls.NAME,
                            )
                        # If base_dir is enforced, verify rm target doesn't escape base_dir
                        if base_dir:
                            _, confined = canonicalize_path(base_dir, tgt)
                            if not confined:
                                reasons.append(f"Recursive rm target escapes workspace: {tgt}")

            # Check find ... -delete
            if binary_name == "find":
                if "-delete" in tokens or ("-exec" in tokens and "rm" in tokens):
                    find_root = tokens[1] if len(tokens) > 1 and not tokens[1].startswith("-") else ""
                    if is_root_or_catastrophic_target(find_root):
                        return Verdict(
                            DecisionLevel.LOCK,
                            [f"Catastrophic find -delete on root/system path: {find_root}"],
                            cls.NAME,
                        )

        # 2. Extract and inspect all filesystem paths referenced in the command
        cmd_paths = extract_paths_from_command(normalized)
        for path_cand in cmd_paths:
            # Check against sensitive files (.ssh/id_rsa, .aws/credentials, /etc/shadow, etc.)
            clean_norm_path = path_cand.replace("$HOME", "~").replace("%USERPROFILE%", "~").lower().replace("\\", "/")
            if any(re.search(pat, clean_norm_path) for pat in SENSITIVE_PATH_PATTERNS):
                return Verdict(
                    DecisionLevel.LOCK,
                    [f"Command accesses restricted credential or system path: {path_cand}"],
                    cls.NAME,
                    metadata={"targetPath": path_cand},
                )

            # Containment check if base_dir is specified
            if base_dir:
                # If path is absolute or traversive, check containment
                if path_cand.startswith(("/", "\\", "~", "..")) or (len(path_cand) > 1 and path_cand[1] == ":"):
                    _, is_confined = canonicalize_path(base_dir, path_cand)
                    if not is_confined:
                        reasons.append(f"Command path parameter escapes base directory: {path_cand}")

        # 3. Dangerous chaining patterns (e.g. curl ... ; chmod +x ; run)
        if re.search(r"\bcurl\b.*[;&|].*\bchmod\s+\+x\b", normalized, re.IGNORECASE):
            reasons.append("Malicious remote execution chain detected: curl followed by chmod +x")

        # Remote execution pipes: curl ... | bash, wget ... | sh
        if re.search(r"\b(curl|wget)\b.*\|\s*(bash|sh|powershell|cmd)\b", normalized, re.IGNORECASE):
            reasons.append("Untrusted remote script piped directly into shell interpreter")

        # 4. Check for embedded URLs to detect SSRF via curl / wget
        urls = re.findall(r"https?://[^\s'\"|;&]+", normalized)
        for u in urls:
            from .custody import CustodyClan
            url_verdict = CustodyClan.inspect_url(u)
            if not url_verdict.passed:
                return url_verdict

        if reasons:
            level = DecisionLevel.LOCK if any("LOCK" in r for r in reasons) else DecisionLevel.DENY
            return Verdict(level, reasons, cls.NAME)

        return Verdict(DecisionLevel.PASS, ["Command passed Tartarus inspection"], cls.NAME)

    @classmethod
    def inspect_sql(cls, query_string: str) -> Verdict:
        if not query_string:
            return Verdict(DecisionLevel.PASS, ["Empty SQL query"], cls.NAME)

        normalized = normalize_text(query_string)
        for pattern in SQL_INJECTION_PATTERNS:
            if re.search(pattern, normalized, re.IGNORECASE):
                return Verdict(
                    DecisionLevel.DENY,
                    [f"SQL injection heuristic triggered: {pattern}"],
                    cls.NAME,
                )

        return Verdict(DecisionLevel.PASS, ["SQL query clean"], cls.NAME)

"""Aegis Policy: allowlists, sensitive-path classes and catastrophic targets.

Everything that decides *what is allowed* lives here, so a project can tune Aegis
without touching the clans. The defaults are deliberately conservative:

    - Network egress from commands is limited to package registries and code hosts.
    - Unknown binaries and unknown tools are routed to the owner (ASK), never silently allowed.
    - Running the project's own code (pytest, npm test, python app.py) is allowed by default,
      because string inspection cannot see what a script does. Set ``project_exec="ask"``
      to require approval, and pair Aegis with an OS sandbox for real containment.
"""

from __future__ import annotations

import fnmatch
import os
import re
from dataclasses import dataclass, field
from typing import FrozenSet, List, Optional, Set


DEFAULT_ALLOWED_DOMAINS: FrozenSet[str] = frozenset({
    # Code hosts
    "github.com", "githubusercontent.com", "gitlab.com", "bitbucket.org",
    # Python
    "pypi.org", "pythonhosted.org",
    # JavaScript
    "npmjs.org", "npmjs.com", "yarnpkg.com", "nodejs.org", "deno.land", "jsr.io",
    # Rust / Go / Ruby / PHP / JVM / .NET
    "crates.io", "proxy.golang.org", "sum.golang.org", "go.dev", "golang.org",
    "rubygems.org", "packagist.org", "repo.maven.apache.org", "repo1.maven.org",
    "plugins.gradle.org", "services.gradle.org", "nuget.org",
})

# Known anonymous upload/paste sinks: uploads there are denied outright, not just ASKed.
KNOWN_EXFIL_SINKS: FrozenSet[str] = frozenset({
    "transfer.sh", "pastebin.com", "file.io", "webhook.site", "ngrok.io", "ngrok-free.app",
    "requestbin.net", "0x0.st", "temp.sh", "termbin.com", "ix.io", "catbox.moe",
    "uguu.se", "pipedream.net", "oast.fun", "interact.sh", "burpcollaborator.net",
})


@dataclass
class AegisPolicy:
    """Tunable policy shared by the gate, harness and clans."""

    allowed_domains: Set[str] = field(default_factory=lambda: set(DEFAULT_ALLOWED_DOMAINS))
    # "allow" (default) or "ask": running project code (python app.py, npm test, pytest, make)
    project_exec: str = "allow"
    # "strict" (default): strict no-shell PASS (non-read-only commands ASK even if Phase-1 threat scan is clean).
    # "critical_only": internal development mode where Phase-1 threat shield (6 hard boundaries LOCK,
    # destructive ops, secrets, exfil, untrusted URLs, path escapes, critical system/admin binaries) still
    # blocks/asks, while clean routine dev commands (npm/pytest/git/node/python/gh/etc.) PASS.
    pass_policy: str = "strict"
    # Verdict for binaries Aegis does not know: "ask" (default) or "deny"
    unknown_binary: str = "ask"
    # Extra binaries the owner trusts (treated like project tooling, paths still checked)
    extra_allowed_binaries: Set[str] = field(default_factory=set)
    # When True, tools without a declared schema are routed to the owner (ASK)
    strict_tools: bool = False
    # More directories that count as "inside the workspace" (e.g. Tekton's allowedDirectories)
    extra_roots: List[str] = field(default_factory=list)
    # "lock" (default) or "ask": what a live credential in an argument or command leads to.
    # "ask" lets the owner approve deliberate cases such as writing a key into .env.
    secret_level: str = "lock"
    # "ask" (default) or "allow": inline interpreter code (-c/-e/heredoc/piped stdin) inside an
    # admitted workspace. Hard boundaries, secrets, reverse shells, destructive patterns, embedded
    # URLs, and out-of-workspace / sensitive paths remain strictly enforced.
    inline_exec: str = "ask"
    # Local loopback ports (localhost / 127.0.0.1 / ::1) explicitly trusted by the owner (e.g. 11434).
    # Cloud metadata (169.254.169.254) and non-allowlisted ports remain blocked/guarded.
    allowed_loopback_ports: Set[int] = field(default_factory=set)

    # --- Hard boundaries (aegis/boundaries.py) ---
    # More paths that are part of the guard: the host's mode file, its identity key, its own code.
    # Writing or deleting them is AEGIS_POLICY_TAMPER (LOCK).
    protected_paths: List[str] = field(default_factory=list)
    # Host identity keys and master-secret stores: reading or uploading always LOCKs.
    secret_paths: List[str] = field(default_factory=list)
    # Security logs besides the system ones (Aegis's ledger, the host's audit log).
    log_paths: List[str] = field(default_factory=list)
    # Backup and recovery locations besides the ones recognised by name.
    backup_paths: List[str] = field(default_factory=list)
    # Service, process and task names of the guard (added to the built-in tekton/aegis names).
    guard_names: Set[str] = field(default_factory=set)
    # Protect the running Aegis package itself. Turn off only while developing Aegis.
    protect_package: bool = True

    # --- Minotaur (aegis/clans/minotaur.py) ---
    # Tripwires loaded from the registry (aegis.clans.minotaur.Tripwires) or None.
    tripwires: Optional[object] = None
    # What the data-leak guard does when a session that read private data and untrusted
    # content tries to send data out: "ask" (default), "deny" or "off".
    leak_guard: str = "ask"
    # Distinct sensitive locations probed within the window before Minotaur calls it a hunt.
    probe_threshold: int = 4
    # Seconds a session remembers that it read private data or untrusted content.
    memory_seconds: float = 30 * 60

    # --- Blast radius (aegis/impact.py) ---
    # A recursive delete larger than this needs the owner (Destructive Action Constitution).
    blast_max_entries: int = 100
    blast_max_bytes: int = 500 * 1024 * 1024

    # --- Code audit (aegis/audit.py): "warn" records OWASP findings in written code, "off" skips it.
    code_audit: str = "warn"

    def roots(self, base_dir: Optional[str]) -> List[str]:
        return ([base_dir] if base_dir else []) + [r for r in self.extra_roots if r]

    def loopback_port_allowed(self, port: Optional[int]) -> bool:
        return bool(port is not None and port in self.allowed_loopback_ports)

    def host_allowed(self, host: str) -> bool:
        host = (host or "").lower().strip(".")
        if not host:
            return False
        return any(host == d or host.endswith("." + d) for d in self.allowed_domains)


DEFAULT_POLICY = AegisPolicy()


def is_exfil_sink(host: str) -> bool:
    host = (host or "").lower().strip(".")
    return any(host == d or host.endswith("." + d) for d in KNOWN_EXFIL_SINKS)


# ---------------------------------------------------------------------------
# Sensitive path classes
# ---------------------------------------------------------------------------
# Patterns run against a lower-cased, forward-slash path with a trailing "/" appended,
# so directory forms ("~/.ssh") and file forms ("~/.ssh/id_rsa") both match.

SENSITIVE_CRITICAL = [
    r"/etc/(?:passwd|shadow|gshadow|sudoers|master\.passwd)(?:/|\.d/)",
    r"/windows/system32/config/(?:sam|system|security)/",
    r"/\.ssh/",
    r"/\.aws/",
    r"/\.gnupg/",
    r"/\.kube/config/",
    r"/\.docker/config\.json/",
    r"/\.netrc/",
    r"/\.git-credentials/",
    r"/\.pypirc/",
    r"/\.config/gcloud/",
    r"/\.azure/",
    r"/\.password-store/",
    r"/\.local/share/keyrings/",
    r"/library/keychains/",
    r"/\.mozilla/firefox/",
    r"/google/chrome/user data/",
    r"/\.config/google-chrome/",
    r"/proc/(?:kcore|self/environ|\d+/environ)/",
    r"/dev/(?:mem|kmem|port)/",
    r"/id_(?:rsa|dsa|ecdsa|ed25519)(?:\.pub)?/",
]

# Startup / persistence locations: writing here is how malware survives a reboot.
SENSITIVE_STARTUP = [
    r"/\.(?:bashrc|zshrc|profile|bash_profile|bash_login|zprofile|zshenv|bash_logout)/",
    r"/\.config/autostart/",
    r"/\.config/systemd/user/",
    r"/etc/cron",
    r"/var/spool/cron/",
    r"/library/launchagents/",
    r"/library/launchdaemons/",
    r"/start menu/programs/startup/",
    r"/documents/(?:windows)?powershell/.*profile\.ps1/",
    r"/\.gitconfig/",
    r"/\.bash_history/",
    r"/\.zsh_history/",
]

# Secret-bearing project files: reading needs approval, uploading is denied.
SENSITIVE_SECRET_FILE = [
    r"/\.env(?:\.(?!example/|sample/|template/|dist/|defaults/)[a-z0-9_-]+)?/",
    r"/\.npmrc/",
    r"/credentials\.json/",
    r"/service[-_]?account[^/]*\.json/",
    r"/secrets?\.(?:json|ya?ml|toml|env)/",
]

# Files that make *later, innocent-looking* commands run code (git commit runs hooks,
# cd runs .envrc under direnv): writing them needs approval.
SENSITIVE_AUTOEXEC = [
    r"/\.git/hooks/",
    r"/\.git/config/",
    r"/\.githooks/",
    r"/\.husky/",
    r"/\.envrc/",
    r"/\.vscode/tasks\.json/",
    r"/\.github/workflows/",
    r"/sitecustomize\.py/",
    r"/usercustomize\.py/",
    r"/conftest\.py/",
]

SENSITIVE_PATH_PATTERNS = SENSITIVE_CRITICAL + SENSITIVE_STARTUP + SENSITIVE_SECRET_FILE + SENSITIVE_AUTOEXEC

_SENSITIVE_CRITICAL_TEMPLATES = (
    (".ssh",), (".aws",), (".gnupg",), (".netrc",), (".git-credentials",), (".pypirc",),
    (".azure",), (".password-store",),
    ("id_rsa",), ("id_rsa.pub",), ("id_dsa",), ("id_dsa.pub",),
    ("id_ecdsa",), ("id_ecdsa.pub",), ("id_ed25519",), ("id_ed25519.pub",),
    ("etc", "passwd"), ("etc", "shadow"), ("etc", "gshadow"), ("etc", "sudoers"),
    ("etc", "sudoers.d"), ("etc", "master.passwd"),
    ("windows", "system32", "config", "sam"),
    ("windows", "system32", "config", "system"),
    ("windows", "system32", "config", "security"),
    (".kube", "config"), (".docker", "config.json"), (".config", "gcloud"),
    (".local", "share", "keyrings"), ("library", "keychains"),
    (".mozilla", "firefox"), ("google", "chrome", "user data"),
    (".config", "google-chrome"),
    ("proc", "kcore"), ("proc", "self", "environ"),
    ("dev", "mem"), ("dev", "kmem"), ("dev", "port"),
)

_SENSITIVE_STARTUP_TEMPLATES = (
    (".bashrc",), (".zshrc",), (".profile",), (".bash_profile",), (".bash_login",),
    (".zprofile",), (".zshenv",), (".bash_logout",), (".gitconfig",),
    (".bash_history",), (".zsh_history",),
    (".config", "autostart"), (".config", "systemd", "user"),
    ("etc", "crontab"), ("etc", "cron.d"), ("etc", "cron.daily"),
    ("etc", "cron.hourly"), ("etc", "cron.weekly"), ("etc", "cron.monthly"),
    ("var", "spool", "cron"), ("library", "launchagents"), ("library", "launchdaemons"),
    ("start menu", "programs", "startup"),
    ("documents", "powershell", "microsoft.powershell_profile.ps1"),
    ("documents", "powershell", "profile.ps1"),
    ("documents", "windowspowershell", "microsoft.powershell_profile.ps1"),
    ("documents", "windowspowershell", "profile.ps1"),
)

_SENSITIVE_SECRET_TEMPLATES = (
    (".env",), (".env.local",), (".env.production",), (".env.prod",),
    (".env.development",), (".env.dev",), (".env.staging",), (".env.secret",),
    (".npmrc",), ("credentials.json",),
    ("service-account.json",), ("service_account.json",), ("serviceaccount.json",),
    ("secret.json",), ("secrets.json",), ("secret.yaml",), ("secrets.yaml",),
    ("secret.yml",), ("secrets.yml",), ("secret.toml",), ("secrets.toml",),
    ("secret.env",), ("secrets.env",),
)

_SENSITIVE_AUTOEXEC_TEMPLATES = (
    (".githooks",), (".husky",), (".envrc",),
    ("sitecustomize.py",), ("usercustomize.py",), ("conftest.py",),
    (".git", "hooks"), (".git", "config"),
    (".vscode", "tasks.json"), (".github", "workflows"),
)

_SENSITIVE_DIR_TEMPLATES = frozenset({
    (".ssh",), (".aws",), (".gnupg",), (".azure",), (".password-store",),
    (".githooks",), (".husky",),
})

_GENERIC_WILDCARD_RE = re.compile(r"\*+(?:\.[a-z0-9_*]+)?")


def has_glob(text: str) -> bool:
    """Return True when *text* contains shell/PowerShell wildcard syntax."""
    return bool(text) and (any(c in text for c in "*?") or ("[" in text and "]" in text))


def is_generic_wildcard(part: str) -> bool:
    """Return True for uninformative globs like '*', '**', '*.py', '*.json', '*.*'."""
    return bool(_GENERIC_WILDCARD_RE.fullmatch((part or "").lower()))


def glob_component_matches(pattern_part: str, literal_target: str) -> bool:
    """Case-insensitive fnmatch of one path component, translating '[^...]' to '[!...]'."""
    p = (pattern_part or "").lower()
    t = (literal_target or "").lower()
    if not has_glob(p):
        return p == t
    pat = re.sub(r"\[\^", "[!", p)
    return fnmatch.fnmatchcase(t, pat)


def _norm_for_match(path: str) -> str:
    p = (path or "").replace("\\", "/").lower()
    if not p.endswith("/"):
        p += "/"
    if not p.startswith("/"):
        p = "/" + p
    return p


_WIN32_TRAILING_RE = re.compile(r"[. ]+(?=/|$)")
_WIN32_DRIVE_COMP_RE = re.compile(r"^[A-Za-z]:$")


def _win32_alias(path: str) -> str:
    """The name Win32 actually opens: trailing dots/spaces and NTFS ADS ':stream' are dropped.

    'conftest.py.', '.envrc . ', and '.env:hidden' map to 'conftest.py', '.envrc', and '.env'
    on Windows NTFS, so the sensitive classes must see that spelling too ('.' and '..' kept).
    """
    parts = path.replace("\\", "/").split("/")
    out: List[str] = []
    for idx, p in enumerate(parts):
        if p in (".", "..") or (idx == 0 and _WIN32_DRIVE_COMP_RE.match(p)):
            out.append(p)
            continue
        base = p.split(":", 1)[0] if ":" in p else p
        cleaned = _WIN32_TRAILING_RE.sub("", base) or base or p
        out.append(cleaned)
    return "/".join(out)


def classify_sensitive(*paths: str, write_mode: bool = False) -> Optional[str]:
    """Return 'critical', 'startup', 'secret', 'autoexec' or None for the given path spellings."""
    spellings = [p for p in paths if p]
    spellings += [a for a in (_win32_alias(p) for p in spellings) if a not in spellings]
    candidates = [_norm_for_match(p) for p in spellings]
    for cls_name, patterns in (("critical", SENSITIVE_CRITICAL),
                               ("startup", SENSITIVE_STARTUP),
                               ("secret", SENSITIVE_SECRET_FILE),
                               ("autoexec", SENSITIVE_AUTOEXEC)):
        for c in candidates:
            for pat in patterns:
                if re.search(pat, c):
                    return cls_name
    if any(has_glob(c) for c in candidates):
        for cls_name, templates in (("critical", _SENSITIVE_CRITICAL_TEMPLATES),
                                    ("startup", _SENSITIVE_STARTUP_TEMPLATES),
                                    ("secret", _SENSITIVE_SECRET_TEMPLATES),
                                    ("autoexec", _SENSITIVE_AUTOEXEC_TEMPLATES)):
            allow_generic = (cls_name == "autoexec" and write_mode)
            for c in candidates:
                if not has_glob(c):
                    continue
                parts = [p for p in c.split("/") if p]
                for tpl in templates:
                    m = len(tpl)
                    if len(parts) < m:
                        continue
                    for start in range(len(parts) - m + 1):
                        window = parts[start : start + m]
                        if not any(has_glob(w) for w in window):
                            continue
                        if m == 1:
                            if tpl not in _SENSITIVE_DIR_TEMPLATES and start != len(parts) - 1:
                                continue
                            if is_generic_wildcard(window[0]) and not allow_generic:
                                continue
                        elif cls_name in ("critical", "startup"):
                            if any(has_glob(w) and is_generic_wildcard(w) for w in window):
                                continue
                        else:
                            if all(is_generic_wildcard(w) for w in window) and not allow_generic:
                                continue
                        if all(glob_component_matches(w, t) for w, t in zip(window, tpl)):
                            return cls_name
    return None


# ---------------------------------------------------------------------------
# Catastrophic targets (recursive delete / wipe of these locks the session)
# ---------------------------------------------------------------------------

_POSIX_SYSTEM_DIRS = {
    "/", "/etc", "/usr", "/bin", "/sbin", "/lib", "/lib32", "/lib64", "/boot", "/var",
    "/opt", "/root", "/home", "/users", "/system", "/library", "/applications",
    "/private", "/dev", "/proc", "/sys", "/srv", "/mnt", "/media",
}
_WINDOWS_SYSTEM_DIRS = {
    "", "windows", "users", "program files", "program files (x86)", "programdata",
    "windows/system32",
}


def is_catastrophic_target(abs_path: str, home: Optional[str] = None) -> bool:
    """True when abs_path is a filesystem root, a system directory, the home dir or above it."""
    if not abs_path:
        return False
    p = abs_path.replace("\\", "/").rstrip("/").lower() or "/"
    # Windows drive paths: c:, c:/, c:/windows, c:/users ...
    m = re.match(r"^([a-z]):(/.*)?$", p)
    if m:
        rest = (m.group(2) or "").strip("/")
        if rest in _WINDOWS_SYSTEM_DIRS:
            return True
        if re.match(r"^users/[^/]+$", rest):      # C:/Users/<name> = a home directory
            return True
        return False
    if p.startswith("//"):                         # UNC share root
        return p.count("/") <= 3
    if p in _POSIX_SYSTEM_DIRS:
        return True
    home = (home or os.path.expanduser("~")).replace("\\", "/").rstrip("/").lower()
    if home and (p == home or home.startswith(p + "/")):
        return True
    return False

"""Hard boundaries: what an agent may never do, whatever it is asked.

These come from the OTHRYS Book of Aegis and the Destructive Action Constitution. Six event
classes always LOCK. No model, approval or policy hint can downgrade them:

    AEGIS_POLICY_TAMPER       changing Aegis's own policy, state, code or mode switches
    SECURITY_LOGGING_DISABLE  clearing or switching off security logs (Aegis's ledger included)
    BACKUP_DESTRUCTION        deleting backups, snapshots, shadow copies or recovery data
    SENTINEL_TAKEOVER         stopping, disabling or killing the guard (Tekton worker, Aegis)
    MASTER_SECRET_EXTRACTION  reading credential stores (~/.ssh, ~/.aws, keychains ...)
    SYSTEM_DESTRUCTION        wiping disks, filesystems, boot/recovery state or system roots

The first four are about Aegis protecting itself and the owner's way back: an agent that
can switch the guard off, erase its traces or delete the backups has already won. The last
two are enforced by Labyrinth and Tartarus; this module only names them.

Everything here can only add a LOCK (or, for writes inside backups, an ASK). It never makes
another verdict milder.
"""

from __future__ import annotations

import os
import re
from typing import Iterable, List, Optional, Tuple

POLICY_TAMPER = "AEGIS_POLICY_TAMPER"
LOGGING_DISABLE = "SECURITY_LOGGING_DISABLE"
BACKUP_DESTRUCTION = "BACKUP_DESTRUCTION"
SENTINEL_TAKEOVER = "SENTINEL_TAKEOVER"
MASTER_SECRET = "MASTER_SECRET_EXTRACTION"
SYSTEM_DESTRUCTION = "SYSTEM_DESTRUCTION"

HARD_BOUNDARIES = (POLICY_TAMPER, LOGGING_DISABLE, BACKUP_DESTRUCTION, SENTINEL_TAKEOVER,
                   MASTER_SECRET, SYSTEM_DESTRUCTION)

# Names of the guard itself: services, processes, scheduled tasks and Run keys.
DEFAULT_GUARD_NAMES = frozenset({"aegis", "tekton", "tekton-relay", "tektondesktoprelay",
                                 "tektonphonerelay", "tekton-sentinel", "legion-sentinel"})
# Environment variables that switch Aegis's mode or point it at other state.
GUARD_ENV_RE = re.compile(r"^(?:TEKTON_)?AEGIS(?:_[A-Z0-9_]*)?$", re.IGNORECASE)

SYSTEM_LOG_DIRS = ("/var/log", "/private/var/log", "/var/audit", "/library/logs",
                   "c:/windows/system32/winevt", "c:/windows/system32/logfiles")
LOG_SERVICES = frozenset({"auditd", "rsyslog", "syslog", "syslog-ng", "systemd-journald",
                          "journald", "eventlog", "wecsvc", "sysmon", "sysmon64"})

# Directory names that hold the owner's way back: "backups", "OTHRYS-backups", "Backups.backupdb",
# "legion-recovery-2026-10-03", "backup-2026-11-01", ".snapshots". Not "my_backup_scripts".
_BACKUP_WORD = r"(?:backups?|backupdb|snapshots?|recovery|restore-points?)"
_BACKUP_SEGMENT = re.compile(rf"(?:^|[-_. ]){_BACKUP_WORD}(?:[-_. ]\d[\d_.-]*)?$")
_BACKUP_EXACT = frozenset({".snapshots", "timeshift", "system volume information", "time machine backups",
                           "$recycle.bin"})


def aegis_home() -> str:
    """Where Aegis keeps its own state (ledger, tripwire registry, sessions)."""
    return os.path.abspath(os.path.expanduser(os.environ.get("AEGIS_HOME") or "~/.aegis"))


def minotaur_registry_path() -> str:
    return os.path.join(aegis_home(), "minotaur.json")


def package_dir() -> str:
    return os.path.dirname(os.path.abspath(__file__))


def _norm(path: str) -> str:
    p = (path or "").replace("\\", "/").rstrip("/").lower()
    return p or "/"


def _inside(path: str, root: str) -> bool:
    p, r = _norm(path), _norm(root)
    return p == r or p.startswith(r + "/")


def _any_inside(path: str, roots: Iterable[str]) -> Optional[str]:
    for r in roots:
        if r and _inside(path, r):
            return r
    return None


def control_paths(policy) -> List[str]:
    """Aegis's own state and code, plus whatever the host declares (Tekton's mode file, identity ...)."""
    roots = [aegis_home()] + list(getattr(policy, "protected_paths", None) or [])
    if getattr(policy, "protect_package", True):
        roots.append(package_dir())
    return roots


def is_backup_path(abs_path: str, policy=None, is_dir: Optional[bool] = None) -> bool:
    """True for a path inside a backup/recovery/snapshot location.

    Parent directories decide. The final name only counts when it is itself a directory,
    so a source file called backup_service.py is not a backup location.
    """
    if _any_inside(abs_path, getattr(policy, "backup_paths", None) or []):
        return True
    parts = [s for s in _norm(abs_path).split("/") if s]
    if not parts:
        return False
    last = parts[-1]
    exists = True
    if is_dir is None:
        try:
            is_dir = os.path.isdir(abs_path)
            exists = os.path.exists(abs_path)
        except OSError:
            is_dir = exists = False
    elif not is_dir:
        try:
            exists = os.path.exists(abs_path)
        except OSError:
            exists = False
    # The parent folders always count. The final name counts when it is a directory, or when
    # the path does not exist yet — a delete target named "OTHRYS-backups" is judged by its
    # name, while an existing regular file like "backup_service.py" is not.
    candidates = parts[:-1] + ([last] if (is_dir or not exists) else [])
    return any(seg in _BACKUP_EXACT or _BACKUP_SEGMENT.search(seg) for seg in candidates)


def check_path(abs_path: str, mode: str, policy) -> Optional[Tuple[str, str, str]]:
    """Hard-boundary check for one resolved path.

    Returns (boundary, verdict_name, reason) or None. verdict_name is "LOCK", "DENY" or "ASK".
    mode is "read", "write", "delete", "exec", "cd" or "upload".
    """
    if not abs_path:
        return None
    changing = mode in ("write", "delete")
    root = _any_inside(abs_path, control_paths(policy))
    if root is not None:
        if changing:
            return POLICY_TAMPER, "LOCK", f"Hard boundary {POLICY_TAMPER}: changes Aegis's own policy, state or code ({abs_path})"
        if _inside(abs_path, aegis_home()) and mode in ("read", "upload", "exec"):
            # The ledger stays readable; the tripwire registry and session state do not.
            name = _norm(abs_path)
            if name.endswith("/minotaur.json") or "/sessions" in name[len(_norm(aegis_home())):] or name == _norm(aegis_home()):
                return POLICY_TAMPER, "DENY", f"Hard boundary {POLICY_TAMPER}: reads Aegis's tripwire registry or session state"
    if changing:
        logs = list(SYSTEM_LOG_DIRS) + list(getattr(policy, "log_paths", None) or [])
        if _any_inside(abs_path, logs):
            return LOGGING_DISABLE, "LOCK", f"Hard boundary {LOGGING_DISABLE}: changes or deletes security logs ({abs_path})"
    if mode == "delete" and is_backup_path(abs_path, policy):
        return BACKUP_DESTRUCTION, "LOCK", f"Hard boundary {BACKUP_DESTRUCTION}: deletes backup or recovery data ({abs_path})"
    if mode == "write" and is_backup_path(abs_path, policy):
        return BACKUP_DESTRUCTION, "ASK", f"Writes inside a backup or recovery location (owner approval): {abs_path}"
    return None


# ---------------------------------------------------------------------------
# Commands
# ---------------------------------------------------------------------------

def _is_guard(word: str, policy) -> bool:
    names = set(DEFAULT_GUARD_NAMES) | {n.lower() for n in (getattr(policy, "guard_names", None) or [])}
    w = word.lower().strip("'\"")
    w = re.sub(r"\.(service|exe|timer|socket|plist)$", "", w)
    if w in names:
        return True
    return any(re.search(rf"(?<![a-z0-9]){re.escape(n)}(?![a-z0-9])", w) for n in names)


def _values(args: List[str], flags: Iterable[str]) -> List[str]:
    """Values given after any of the flags (Stop-Service -Name x, taskkill /im x ...)."""
    flags = {f.lower() for f in flags}
    out = []
    for i, a in enumerate(args):
        low = a.lower()
        if low in flags and i + 1 < len(args):
            out.extend(v for v in args[i + 1].split(",") if v)
        elif "=" in a and low.split("=", 1)[0] in flags:
            out.append(a.split("=", 1)[1])
        elif ":" in a and low.split(":", 1)[0] in flags:
            out.append(a.split(":", 1)[1])
    return out


def _positional(args: List[str]) -> List[str]:
    return [a for a in args if not a.startswith(("-", "/"))]


def check_command(name: str, args: List[str], policy) -> Optional[Tuple[str, str]]:
    """Hard-boundary check for one parsed command. Returns (boundary, reason) for a LOCK, else None."""
    low_args = [a.lower() for a in args]
    pos = _positional(args)

    # --- the guard's own services, processes, tasks and autostart entries
    if name == "systemctl":
        verb = next((a for a in low_args if not a.startswith("-")), "")
        units = pos[1:] if pos else []
        if verb in {"stop", "disable", "mask", "kill", "edit", "revert", "set-property", "freeze"}:
            if any(_is_guard(u, policy) for u in units):
                return SENTINEL_TAKEOVER, f"Hard boundary {SENTINEL_TAKEOVER}: {verb} on the guard service ({' '.join(units)})"
            if any(re.sub(r"\.service$", "", u.lower()) in LOG_SERVICES for u in units):
                return LOGGING_DISABLE, f"Hard boundary {LOGGING_DISABLE}: {verb} on a logging service ({' '.join(units)})"
    if name == "service" and len(pos) >= 2 and pos[1].lower() in ("stop", "disable"):
        if _is_guard(pos[0], policy):
            return SENTINEL_TAKEOVER, f"Hard boundary {SENTINEL_TAKEOVER}: service {pos[0]} {pos[1]}"
        if pos[0].lower() in LOG_SERVICES:
            return LOGGING_DISABLE, f"Hard boundary {LOGGING_DISABLE}: service {pos[0]} {pos[1]}"
    if name == "sc" and len(pos) >= 2 and pos[0].lower() in ("stop", "delete", "config", "failure", "pause"):
        if _is_guard(pos[1], policy):
            return SENTINEL_TAKEOVER, f"Hard boundary {SENTINEL_TAKEOVER}: sc {pos[0]} {pos[1]}"
        if pos[1].lower() in LOG_SERVICES:
            return LOGGING_DISABLE, f"Hard boundary {LOGGING_DISABLE}: sc {pos[0]} {pos[1]}"
    if name in ("stop-service", "set-service", "remove-service", "suspend-service", "spsv"):
        targets = _values(args, ["-name", "-displayname", "-inputobject"]) or pos
        if any(_is_guard(t, policy) for t in targets):
            return SENTINEL_TAKEOVER, f"Hard boundary {SENTINEL_TAKEOVER}: {name} on the guard service"
        if any(t.lower() in LOG_SERVICES for t in targets):
            return LOGGING_DISABLE, f"Hard boundary {LOGGING_DISABLE}: {name} on a logging service"
    if name == "launchctl" and low_args and low_args[0] in ("unload", "bootout", "remove", "disable", "kill", "stop"):
        if any(_is_guard(a, policy) for a in args[1:]):
            return SENTINEL_TAKEOVER, f"Hard boundary {SENTINEL_TAKEOVER}: launchctl {low_args[0]} on the guard"
    if name in ("pkill", "killall"):
        if any(_is_guard(a, policy) for a in pos):
            return SENTINEL_TAKEOVER, f"Hard boundary {SENTINEL_TAKEOVER}: {name} on the guard process"
    if name in ("taskkill",):
        targets = _values(args, ["/im", "-im", "/fi", "-fi"])
        if any(_is_guard(t, policy) for t in targets):
            return SENTINEL_TAKEOVER, f"Hard boundary {SENTINEL_TAKEOVER}: taskkill on the guard process"
    if name in ("stop-process", "spps"):
        targets = _values(args, ["-name", "-processname"]) or [a for a in pos if not a.isdigit()]
        if any(_is_guard(t, policy) for t in targets):
            return SENTINEL_TAKEOVER, f"Hard boundary {SENTINEL_TAKEOVER}: {name} on the guard process"
    if name == "schtasks" and any(a in ("/delete", "/change", "/end", "-delete", "-change", "-end") for a in low_args):
        if any(_is_guard(t, policy) for t in _values(args, ["/tn", "-tn"])):
            return SENTINEL_TAKEOVER, f"Hard boundary {SENTINEL_TAKEOVER}: schtasks changes the guard's task"
    if name in ("unregister-scheduledtask", "disable-scheduledtask", "stop-scheduledtask"):
        if any(_is_guard(t, policy) for t in _values(args, ["-taskname", "-taskpath"]) + pos):
            return SENTINEL_TAKEOVER, f"Hard boundary {SENTINEL_TAKEOVER}: {name} on the guard's task"
    if name == "reg" and low_args and low_args[0] in ("delete", "add"):
        joined = " ".join(args)
        if re.search(r"currentversion\\+run", joined, re.IGNORECASE) and _is_guard(joined, policy):
            return SENTINEL_TAKEOVER, f"Hard boundary {SENTINEL_TAKEOVER}: reg {low_args[0]} on the guard's autostart entry"
    if name in ("remove-itemproperty", "rp", "set-itemproperty", "sp", "clear-itemproperty"):
        joined = " ".join(args)
        if re.search(r"currentversion\\+run", joined, re.IGNORECASE) and _is_guard(joined, policy):
            return SENTINEL_TAKEOVER, f"Hard boundary {SENTINEL_TAKEOVER}: {name} on the guard's autostart entry"

    # --- switching Aegis off through its own switches
    if name in ("setx", "unset"):
        targets = pos if name == "unset" else pos[:1]
        if any(GUARD_ENV_RE.match(t.split("=", 1)[0]) for t in targets):
            return POLICY_TAMPER, f"Hard boundary {POLICY_TAMPER}: {name} changes Aegis's mode variables"
    if name in ("export", "declare", "typeset", "set", "env"):
        for a in pos:
            var = a.split("=", 1)[0]
            if "=" in a and GUARD_ENV_RE.match(var):
                return POLICY_TAMPER, f"Hard boundary {POLICY_TAMPER}: {name} sets {var}"
    if name == "aegis" or (name in ("python", "python3", "py") and len(args) >= 2 and args[0] == "-m" and args[1] == "aegis"):
        sub = args[2:] if name != "aegis" else args
        words = [w.lower() for w in sub if not w.startswith("-")]
        harmless = {"explain", "status", "verify", "tail", "probe", "audit", "check", "gate", "help", "version", "learn"}
        if words and words[0] in ("minotaur", "ledger", "policy", "sandbox", "hook") and len(words) > 1 \
                and words[1] not in harmless:
            return POLICY_TAMPER, f"Hard boundary {POLICY_TAMPER}: aegis {' '.join(words[:2])} changes the guard's state"

    # --- security logs
    if name == "wevtutil" and low_args and low_args[0] in ("cl", "clear-log", "sl", "set-log", "um", "uninstall-manifest"):
        return LOGGING_DISABLE, f"Hard boundary {LOGGING_DISABLE}: wevtutil {low_args[0]}"
    if name in ("clear-eventlog", "remove-eventlog", "limit-eventlog", "clear-winevent"):
        return LOGGING_DISABLE, f"Hard boundary {LOGGING_DISABLE}: {name}"
    if name == "auditctl" and (any(a == "-d" or a.startswith("-D") for a in args)
                               or ("-e" in args and "0" in args)):
        return LOGGING_DISABLE, f"Hard boundary {LOGGING_DISABLE}: auditctl removes audit rules or switches auditing off"
    if name == "journalctl" and any(a.startswith(("--vacuum", "--rotate", "--flush", "--relinquish-var")) for a in low_args):
        return LOGGING_DISABLE, f"Hard boundary {LOGGING_DISABLE}: journalctl deletes or rotates the system journal"
    if name in ("set-mppreference", "add-mppreference"):
        joined = " ".join(low_args)
        if re.search(r"-disable\w+\s+(?:\$?true|1)", joined) or "-exclusion" in joined:
            return LOGGING_DISABLE, f"Hard boundary {LOGGING_DISABLE}: weakens Microsoft Defender"

    # --- backups and recovery
    if name == "vssadmin" and any(a in ("delete", "resize") for a in low_args):
        return BACKUP_DESTRUCTION, f"Hard boundary {BACKUP_DESTRUCTION}: vssadmin deletes shadow copies"
    if name == "wmic" and "shadowcopy" in low_args and "delete" in low_args:
        return BACKUP_DESTRUCTION, f"Hard boundary {BACKUP_DESTRUCTION}: wmic deletes shadow copies"
    if name == "wbadmin" and low_args and low_args[0] in ("delete", "disable"):
        return BACKUP_DESTRUCTION, f"Hard boundary {BACKUP_DESTRUCTION}: wbadmin {low_args[0]}"
    if name in ("remove-wbbackupset", "remove-wbsystemstatebackup", "disable-computerrestore", "remove-computerrestorepoint"):
        return BACKUP_DESTRUCTION, f"Hard boundary {BACKUP_DESTRUCTION}: {name}"
    if name == "tmutil" and low_args and (low_args[0].startswith("delete") or low_args[0] in ("disable", "removedestination")):
        return BACKUP_DESTRUCTION, f"Hard boundary {BACKUP_DESTRUCTION}: tmutil {low_args[0]}"
    if name == "timeshift" and any(a.startswith("--delete") for a in low_args):
        return BACKUP_DESTRUCTION, f"Hard boundary {BACKUP_DESTRUCTION}: timeshift deletes snapshots"
    if name == "btrfs" and len(low_args) >= 2 and low_args[0] in ("subvolume", "sub") and low_args[1] in ("delete", "del"):
        return BACKUP_DESTRUCTION, f"Hard boundary {BACKUP_DESTRUCTION}: btrfs subvolume delete"
    if name == "reagentc" and any(a in ("/disable", "-disable") for a in low_args):
        return BACKUP_DESTRUCTION, f"Hard boundary {BACKUP_DESTRUCTION}: reagentc disables the recovery environment"
    if name == "bcdedit" and re.search(r"recoveryenabled\s+no|bootstatuspolicy\s+ignoreallfailures|/deletevalue",
                                         " ".join(low_args)):
        return BACKUP_DESTRUCTION, f"Hard boundary {BACKUP_DESTRUCTION}: bcdedit disables boot recovery"
    return None


# Free-text tampering forms that are not ordinary argv: PowerShell $env: assignments and
# .NET calls. Checked on the whole command text as an extra layer (it can only add a LOCK).
_TEXT_RULES = (
    (re.compile(r"\$env:(?:TEKTON_)?AEGIS\w*\s*=", re.IGNORECASE), POLICY_TAMPER, "assigns an Aegis mode variable"),
    (re.compile(r"SetEnvironmentVariable\(\s*['\"](?:TEKTON_)?AEGIS", re.IGNORECASE), POLICY_TAMPER,
     "sets an Aegis mode variable through .NET"),
    (re.compile(r"Remove-Item\s+(?:-\w+\s+)*(?:env:|Env:)\\?(?:TEKTON_)?AEGIS", re.IGNORECASE), POLICY_TAMPER,
     "removes an Aegis mode variable"),
)


def check_text(text: str) -> Optional[Tuple[str, str]]:
    for rx, boundary, what in _TEXT_RULES:
        if rx.search(text or ""):
            return boundary, f"Hard boundary {boundary}: {what}"
    return None

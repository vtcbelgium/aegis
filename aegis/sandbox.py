"""Tartarus: OS-level confinement, so a command can only touch what the policy allows.

Aegis reads the command text; it cannot see what a program does once it runs (python app.py
may do anything). The OTHRYS Book of Aegis reserved **Tartarus** for "isolated/quarantine
execution ... with proven sandbox technology rather than a custom hypervisor". This is that
layer. One policy, enforced twice: Aegis judges the call, the sandbox limits what it can reach.

It builds a Linux `bubblewrap` (bwrap) wrapper from an AegisPolicy — ported from the OTHRYS
T590 coding-test sandbox, verified there on a real unprivileged user namespace:

    workspace (and extra_roots) read-write; the rest of the system read-only; the home
    directory, credential stores and Aegis's own state hidden; no network by default; a
    fresh PID/IPC/UTS namespace; a cleared environment; dies with its parent.

It never weakens Aegis. If bwrap cannot run (not Linux, not installed, no user namespaces),
`wrap()` fails closed: it raises SandboxUnavailable and the caller decides (Tekton runs the
job unsandboxed only when the owner allows it, and says so).

This is the srt-style approach (Anthropic's sandbox-runtime) done with the tool already proven
on the T590; `probe()` reports whether srt or bwrap is the better backend on this host.
"""

from __future__ import annotations

import os
import shutil
import subprocess
from dataclasses import dataclass, field
from typing import List, Optional

# Credential stores and Aegis state are masked even inside an allowed root.
HIDE_HOME_SUBPATHS = (".ssh", ".aws", ".gnupg", ".kube", ".docker", ".config/gcloud", ".azure",
                      ".password-store", ".netrc", ".git-credentials", ".npmrc", ".pypirc",
                      ".aegis", ".config/aegis")
SYSTEM_RO = ("/usr", "/bin", "/sbin", "/lib", "/lib32", "/lib64", "/etc/alternatives",
             "/etc/ssl/certs", "/opt")


class SandboxUnavailable(RuntimeError):
    """bwrap cannot confine on this host; the caller must decide what to do."""


@dataclass
class SandboxProfile:
    workspace: str
    extra_roots: List[str] = field(default_factory=list)
    network: bool = False
    allow_home_read: bool = False
    tmp_writable: bool = True
    hide: List[str] = field(default_factory=lambda: list(HIDE_HOME_SUBPATHS))

    @classmethod
    def from_policy(cls, policy, workspace: str, network: bool = False) -> "SandboxProfile":
        roots = [r for r in (getattr(policy, "extra_roots", None) or []) if r]
        return cls(workspace=os.path.abspath(workspace), extra_roots=[os.path.abspath(r) for r in roots],
                   network=network)


def bwrap_path() -> Optional[str]:
    return shutil.which("bwrap")


def srt_path() -> Optional[str]:
    return shutil.which("srt")


def _user_namespaces_ok() -> bool:
    try:
        with open("/proc/sys/kernel/unprivileged_userns_clone") as fh:
            if fh.read().strip() == "0":
                return False
    except FileNotFoundError:
        pass
    except OSError:
        return False
    return True


def available() -> bool:
    return os.name == "posix" and os.uname().sysname == "Linux" and bool(bwrap_path()) and _user_namespaces_ok()


def probe() -> dict:
    """Report what confinement this host can do, and prove bwrap actually runs."""
    info = {
        "platform": os.uname().sysname if os.name == "posix" else os.name,
        "bwrap": bwrap_path(), "srt": srt_path(),
        "userNamespaces": _user_namespaces_ok(), "works": False, "backend": None, "error": None,
    }
    if not available():
        info["error"] = "bubblewrap unavailable (needs Linux, bwrap and unprivileged user namespaces)"
        return info
    try:
        r = subprocess.run([bwrap_path(), "--unshare-all", "--die-with-parent", "--ro-bind", "/usr", "/usr",
                            "--ro-bind", "/lib", "/lib", "--proc", "/proc", "--dev", "/dev",
                            "/usr/bin/true" if os.path.exists("/usr/bin/true") else "/bin/true"],
                           capture_output=True, timeout=10)
        info["works"] = r.returncode == 0
        info["backend"] = "bwrap"
        if r.returncode != 0:
            info["error"] = r.stderr.decode("utf-8", "replace")[:200]
    except Exception as exc:  # noqa: BLE001
        info["error"] = f"{type(exc).__name__}: {exc}"
    return info


def build_argv(profile: SandboxProfile, command: List[str], *, shell: Optional[str] = None) -> List[str]:
    """Build the bwrap argv that runs `command` under the profile. Raises if unavailable."""
    bw = bwrap_path()
    if not available() or not bw:
        raise SandboxUnavailable("bubblewrap unavailable (needs Linux, bwrap and user namespaces)")
    ws = os.path.abspath(profile.workspace)
    if not os.path.isdir(ws):
        raise SandboxUnavailable(f"workspace does not exist: {ws}")

    argv: List[str] = [bw, "--die-with-parent", "--new-session",
                       "--unshare-user", "--unshare-pid", "--unshare-ipc", "--unshare-uts", "--unshare-cgroup"]
    if not profile.network:
        argv += ["--unshare-net"]
    argv += ["--proc", "/proc", "--dev", "/dev", "--tmpfs", "/tmp" if profile.tmp_writable else "/run/aegis-empty"]

    for ro in SYSTEM_RO:
        if os.path.exists(ro):
            argv += ["--ro-bind", ro, ro]
    for extra in ("/etc/resolv.conf", "/etc/hosts", "/etc/nsswitch.conf", "/etc/ca-certificates.conf"):
        if profile.network and os.path.exists(extra):
            argv += ["--ro-bind", extra, extra]

    # Writable workspace and declared extra roots.
    seen = set()
    for root in [ws] + [os.path.abspath(r) for r in profile.extra_roots]:
        if root and root not in seen and os.path.isdir(root):
            argv += ["--bind", root, root]
            seen.add(root)

    # Hide credential stores / Aegis state even when they sit under an allowed root.
    home = os.path.abspath(os.path.expanduser("~"))
    for sub in profile.hide:
        target = os.path.join(home, sub)
        if any(target == r or target.startswith(r + "/") for r in seen):
            argv += ["--tmpfs", target]

    argv += ["--chdir", ws, "--clearenv",
             "--setenv", "PATH", "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin",
             "--setenv", "HOME", ws, "--setenv", "TMPDIR", "/tmp",
             "--setenv", "LANG", os.environ.get("LANG", "C.UTF-8"),
             "--setenv", "AEGIS_SANDBOXED", "1"]
    argv += ["--"] + _as_command(command, shell)
    return argv


def _as_command(command, shell: Optional[str]) -> List[str]:
    if isinstance(command, (list, tuple)):
        return list(command)
    sh = shell or "/bin/bash"
    sh = shutil.which(os.path.basename(sh)) or "/bin/sh"
    return [sh, "-c", str(command)]


def run(profile: SandboxProfile, command, *, shell: Optional[str] = None, timeout: Optional[float] = None,
        **popen_kwargs) -> subprocess.CompletedProcess:
    """Run a command confined by the profile. Raises SandboxUnavailable if it cannot confine."""
    argv = build_argv(profile, command, shell=shell)
    return subprocess.run(argv, timeout=timeout, **popen_kwargs)


def wrap_for_policy(policy, workspace: str, command, *, network: bool = False,
                    shell: Optional[str] = None) -> List[str]:
    """Convenience: build the confined argv straight from an AegisPolicy."""
    return build_argv(SandboxProfile.from_policy(policy, workspace, network=network), command, shell=shell)

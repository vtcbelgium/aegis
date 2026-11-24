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
import platform
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


_SKIP_WALK_DIRS = frozenset({
    "node_modules", "__pycache__", ".pytest_cache", ".mypy_cache", ".ruff_cache", ".next",
})
_SKIP_GIT_WALK_DIRS = frozenset({"objects", "logs", "refs"})


@dataclass
class SandboxProfile:
    workspace: str
    extra_roots: List[str] = field(default_factory=list)
    network: bool = False
    allow_home_read: bool = False
    tmp_writable: bool = True
    readonly_workspace: bool = False
    empty_workspace: bool = False
    hide: List[str] = field(default_factory=lambda: list(HIDE_HOME_SUBPATHS))
    protected_paths: List[str] = field(default_factory=list)
    backup_paths: List[str] = field(default_factory=list)

    @classmethod
    def from_policy(
        cls,
        policy,
        workspace: str,
        network: bool = False,
        *,
        readonly_workspace: bool = False,
        empty_workspace: bool = False,
    ) -> "SandboxProfile":
        roots = [r for r in (getattr(policy, "extra_roots", None) or []) if r]
        return cls(workspace=os.path.abspath(workspace), extra_roots=[os.path.abspath(r) for r in roots],
                   network=network,
                   readonly_workspace=readonly_workspace,
                   empty_workspace=empty_workspace,
                   protected_paths=list(getattr(policy, "protected_paths", []) or [])
                       + list(getattr(policy, "secret_paths", []) or [])
                       + list(getattr(policy, "log_paths", []) or []),
                   backup_paths=list(getattr(policy, "backup_paths", []) or []))


def bwrap_path() -> Optional[str]:
    return shutil.which("bwrap")


def srt_path() -> Optional[str]:
    return shutil.which("srt")


def _user_namespaces_ok() -> bool:
    if platform.system() != "Linux":
        return False
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
    return platform.system() == "Linux" and bool(bwrap_path()) and _user_namespaces_ok()


def probe() -> dict:
    """Report what confinement this host can do, and prove bwrap actually runs."""
    info = {
        "platform": platform.system(),
        "bwrap": bwrap_path(), "srt": srt_path(),
        "userNamespaces": _user_namespaces_ok(), "works": False, "backend": None, "error": None,
    }
    if not available():
        info["error"] = "bubblewrap unavailable (needs Linux, bwrap and unprivileged user namespaces)"
        return info
    try:
        import tempfile
        with tempfile.TemporaryDirectory(prefix="aegis-probe-") as workspace:
            r = run(SandboxProfile(workspace), ["/usr/bin/true"], capture_output=True, timeout=10)
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

    argv: List[str] = [bw, "--die-with-parent", "--new-session",
                       "--unshare-user", "--unshare-pid", "--unshare-ipc", "--unshare-uts", "--unshare-cgroup"]
    if not profile.network:
        argv += ["--unshare-net"]
    argv += ["--cap-drop", "ALL", "--proc", "/proc", "--dev", "/dev", "--tmpfs", "/tmp"]
    if not profile.tmp_writable:
        argv += ["--remount-ro", "/tmp"]

    for ro in SYSTEM_RO:
        if os.path.exists(ro):
            argv += ["--ro-bind", ro, ro]
    for extra in ("/etc/resolv.conf", "/etc/hosts", "/etc/nsswitch.conf", "/etc/ca-certificates.conf"):
        if profile.network and os.path.exists(extra):
            argv += ["--ro-bind", extra, extra]

    if profile.empty_workspace:
        argv += ["--chdir", "/tmp", "--clearenv",
                 "--setenv", "PATH", "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin",
                 "--setenv", "HOME", "/tmp", "--setenv", "TMPDIR", "/tmp",
                 "--setenv", "LANG", os.environ.get("LANG", "C.UTF-8"),
                 "--setenv", "AEGIS_SANDBOXED", "1"]
        argv += ["--"] + _as_command(command, shell)
        return argv

    ws = os.path.realpath(profile.workspace)
    if not os.path.isdir(ws):
        raise SandboxUnavailable(f"workspace does not exist: {ws}")

    # Workspace and declared extra roots (read-only when readonly_workspace=True, else writable).
    ws_bind_flag = "--ro-bind" if profile.readonly_workspace else "--bind"
    seen = set()
    for root in sorted([ws] + [os.path.realpath(r) for r in profile.extra_roots], key=len):
        if root in (os.path.abspath(os.sep),) or root in SYSTEM_RO or root in ("/proc", "/dev", "/sys", "/tmp"):
            raise SandboxUnavailable(f"unsafe writable root: {root}")
        if not os.path.isdir(root):
            raise SandboxUnavailable(f"allowed root does not exist: {root}")
        if root not in seen:
            argv += [ws_bind_flag, root, root]
            seen.add(root)

    # Hide credential stores / Aegis state and lock autoexec paths read-only inside allowed roots.
    home = os.path.realpath(os.path.expanduser("~"))
    from .boundaries import aegis_home, is_backup_path, package_dir
    from .policy import classify_sensitive
    hidden = set()
    for sub in profile.hide:
        if os.path.isabs(sub) or ".." in sub.replace("\\", "/").split("/"):
            raise SandboxUnavailable("hide entries must be home-relative")
        hidden.add(os.path.join(home, sub))
    hidden.update([os.path.realpath(aegis_home()), package_dir()])
    hidden.update(os.path.realpath(p) for p in profile.protected_paths)
    readonly = {os.path.realpath(p) for p in profile.backup_paths}

    scanned = 0
    entries = 0

    def scan_error(exc):
        fname = str(getattr(exc, "filename", "") or "").rstrip(os.sep)
        if os.path.basename(fname) == "lost+found":
            hidden.add(os.path.realpath(fname))
            return
        raise SandboxUnavailable("allowed root could not be inspected safely") from exc

    for root in seen:
        for directory, dirs, files in os.walk(root, followlinks=False, onerror=scan_error):
            if os.path.basename(directory) == ".git":
                dirs[:] = [d for d in dirs if d not in _SKIP_GIT_WALK_DIRS]
            else:
                dirs[:] = [d for d in dirs if d not in _SKIP_WALK_DIRS]
            scanned += 1
            entries += len(dirs) + len(files)
            if scanned > 20000 or entries > 200000:
                raise SandboxUnavailable("allowed roots too large to inspect safely")
            for name in dirs[:] + files:
                target = os.path.join(directory, name)
                sens = classify_sensitive(target)
                if sens in ("critical", "secret", "startup"):
                    hidden.add(target)
                elif sens == "autoexec" or (
                    not any(target == p or target.startswith(p.rstrip(os.sep) + os.sep) for p in readonly)
                    and is_backup_path(target)
                ):
                    readonly.add(target)
                # Hidden trees need no traversal because their entire contents are masked.
                if target in hidden:
                    if name in dirs:
                        dirs.remove(name)

    def exposed(target):
        return any(target == r or target.startswith(r.rstrip(os.sep) + os.sep) for r in seen)

    for target in sorted(readonly, key=len):
        if exposed(target) and os.path.lexists(target):
            if any(target == h or target.startswith(h.rstrip(os.sep) + os.sep) for h in hidden):
                continue
            if os.path.islink(target):
                raise SandboxUnavailable(f"backup or autoexec path is a symlink: {target}")
            argv += ["--ro-bind", target, target]
    masked = []
    for target in sorted(hidden, key=len):
        if not exposed(target) or not os.path.lexists(target):
            continue
        if target == ws or ws.startswith(target.rstrip(os.sep) + os.sep):
            raise SandboxUnavailable("workspace overlaps protected state")
        if any(target.startswith(p.rstrip(os.sep) + os.sep) for p in masked):
            continue
        if os.path.islink(target):
            raise SandboxUnavailable(f"protected path is a symlink: {target}")
        if os.path.isdir(target):
            argv += ["--tmpfs", target, "--remount-ro", target]
        else:
            argv += ["--ro-bind", "/dev/null", target]
        masked.append(target)

    argv += ["--chdir", ws, "--clearenv",
             "--setenv", "PATH", "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin",
             "--setenv", "HOME", ws, "--setenv", "TMPDIR", "/tmp",
             "--setenv", "LANG", os.environ.get("LANG", "C.UTF-8"),
             "--setenv", "AEGIS_SANDBOXED", "1"]
    argv += ["--"] + _as_command(command, shell)
    return argv


def _as_command(command, shell: Optional[str]) -> List[str]:
    import posixpath
    if isinstance(command, (list, tuple)):
        return list(command)
    sh = shell or "/bin/bash"
    if not posixpath.isabs(sh):
        raise SandboxUnavailable("sandbox shell must be an absolute path")
    return [sh, "-c", str(command)]


def run(profile: SandboxProfile, command, *, shell: Optional[str] = None, timeout: Optional[float] = None,
        **popen_kwargs) -> subprocess.CompletedProcess:
    """Run a command confined by the profile. Raises SandboxUnavailable if it cannot confine."""
    argv = build_argv(profile, command, shell=shell)
    if popen_kwargs.get("shell") or popen_kwargs.get("pass_fds") or popen_kwargs.get("preexec_fn"):
        raise SandboxUnavailable("unsafe launcher options")
    popen_kwargs.update(shell=False, close_fds=True,
                        env={"PATH": "/usr/bin:/bin", "LANG": "C.UTF-8"})
    return subprocess.run(argv, timeout=timeout, **popen_kwargs)


def wrap_for_policy(policy, workspace: str, command, *, network: bool = False,
                    shell: Optional[str] = None, readonly_workspace: bool = False,
                    empty_workspace: bool = False) -> List[str]:
    """Convenience: build the confined argv straight from an AegisPolicy."""
    return build_argv(
        SandboxProfile.from_policy(
            policy,
            workspace,
            network=network,
            readonly_workspace=readonly_workspace,
            empty_workspace=empty_workspace,
        ),
        command,
        shell=shell,
    )

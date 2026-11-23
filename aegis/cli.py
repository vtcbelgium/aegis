"""Aegis CLI & Local Daemon.

Commands:
    aegis audit <target_path>       Scan code/config for OWASP & LLM vulnerabilities
    aegis gate <tool> <args_json>   Test a tool call against the negative gate
    aegis serve [--port 9999]       Run local background security daemon & REST API
"""

from __future__ import annotations

import argparse
import http.server
import json
import os
import secrets
import sys
from typing import Any, Dict, Optional
from .core import AegisGate, SUPREME_LAW, DecisionLevel
from .harness import AegisHarness
from .clans import LabyrinthClan, TartarusClan, CustodyClan

if sys.platform == "win32":
    try:
        if hasattr(sys.stdout, "reconfigure"):
            sys.stdout.reconfigure(encoding="utf-8", errors="replace")
        if hasattr(sys.stderr, "reconfigure"):
            sys.stderr.reconfigure(encoding="utf-8", errors="replace")
    except Exception:
        pass


def run_audit(target_path: str) -> int:
    """Audit a directory or file."""
    from .audit import scan_path

    try:
        report = scan_path(target_path)
    except FileNotFoundError as exc:
        print(f"Error: {exc}", file=sys.stderr)
        return 1

    print(f"🛡️  Aegis Sentinel Audit: {report['target']}")
    print(f"📜 Supreme Law: \"{SUPREME_LAW}\"\n")

    for item in report["findings"]:
        icon = "🛑" if item["kind"] == "secret" else "⚠️ "
        print(f"  {icon} [{item['level']}] {item['file']}: {item['message']}")

    print("\n" + "=" * 60)
    if report["passed"]:
        print(f"✅ PASS: Clean repository ({report['filesScanned']} files scanned). Zero security restrictions triggered.")
        return 0
    else:
        print(
            f"🛑 FAILED: {report['findingCount']} security finding(s) across "
            f"{report['filesWithIssues']} file(s). Gate escalated to: {report['level']}"
        )
        return 1


def run_gate_check(tool_name: str, args_json: str, base_dir: Optional[str] = None) -> int:
    """Test a tool call against the gate."""
    try:
        args = json.loads(args_json)
    except Exception:
        print("Error: Invalid JSON arguments", file=sys.stderr)
        return 1

    if not base_dir:
        print("Warning: no --base-dir given, so workspace containment is OFF for this check.", file=sys.stderr)
    harness = AegisHarness(base_dir=base_dir)
    verdict = harness.evaluate_tool_call(tool_name, args)

    print(f"Tool:     {tool_name}")
    print(f"BaseDir:  {base_dir or 'None'}")
    print(f"Level:    {verdict.level.name} (Value: {verdict.level.value})")
    print(f"Passed:   {verdict.passed}")
    print(f"Reasons:  {', '.join(verdict.reasons)}")
    return 0 if verdict.passed else 1


def run_daemon(
    port: int = 9999,
    base_dir: str = ".",
    owner_secret: Optional[str] = None,
    open_browser: bool = False,
) -> None:
    """Run the hardened local Control Center and security daemon REST API."""
    from .server import run_server
    run_server(port=port, base_dir=base_dir, owner_secret=owner_secret, open_browser=open_browser)


def run_doctor_cli(as_json: bool = False) -> int:
    """Print an honest health report of Aegis on this machine."""
    from .setup_wizard import run_doctor
    report = run_doctor()
    if as_json:
        print(json.dumps(report, indent=2))
        return 0 if (report["policy"]["ok"] and report["ledger"]["ok"] and report["tripwires"]["ok"]) else 1

    print(f"🛡️  Aegis Doctor v{report['version']} ({report['platform']}, Python {report['python']})")
    print(f"   State folder: {report['aegisHome']}")
    pol = report["policy"]
    print(f"   Policy file:  {'OK' if pol['ok'] else 'ERROR: ' + str(pol['error'])} ({pol['path']})")
    led = report["ledger"]
    print(f"   Ledger chain: {'OK' if led['ok'] else 'BROKEN'} ({led['count']} entries)")
    tw = report["tripwires"]
    print(f"   Tripwires:    {tw['decoyCount']} decoy(s), {tw['canaryCount']} canary token(s)")
    sb = report["sandbox"]
    print(f"   OS Sandbox:   {'Bubblewrap OK' if sb['works'] else 'Unavailable (' + sb['platform'] + ' — rule gate active)'}")
    print("\nConnected AI Apps:")
    for h in report["hosts"].values():
        if h["kind"] == "hook":
            status = "PROTECTED" if h["protected"] else ("not connected" if h["detected"] else "not detected")
        elif h["kind"] == "mcp":
            status = f"{h['protectedCount']}/{h['totalCount']} MCP servers guarded" if h["exists"] else "no MCP config"
        else:
            status = "ready in " + str(h["path"]) if h["detected"] else "install from browser store"
        print(f"   - {h['name']:32} {status}")
    return 0 if (pol["ok"] and led["ok"] and tw["ok"]) else 1


def run_setup_cli(target: str, disable: bool = False) -> int:
    """Safely configure Aegis hooks for supported AI hosts (creates backups first)."""
    from .setup_wizard import (
        claude_code_settings_path,
        configure_hook_host,
        detect_hosts,
        gemini_cli_settings_path,
    )
    hosts = detect_hosts()
    targets = []
    if target == "auto":
        for key in ("claude_code", "gemini_cli"):
            if hosts[key]["detected"]:
                targets.append(key)
        if not targets:
            print("No Claude Code or Gemini CLI config directory detected yet.")
            print("Run `aegis setup claude` or `aegis setup gemini` to create one, or launch `aegis ui`.")
            return 0
    elif target == "claude":
        targets = ["claude_code"]
    elif target == "gemini":
        targets = ["gemini_cli"]
    else:
        print(f"Unknown setup target: {target}", file=sys.stderr)
        return 1

    path_map = {
        "claude_code": claude_code_settings_path(),
        "gemini_cli": gemini_cli_settings_path(),
    }
    for key in targets:
        res = configure_hook_host(path_map[key], enable=not disable)
        verb = "Disabled" if disable else "Enabled"
        print(f"✅ {verb} Aegis hooks for {hosts[key]['name']}: {res['path']}")
        if res["backup"]:
            print(f"   Backup saved: {res['backup']}")
    return 0


def run_explain(command: str, base_dir: Optional[str]) -> int:
    """Show why a shell command gets its verdict (like dcg explain)."""
    from .shell import analyze_command
    v = analyze_command(command, base_dir=base_dir or os.getcwd(), policy=None)
    print(f"Command: {command}")
    print(f"Verdict: {v.level.name}")
    if v.metadata.get("boundary"):
        print(f"Boundary: {v.metadata['boundary']}")
    if v.metadata.get("effects"):
        print(f"Effects: {', '.join(v.metadata['effects'])}")
    if v.metadata.get("impact"):
        for imp in v.metadata["impact"]:
            print(f"Impact: {imp['entries']} items, {imp['bytes']} bytes"
                  + ("+ (stopped early)" if not imp["complete"] else ""))
    for r in v.reasons:
        print(f"  - {r}")
    return 0 if v.level < DecisionLevel.ASK else (2 if v.level >= DecisionLevel.DENY else 1)


def run_minotaur(action: str, workspace: Optional[str]) -> int:
    from .clans.minotaur import MinotaurClan, Tripwires, plant
    if action == "init":
        summary = plant(workspace=workspace or os.getcwd())
        print(f"Planted {len(summary['planted'])} decoy(s), kept {len(summary['kept'])}; "
              f"registry {summary['registry']}")
        for p in summary["planted"]:
            print(f"  + {p}")
        return 0
    m = MinotaurClan(tripwires=Tripwires.load())
    print(json.dumps(m.snapshot(), indent=1))
    return 0


def run_ledger(action: str, n: int, expected_tip: Optional[str] = None) -> int:
    from .ledger import DecisionLedger, default_ledger_path
    led = DecisionLedger(default_ledger_path())
    if action == "verify":
        r = led.verify(expected_tip=expected_tip)
        print(f"{'OK' if r.ok else 'FAILED'}: {r.count} entries"
              + ("" if r.ok else f"; {r.problem} at line {r.line}"))
        return 0 if r.ok else 1
    for ev in led.tail(n):
        print(f"{ev.get('at','')[:19]} {ev.get('level','?'):8} {ev.get('tool','?'):16} "
              f"{ev.get('boundary') or ''} {ev.get('summary','')}")
    return 0


def run_sandbox(action: str, command: Optional[str], base_dir: Optional[str]) -> int:
    from . import sandbox
    if action == "probe":
        print(json.dumps(sandbox.probe(), indent=1))
        return 0
    if action == "run":
        if not command:
            print("Error: provide a command to run", file=sys.stderr)
            return 1
        ws = base_dir or os.getcwd()
        try:
            return sandbox.run(sandbox.SandboxProfile.from_policy(_policy_from_env(), ws), command).returncode
        except sandbox.SandboxUnavailable as exc:
            print(f"Sandbox unavailable: {exc}", file=sys.stderr)
            return 3
    return 1


def run_pin(action: str, server: str, tools_json: str) -> int:
    from .pinning import ToolPins
    raw = tools_json
    if os.path.isfile(tools_json):
        try:
            with open(tools_json, "r", encoding="utf-8") as fh:
                raw = fh.read()
        except OSError as exc:
            print(f"Error: could not read tools file '{tools_json}': {exc}", file=sys.stderr)
            return 1
    try:
        tools = json.loads(raw)
        if isinstance(tools, dict):
            tools = tools.get("tools", [])
        if not isinstance(tools, list):
            raise ValueError("tools must be a list")
    except ValueError:
        print("Error: tools must be a JSON file path or JSON string containing a list of tool definitions", file=sys.stderr)
        return 1
    pins = ToolPins()
    if action == "pin":
        pins.pin(server, tools)
        print(f"Pinned {len(tools)} tool(s) for '{server}'.")
        return 0
    changes = pins.check(server, tools)
    if not changes:
        print(f"'{server}': no changes from the pinned catalogue.")
        return 0
    for c in changes:
        print(f"  [{c.kind}] {c.tool}: {c.detail}")
    return 2


def run_learn(n: int) -> int:
    """Suggest policy tweaks from what has been ASKed most often (you stay in control)."""
    from collections import Counter
    from .ledger import default_ledger_path, iter_entries
    asks: Counter = Counter()
    for ev in iter_entries(default_ledger_path()):
        if ev.get("level") == "ASK" and ev.get("binary"):
            asks[ev["binary"]] += 1
    if not asks:
        print("No ASK history yet. Let Aegis run in your work, then try again.")
        return 0
    print("Most-asked commands (consider adding safe ones to extra_allowed_binaries):")
    for binary, count in asks.most_common(n):
        print(f"  {count:4}  {binary}")
    return 0


def _policy_from_env():
    from .integrations.generic import load_policy
    return load_policy()


def run_hook(post: bool = False, fmt: str = "claude") -> int:
    """Vendor-neutral agent hook. Reads one tool call (or tool result) as JSON on stdin."""
    from .integrations import generic
    from .integrations.claude_code import run_posttooluse, _read_event
    try:
        event = _read_event()
        if post or event.get("hook_event_name") == "PostToolUse":
            return run_posttooluse(event, fmt=fmt)
        d = generic.evaluate(event.get("tool_name") or "", event.get("tool_input", {}),
                             cwd=event.get("cwd"), session_id=event.get("session_id") or "default")
    except Exception as exc:   # fail closed: ask a human rather than silently allow
        d = generic.HookDecision("deny", f"Aegis could not evaluate this call ({type(exc).__name__}).",
                                 "LOCK", None)
    out, code = generic.render(d, fmt=fmt)
    if out:
        (sys.stderr if fmt == "exit" else sys.stdout).write(out + "\n")
    return code


def main() -> None:
    parser = argparse.ArgumentParser(description="Aegis: deterministic negative security gate & firewall for AI agents")
    sub = parser.add_subparsers(dest="subcommand")
    dojo = sub.add_parser("dojo", help="Run bounded offline simulations from the six legacy knowledge packs")
    dojo.add_argument("--mission", required=True)
    dojo.add_argument("--pack", choices=("all", "01", "02", "03", "04", "05", "06"), default="all")

    ap = sub.add_parser("audit", help="Scan a file or directory for secrets and OWASP issues")
    ap.add_argument("path", default=".", nargs="?")

    gp = sub.add_parser("gate", help="Evaluate a tool call (JSON args)")
    gp.add_argument("tool"); gp.add_argument("args")
    gp.add_argument("--base-dir", default=None)

    ep = sub.add_parser("explain", help="Explain the verdict for a shell command")
    ep.add_argument("command"); ep.add_argument("--base-dir", default=None)

    mp = sub.add_parser("minotaur", help="Tripwires: init (plant decoys) or status")
    mp.add_argument("action", choices=["init", "status"]); mp.add_argument("--workspace", default=None)

    lp = sub.add_parser("ledger", help="Decision ledger: tail or verify")
    lp.add_argument("action", choices=["tail", "verify"]); lp.add_argument("-n", type=int, default=20)
    lp.add_argument("--expect-tip", default=None, help="Trusted external digest to detect removed tail entries")

    spn = sub.add_parser("sandbox", help="Confinement: probe the host or run a command confined")
    spn.add_argument("action", choices=["probe", "run"]); spn.add_argument("command", nargs="?")
    spn.add_argument("--base-dir", default=None)

    mcpp = sub.add_parser("mcp-proxy", help="Transparent stdio MCP security proxy wrapping an upstream server command")
    mcpp.add_argument("--server-id", default=None, help="Stable identifier for MCP tool pinning & fingerprinting")
    mcpp.add_argument("--base-dir", default=None, help="Base directory for path confinement & workspace policies")
    mcpp.add_argument("--pins-file", default=None, help="Custom path for pins.json")
    mcpp.add_argument("--no-auto-pin", action="store_true", help="Require explicit prior `aegis pin pin` instead of auto-pinning first-seen tools")
    mcpp.add_argument("command", nargs=argparse.REMAINDER, help="Upstream MCP server command (e.g. -- npx -y @modelcontextprotocol/server-filesystem /tmp)")

    pp = sub.add_parser("pin", help="MCP tool pinning: check or pin a server's tools")
    pp.add_argument("action", choices=["check", "pin"]); pp.add_argument("server"); pp.add_argument("tools")

    lrn = sub.add_parser("learn", help="Suggest policy tweaks from the ledger (you decide)")
    lrn.add_argument("-n", type=int, default=15)

    hp = sub.add_parser("hook", help="Run as an agent hook (reads a tool call as JSON on stdin)")
    hp.add_argument("--post", action="store_true", help="PostToolUse mode (scan output for decoys)")
    hp.add_argument("--format", choices=("claude", "json", "exit"), default="claude",
                    help="Output shape: claude/gemini/copilot JSON (default), plain json, or exit-code only")

    uip = sub.add_parser("ui", help="Open the offline Aegis Control Center app in your browser")
    uip.add_argument("--port", type=int, default=9999)
    uip.add_argument("--base-dir", default=".")
    uip.add_argument("--no-open", action="store_true", help="Do not automatically launch a browser tab")

    docp = sub.add_parser("doctor", help="Check Aegis health, ledger integrity, tripwires, and connected AI apps")
    docp.add_argument("--json", action="store_true", help="Emit structured JSON diagnostics")

    setp = sub.add_parser("setup", help="One-click setup for Claude Code / Gemini CLI hooks (creates backups)")
    setp.add_argument("target", nargs="?", choices=("auto", "claude", "gemini"), default="auto")
    setp.add_argument("--disable", action="store_true", help="Remove Aegis hooks instead of enabling them")

    svp = sub.add_parser("serve", help="Run local security daemon & Control Center API")
    svp.add_argument("--port", type=int, default=9999); svp.add_argument("--base-dir", default=".")

    args = parser.parse_args()
    if args.subcommand == "ui":
        run_daemon(args.port, base_dir=args.base_dir, open_browser=not args.no_open)
    elif args.subcommand == "doctor":
        sys.exit(run_doctor_cli(as_json=args.json))
    elif args.subcommand == "setup":
        sys.exit(run_setup_cli(args.target, disable=args.disable))
    elif args.subcommand == "dojo":
        from .dojo import run_dojo
        report = run_dojo(mission=args.mission, pack=args.pack)
        print(json.dumps(report, indent=2))
        sys.exit(0 if report["passed"] else 1)
    elif args.subcommand == "audit":
        sys.exit(run_audit(args.path))
    elif args.subcommand == "gate":
        sys.exit(run_gate_check(args.tool, args.args, base_dir=args.base_dir))
    elif args.subcommand == "explain":
        sys.exit(run_explain(args.command, args.base_dir))
    elif args.subcommand == "minotaur":
        sys.exit(run_minotaur(args.action, args.workspace))
    elif args.subcommand == "ledger":
        sys.exit(run_ledger(args.action, args.n, args.expect_tip))
    elif args.subcommand == "sandbox":
        sys.exit(run_sandbox(args.action, args.command, args.base_dir))
    elif args.subcommand == "mcp-proxy":
        from .mcp_proxy import run_mcp_proxy_stdio
        cmd = args.command
        if cmd and cmd[0] == "--":
            cmd = cmd[1:]
        sys.exit(run_mcp_proxy_stdio(
            cmd,
            server_id=args.server_id,
            base_dir=args.base_dir,
            pins_path=args.pins_file,
            auto_pin_new=not args.no_auto_pin,
        ))
    elif args.subcommand == "pin":
        sys.exit(run_pin(args.action, args.server, args.tools))
    elif args.subcommand == "learn":
        sys.exit(run_learn(args.n))
    elif args.subcommand == "hook":
        sys.exit(run_hook(post=args.post, fmt=args.format))
    elif args.subcommand == "serve":
        run_daemon(args.port, base_dir=args.base_dir)
    else:
        parser.print_help()


if __name__ == "__main__":
    main()

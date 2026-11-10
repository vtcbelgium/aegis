# 🛡️ Aegis — a deterministic security gate and firewall for AI agents

[![License](https://img.shields.io/badge/license-Apache--2.0-blue.svg)](LICENSE)
[![Security regression](https://github.com/vtcbelgium/aegis/actions/workflows/tests.yml/badge.svg)](https://github.com/vtcbelgium/aegis/actions/workflows/tests.yml)
[![No LLM](https://img.shields.io/badge/decisions-deterministic%2C%20zero%20tokens-blueviolet.svg)]()
[![Model-agnostic](https://img.shields.io/badge/works%20with-any%20AI-success.svg)]()

> **Supreme law:** *Aegis may subtract authority. Aegis may never create it.*

Aegis sits between an AI agent and the things it can do — run commands, read and write files,
call tools, reach the network — and decides, for each action, whether it may proceed. The
decision is made by **fixed rules, not by another AI**, so a prompt injection cannot argue its
way past it. It costs no tokens, runs offline, and gives the same verdict for the same input
every time.

**It works with any agent.** The engine knows nothing about which model or product is calling.
Use it through the MCP proxy (any MCP client — Claude, ChatGPT, Cursor, local models), the
Python harness (any agent loop), a host hook adapter, or the `aegis`
command line. No integration is a dependency of the others.

---

## Why rules instead of a judge model

Many guardrails ask a second AI to judge the first. That adds latency and token cost to every
call, fails open when the judge errors, and collapses the moment someone crafts a prompt that
fools the judge. Aegis never negotiates with a model:

- **Deterministic.** Per-tool argument schemas, one shared path resolver, a quote-aware shell
  parser with a binary allowlist, and IP canonicalization. Same input → same verdict.
- **Monotonic.** Decisions only ever get stricter within a session:
  `PASS < OBSERVE < WARN < ASK < RESTRICT < DENY < LOCK`. The agent cannot climb back down;
  only an authenticated owner secret resets a quarantine.
- **Fails closed.** Malformed input, an unreadable argument, or an internal error escalates,
  never silently allows.
- **Honest.** Aegis reads the *text* of a call; it cannot see what a program does once it runs.
  So it pairs with an OS sandbox (below) for real containment, and says so.

---

## The clans

```
        AI agent (any model, any host)
                   │
                   ▼
   ┌───────────────────────────────────────────────┐
   │                 AEGIS GATE                      │
   │  Labyrinth   file paths & sensitive locations   │
   │  Tartarus    commands & SQL (+ OS sandbox)      │
   │  Custody     secrets & SSRF / exfiltration      │
   │  Hecatoncheires  loops & rapid-violation brake  │
   │  Minotaur    tripwires, data-leak guard (sensor)│
   └───────────────────────────────────────────────┘
       │ PASS/WARN      │ ASK              │ DENY/LOCK
       ▼                ▼                  ▼
     runs         owner approves         blocked
```

- **Labyrinth** — confines file access to the workspace; credential stores, startup files and
  secret-bearing files are denied or sent for approval.
- **Tartarus** — parses every command (POSIX sh, PowerShell, cmd), following substitutions,
  heredocs, wrappers and nested shells; unknown binaries are sent to the owner, not allowed.
- **Custody** — masks and blocks live credentials and catches SSRF to cloud metadata and
  uploads to anonymous exfiltration sinks.
- **Hecatoncheires** — brakes runaway loops and repeated violations.
- **Minotaur** — the stateful sensor (see below). It may only raise a verdict, never lower one.

## What 1.0 adds

- **Aegis protects itself.** Six hard-boundary classes always LOCK: tampering with Aegis's own
  policy/state, disabling security logs, destroying backups or recovery data, stopping or
  killing the guard, extracting master secrets, and destroying the system.
- **Decision ledger.** Every hook decision is a hash-chained JSON line with recognized secrets
  redacted. `aegis ledger verify` detects edits and broken links. To detect removal of complete
  tail entries, compare against a digest you stored separately using `--expect-tip DIGEST`.
- **Blast radius.** A delete is measured before it runs; above 100 items or 500 MB the owner
  decides, and the reason says how much. Destructive git (`reset --hard`, `clean -f`, forced
  push, `branch -D`, …) asks too.
- **Minotaur tripwires.** `aegis minotaur init` plants decoy files holding fake "canary"
  credentials where a thief would look but ordinary work never goes. Touching a decoy, or any
  appearance of a canary in a call or in tool output, locks the session.
- **Data-leak guard (the "lethal trifecta").** When one session has read private data, taken in
  untrusted content, and then tries to send data out, Aegis asks — you need not spot the
  injection, only stop the combination.
- **Tartarus confinement.** `aegis.sandbox` turns the policy into a Linux `bubblewrap` jail
  (workspace writable, system read-only, secrets hidden, no network by default), closing the
  "a script can do anything" gap. One policy, enforced twice.
- **MCP tool pinning.** Fingerprints each server's tool descriptions and flags rug pulls,
  poisoned descriptions and cross-server shadowing — all on your machine.
- **OWASP code audit.** Advisory scan of code the agent writes, and `aegis audit <path>`.

- **Exact destructive confirmation.** Actions requiring destructive review include resolved
  targets and measured impact. The owner must type `APPROVE DESTRUCTIVE: <operation> :: <target>`
  exactly; generic consent and boolean approval callbacks cannot approve these requests.
  Confirmations bind the full call and observed impact. Wildcard deletion is refused;
  bounded ordinary deletes below the configured review threshold retain their existing policy.
- **Restored Dojo.** All six historical knowledge packs and the registry are preserved with
  provenance. `aegis dojo --mission "local regression"` runs bounded offline policy simulations.
  See [Dojo coverage and limits](docs/dojo/COVERAGE.md).

## Install

```bash
pip install aegis-gate     # or: pip install -e .  from a clone
```

## Use it

**Any MCP client** (model-agnostic):

```python
from aegis import AegisMcpProxy
proxy = AegisMcpProxy(base_dir="/path/to/workspace")
ok, forwarded, verdict = proxy.filter_request(rpc_request)   # before the tool runs
ok, cleaned, verdict   = proxy.filter_response(rpc_response) # scrub output
```

**Any Python agent:**

```python
from aegis import AegisGate, AegisHarness
harness = AegisHarness(AegisGate(base_dir="/path/to/workspace"))
verdict = harness.evaluate_tool_call("start_process", {"command": "rm -rf /"})
# verdict.level == DecisionLevel.LOCK
```

**Claude Code** — add one hook (covers every tool):

```json
{ "hooks": { "PreToolUse":  [{"matcher": "*", "hooks": [{"type": "command", "command": "aegis hook"}]}],
             "PostToolUse": [{"matcher": "*", "hooks": [{"type": "command", "command": "aegis hook --post"}]}] } }
```

**Any other agent** — `aegis hook` reads a tool call as JSON on stdin and answers in the shape
you ask for: `--format claude` (the JSON above), `--format json` (`{"decision","reason","level"}`),
or `--format exit` (exit 0 to allow, 2 to block with the reason on stderr — works with anything
that honours a hook's exit code). Nothing in Aegis is tied to one model or vendor.

Other hosts must adapt their event names, input JSON and decision format to their own hook
contract. Tool-name normalization is shared; a host's hook configuration is not universal.

**MCP catalogue verification** — explicitly pin a reviewed catalogue, then pass
`ToolPins()` and a stable `server_id` as `tool_pins` and `server_id` to `AegisMcpProxy`.
Calls remain blocked until `filter_response` accepts a matching `tools/list` result. A changed,
unrecognized or suspicious catalogue is withheld and its tools cannot execute through the proxy.
First-use auto-pinning is a convenience API, not proof that a server is trustworthy.

**Command line:**

```bash
aegis explain 'rm -rf /'          # why a command gets its verdict
aegis minotaur init               # plant tripwires
aegis ledger verify               # check the decision log is intact
aegis sandbox probe               # can this host confine with bubblewrap?
aegis audit ./src                 # OWASP scan a repo
aegis pin check myserver tools.json
```

Configure through environment variables (so every host configures it the same way):
`AEGIS_PROJECT_EXEC`, `AEGIS_SECRET_LEVEL`, `AEGIS_LEAK_GUARD`, `AEGIS_CODE_AUDIT`,
`AEGIS_UNKNOWN_BINARY`, `AEGIS_EXTRA_ROOTS`, `AEGIS_STRICT_TOOLS`.

## What Aegis is not

- It is **not a sandbox by itself.** It judges the call; it cannot see what a program does once
  it runs. Pair it with the bundled `bubblewrap` confinement (Linux) or another OS sandbox.
- It is **not a guarantee.** It is one deterministic layer. Run agents with least privilege and
  keep backups. Found a bypass? See [SECURITY.md](SECURITY.md).

See [the enforcement and migration guide](docs/ENFORCEMENT.md) for trust boundaries,
state persistence, Linux confinement, and upgrading existing hooks.

## License

Apache-2.0. Copyright 2026 Jeroen Pauwels / OTHRYS. See [LICENSE](LICENSE) and [NOTICE](NOTICE).

# 🛡️ Aegis: Sovereign Negative Security Gate & Agentic Firewall

[![License](https://img.shields.io/badge/license-Apache--2.0-blue.svg)](LICENSE)
[![Tests](https://img.shields.io/badge/tests-80%20passed%20(80%2F80)-brightgreen.svg)]()
[![Tokens](https://img.shields.io/badge/token%20spend-%E2%82%AC0%20(zero)-brightgreen.svg)]()
[![Model](https://img.shields.io/badge/architecture-monotonic%20negative%20gate-blueviolet.svg)]()

> **The Supreme Constitutional Law:**  
> *"Aegis may subtract authority. Aegis may never create it."*

---

## ⚡ Defense-in-Depth vs LLM-as-a-Judge

Many guardrail implementations rely heavily on **prompting a second LLM to evaluate the primary LLM**. While flexible, this introduces critical tradeoffs:
* **Token Costs & Latency:** Adds 500ms–2000ms and paid token spend to every user turn and tool call.
* **Adversarial Jailbreaks:** If an attacker crafts a bypass that fools the judge model, the guardrail collapses.
* **Positive Failure Modes:** When judge calls fail or timeout, systems frequently fail open.

### The Aegis Invariant: Deterministic Negative Gating

Aegis implements a **fast, zero-token deterministic software gate** operating at the tool, syscall, and network boundaries:
1. **Model-Independent Policy:** Aegis does not negotiate or reason with LLMs. An agent cannot persuade or jailbreak the gate, because evaluation relies on per-tool argument schemas, one shared path resolver, a quote-aware shell parser with a binary allowlist, and IP canonicalization.
2. **Strict Monotonicity:** Decisions follow a strict mathematical poset: `PASS < OBSERVE < WARN < ASK < RESTRICT < DENY < LOCK`. Repeated agent-initiated DENY/LOCK verdicts escalate the session and cannot be de-escalated by the agent; only an authenticated owner secret can reset quarantine. ASK verdicts and findings in tool *output* never lock a session.
3. **Human-in-the-Loop (`ASK`):** Ambiguous actions (unknown binaries, inline code, non-allowlisted network egress, config changes) return `ASK`. Pass an `approval_callback` to route them to an owner approval queue such as Tekton; without one, ASK blocks.
4. **Defense-in-Depth Pairing:** String checks provide boundary policy gating. For maximum defense, Aegis is designed to pair with OS sandboxing (containers, Bubblewrap, or seccomp) to contain lower-level execution.
5. **Zero Token Overhead:** Evaluates payloads in microseconds with zero external dependencies (pure Python standard library).

---

## 🏛️ The Four Defensive Clans

```
[ Autonomous Agent / LLM ]
           │
           ▼
┌─────────────────────────────────────────────────────────────┐
│                 AEGIS SOVEREIGN NEGATIVE GATE               │
│                                                             │
│  🌀 Labyrinth Clan:       Path containment & sensitive files│
│  🛡️ Tartarus Clan:        Allowlist shell analyzer & SQL    │
│  🗝️ Credential Custody:    Secrets / SSRF & cloud metadata   │
│  ⚔️ Hecatoncheires:       Loop brake & thread safety        │
│  🛑 Monotonic Poset:      PASS ➔ ASK ➔ DENY ➔ LOCK          │
└──────────────────────────────┬──────────────────────────────┘
                               │
                ▲ BLOCKED      │ APPROVED (Zero Authority Added)
                │              ▼
          [ Quarantine ]  [ OS / Tool Execution ]
```

1. **🌀 Labyrinth Clan:** One resolver for every path (`~`, `~user`, `$HOME`, `${HOME}`, `%USERPROFILE%`, `$env:USERPROFILE`, symlinks, Windows paths even on a Linux host). Workspace containment, credential stores (`~/.ssh`, `~/.aws`, `/etc/shadow` …), startup/persistence files, secret-bearing project files (`.env`), and auto-executing files (`.git/hooks`, `.envrc`).
2. **🛡️ Tartarus Clan:** Quote-aware parsing into segments (`;` `&&` `||` `|` `&`, newlines, subshells, `$(…)`, backticks, heredocs, redirects), shell grammar keywords, variables assigned in the same command, brace and `$IFS` expansion, wrappers (`env`, `xargs`, `timeout` …) and nested shells (`bash -c`, `cmd /c`, `powershell -Command`). Each segment's binary is looked up in an explicit allowlist; unknown binaries go to the owner.
3. **🗝️ Credential Custody Clan:** Cloud metadata (any encoding: `0xa9fea9fe`, IPv4-mapped IPv6, DNS names resolving to it) → LOCK; loopback, link-local, RFC1918 → DENY; live secrets (Anthropic, OpenAI, Stripe, GitHub, Slack, Google, AWS, PEM keys).
4. **⚔️ Hecatoncheires Clan:** Runaway loop brake on identical calls, thread-safe shared state, rapid-violation brake (3 agent DENY/LOCK in 60 s → LOCK).

---

## ⚖️ How Decisions Are Made

| Verdict | Examples |
|---|---|
| **LOCK** (session quarantined) | `rm -rf ~`, `find / -delete`, `Remove-Item -Recurse C:\Users`, any command touching `~/.ssh` or `~/.aws`, live API key in a command, cloud metadata SSRF, `mkfs`, `shutdown` |
| **DENY** | paths outside the workspace, `sudo`, pipes into an interpreter (`curl … \| sh`), uploading `.env`, uploads to known paste/exfil sinks, reverse-shell patterns, writing `.bashrc`/autostart/cron |
| **ASK** (owner decides) | unknown binaries, inline code (`python -c`, `node -e`, heredocs), downloads/uploads to hosts outside the allowlist, `git push` to a non-origin remote, `git config`, global installs, reading `.env`, writing `.git/hooks`, env dumps, local services |
| **PASS** | normal work: `git`, `npm`/`pip`/`pytest`/`cargo`/`go`, file edits in the workspace, downloads from code hosts and package registries |

Everything that decides *what is allowed* lives in `aegis/policy.py`:

```python
from aegis import AegisGate
from aegis.policy import AegisPolicy

policy = AegisPolicy(
    project_exec="ask",                      # default "allow": running the project's own code
    allowed_domains={"github.com", "pypi.org", "registry.npmjs.org", "othrys.be"},
    extra_allowed_binaries={"terraform"},
    strict_tools=True,                       # tools without a schema -> ASK
)
gate = AegisGate(base_dir="/safe/workspace", policy=policy,
                 approval_callback=lambda verdict: ask_owner(verdict))  # e.g. Tekton approvals
```

### What Aegis does not stop

String inspection cannot see what code does. If an agent writes `cleanup.py` and then runs `python cleanup.py`, Aegis sees ordinary project work (with `project_exec="ask"` it asks first). The same holds for `npm test`, `make`, or code installed from an allowlisted code host. Response scanning catches common injection phrasings in five languages after normalization, but a determined attacker can paraphrase. **Pair Aegis with an OS sandbox** (container, Bubblewrap, a separate user) so a mistake is contained even when the policy allows it.

---

## 🚀 Use Cases & Integration Modes

### 1. 🪢 Agent Harness Interceptor (SWE-bench, LangChain, AutoGen, CrewAI)
Known Tekton / Desktop Commander tools (`read_file`, `write_file`, `edit_block`, `move_file`, `start_process`, `interact_with_process`, `set_config_value` …) use exact argument schemas. Other tools are classified by whole words in their argument names (`data_dir` is a path, never content), and any value that looks like a path or URL is checked regardless.

```python
from aegis import AegisGate, AegisHarness

gate = AegisGate(base_dir="/safe/workspace")
harness = AegisHarness(gate)

@harness.protect_tool
def execute_bash(command: str):
    # Raises PermissionError before this runs if Aegis blocks or asks.
    return os.system(command)
```

### 2. 🔌 Model Context Protocol (MCP) Security Proxy
Gates `tools/call` requests and redacts tool output (injection text replaced, secrets masked in place) without escalating the session:

```python
from aegis import AegisMcpProxy

proxy = AegisMcpProxy(base_dir="./safe_dir", approval_callback=tekton_approve)
should_forward, error_response, verdict = proxy.filter_request(incoming_rpc)
ok, sanitized, finding = proxy.filter_response(upstream_response)
```

### 3. 🖥️ Desktop Daemon & Standalone REST API

```bash
aegis serve --port 9999 --base-dir ./workspace
```

* `GET  /status` → monotonic level & telemetry
* `POST /gate`   → tool call evaluation
* `POST /reset`  → reset with the owner secret printed at startup (or `AEGIS_OWNER_SECRET`)

### 4. 🌐 Browser Extension ("AdBlocker for AI Agents")
`browser-extension/` (Manifest V3): redacts prompt-injection text from pages, including zero-font, invisible and split-across-elements text, replacing only the innermost element so the rest of the page survives. Exfiltration beacons (`?cookie=`, `?session_id=`, `?api_key=` …) are blocked before the request leaves the browser by `declarativeNetRequest` rules in `rules.json`.

### 5. 🏔️ OTHRYS Native Integration
Aegis serves as the sovereign Security Authority across the OTHRYS fleet:
* Maintained on the T590 Sentinel scheduler.
* Integrated into the central Sites dashboard and Titans command deck.
* Documented publicly under `/legal/security`.

---

## 🛠️ CLI Quickstart

```bash
# Scan a codebase for hardcoded secrets
aegis audit ./my-project

# Test a tool call against the gate (always pass --base-dir: without it there is no containment)
aegis gate start_process '{"command": "cat ~/.ssh/id_rsa"}' --base-dir ./workspace

# Launch the daemon
aegis serve --port 9999 --base-dir ./workspace

# Interactive stress lab (real engine)
python playground/serve.py
```

---

## 🧪 Verification & Testing

Zero runtime dependencies (Python standard library only).

```bash
python -m unittest discover -s tests -t .
# Ran 80 tests — includes the 1,484-payload fuzz battery, a shared-gate concurrency hammer,
# and the red-team regression suites (rounds 1–5: 80+ bypass attempts, 100+ normal-work commands)

# Browser extension (needs jsdom)
npm install --no-save jsdom && npm run test:extension
```

---

## 📜 License

Apache License 2.0. Copyright (c) 2026 Jeroen Pauwels / OTHRYS.

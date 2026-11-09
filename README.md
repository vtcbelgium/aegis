# 🛡️ Aegis: Sovereign Negative Security Gate & Agentic Firewall

[![License](https://img.shields.io/badge/license-Apache--2.0-blue.svg)](LICENSE)
[![Tests](https://img.shields.io/badge/tests-48%20passed%20(48%2F48)-brightgreen.svg)]()
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
1. **Model-Independent Policy:** Aegis does not negotiate or reason with LLMs. An agent cannot persuade or jailbreak the gate, because evaluation relies on canonicalized paths, argument ASTs, tokenized commands, and IP resolution.
2. **Strict Monotonicity:** Decisions follow a strict mathematical poset: `PASS < OBSERVE < WARN < ASK < RESTRICT < DENY < LOCK`. Once an agent session violates a rule, its privileges escalate upwards and cannot be de-escalated by the agent. Only an authenticated owner secret can reset quarantine.
3. **Human-in-the-Loop (`ASK`):** Sensitive or ambiguous mutations trigger an `ASK` verdict that routes directly to an owner approval queue (e.g. Tekton).
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
│  🌀 Labyrinth Clan:       Path traversal & directory escape │
│  🛡️ Tartarus Boundary:    Command injection & destructive ops│
│  🗝️ Credential Custody:    API keys / SSRF & cloud metadata  │
│  ⚔️ Hecatoncheires:       Race conditions & loop brakes     │
│  🛑 Monotonic Poset:      PASS ➔ ASK ➔ DENY ➔ LOCK          │
└──────────────────────────────┬──────────────────────────────┘
                               │
                ▲ BLOCKED      │ APPROVED (Zero Authority Added)
                │              ▼
          [ Quarantine ]  [ OS / Tool Execution ]
```

1. **🌀 Labyrinth Clan:** Absolute path containment, null-byte truncation defense, recursive multi-level URL unquoting (`%252e%252e`), Windows ADS defense (`::$data`), and sensitive system path protection (`/etc/shadow`, SAM registry).
2. **🛡️ Tartarus Clan:** Shell chaining detection (`;`, `&&`, `||`, subshells), tokenized command analysis via `shlex`, flag permutation detection (`rm -fr /`, `rm -r -f /`, `find / -delete`), and safe workspace command differentiation.
3. **🗝️ Credential Custody Clan:** Zero-egress boundary for Cloud Instance Metadata (`169.254.169.254`, `metadata.google.internal`), RFC1918 intranet blocking, BSD short IP / hex / octal normalization (`127.1`, `0x7f.1`), DNS rebinding defense (`nip.io`), and secret scanning (Anthropic, Stripe, GitHub, Slack, Google, and RSA/EC PEM keys).
4. **⚔️ Hecatoncheires Clan:** Runaway agent loop detection (trips emergency brake when an agent repeats identical tool arguments > threshold), thread-safe shared gate synchronization, and rapid escalation brakes.

---

## 🚀 Use Cases & Integration Modes

### 1. 🪢 Agent Harness Interceptor (SWE-bench, LangChain, AutoGen, CrewAI)
Wrap any Python tool or agent harness to enforce fail-closed execution with recursive argument traversal and automatic positional argument binding:

```python
from aegis import AegisGate, AegisHarness

gate = AegisGate(base_dir="/safe/workspace")
harness = AegisHarness(gate)

@harness.protect_tool
def execute_bash(command: str):
    # If the agent attempts command injection or path escape,
    # Aegis raises PermissionError before this function ever runs.
    return os.system(command)
```

### 2. 🔌 Model Context Protocol (MCP) Security Proxy
Protect Claude Desktop, Cursor, and Antigravity with request gating and response leak filtering:

```python
from aegis import AegisMcpProxy

proxy = AegisMcpProxy(base_dir="./safe_dir")
should_forward, error_response, verdict = proxy.filter_request(incoming_rpc)
if not should_forward:
    send_to_client(error_response)
```

### 3. 🖥️ Desktop Daemon & Standalone REST API
Run Aegis as a local background security daemon:

```bash
aegis serve --port 9999 --base-dir ./workspace
```

* `GET  http://127.0.0.1:9999/status` -> Live monotonic scale & telemetry snapshot
* `POST http://127.0.0.1:9999/gate`   -> Real-time tool call evaluation

### 4. 🌐 Browser Extension ("AdBlocker for AI Agents")
Available under `browser-extension/`:
* Manifest V3 extension that intercepts zero-font prompt injections (`font-size: 0px`, opacity 0, background-matching colors) embedded in untrusted web pages.

---

## 🛠️ CLI Quickstart

```bash
# Scan a codebase for OWASP and secret violations
aegis audit ./my-project

# Test a tool call against the gate
aegis gate run_command '{"command": "cat ~/.ssh/id_rsa"}' --base-dir ./workspace

# Launch the daemon
aegis serve --port 9999 --base-dir ./workspace
```

---

## 🧪 Verification & Testing

Aegis is completely self-contained with **zero runtime external dependencies** (uses Python standard library primitives).

```bash
python -m unittest discover -s tests -t .
# Ran 48 tests in ~3.6s (includes 1,000+ payload fuzzing battery and 10,000-eval shared gate concurrency hammer)
```

### 5. 🏔️ OTHRYS Native Integration
Aegis serves as the sovereign Security Authority across the OTHRYS fleet:
* Maintained on the T590 Sentinel scheduler.
* Integrated into the central Sites dashboard and Titans command deck.
* Documented publicly under `/legal/security`.

---

## 🛠️ CLI Quickstart

```bash
# Scan a codebase for OWASP and secret violations
aegis audit ./my-project

# Test a tool call against the gate
aegis gate run_command '{"command": "rm -rf /"}'

# Launch the daemon
aegis serve --port 9999
```

---

## 🧪 Verification & Testing

Aegis is completely self-contained with **zero runtime external dependencies** (uses Python standard library primitives).

```bash
python -m unittest discover -s tests
# Ran 19 tests in 0.004s — OK
```

---

## 📜 License

Apache License 2.0. Copyright (c) 2026 Jeroen Pauwels / OTHRYS.

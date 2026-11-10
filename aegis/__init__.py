"""Aegis: Deterministic Monotonic Negative Security Gate & Agentic Firewall.

Supreme Law:
    "Aegis may subtract authority. Aegis may never create it."
"""

from .core import AegisGate, DecisionLevel, SUPREME_LAW, Verdict
from .harness import AegisHarness
from .mcp_proxy import AegisMcpProxy
from .clans import LabyrinthClan, TartarusClan, CustodyClan, HecatoncheiresClan, MinotaurClan, Tripwires
from .ledger import DecisionLedger

__version__ = "1.0.0"
__all__ = [
    "AegisGate",
    "DecisionLevel",
    "SUPREME_LAW",
    "Verdict",
    "AegisHarness",
    "AegisMcpProxy",
    "LabyrinthClan",
    "TartarusClan",
    "CustodyClan",
    "HecatoncheiresClan",
    "MinotaurClan",
    "Tripwires",
    "DecisionLedger",
]

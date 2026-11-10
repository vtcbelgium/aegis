# Restored Aegis Dojo

All six original knowledge packs and their registry are preserved in `knowledge-packs/`,
from `vtcbelgium/othrys-os` commit `af91ab236f5ec8bd2c7eb1742b5a1e0dae872f4c`,
branch `wip/aegis-pre-1.0-reconcile-20261001`. They remain reference-only material,
with their original bibliographic attribution and legacy cautions. Importing them does
not promote historical algorithms or candidate exercises into present-day authority.

Run `aegis dojo --mission "local regression"` or select `--pack 01` through `06`.
The runner only evaluates policy and makes disposable evidence fixtures: attack strings
are never executed, no network scans run, and no production state or tripwires are planted.
Reports include expected/actual verdicts and cleanup evidence. Missing mission or broader
execution scope is refused. An ordinary campaign cannot authorize a production exercise.

| Pack | Executable coverage | Additional regression evidence |
|---|---|---|
| 01 Methodology | Declared mission/scope, workspace escape, normal read, self-authorization refusal, reproducible report and cleanup | `tests/test_dojo.py`, `tests/test_harness.py` |
| 02 Crypto/identity | Secret custody, exact action binding, generic-consent refusal, evidence tampering | `tests/test_destructive_confirmation.py`, `tests/test_ledger.py`; Tekton's authenticated-session and exact-owner-confirmation integration tests cover host authorization |
| 03 Detection/evasion | Fragmented shell, encoded metadata, canary attribution, correlated egress, monotonic sensor evidence | `tests/test_minotaur.py`, `tests/test_monotonic.py`, `tests/test_redteam_v1.py` |
| 04 Containment/response | Log tampering, backups, sentinel takeover, system destruction, failed self-reset, loop brake | `tests/test_boundaries.py`, `tests/test_state_hardening.py`, `tests/test_sandbox_live.py` |
| 05 Recon/surface | Unknown binary/tool refusal, admitted directory access, cloud-metadata boundary | `tests/test_integrations.py`, `tests/test_state_hardening.py` (MCP catalogue drift), Minotaur credential-hunting cases |
| 06 Applications/infrastructure | Inline-code approval, malformed arguments, SQL injection, wildcard deletion refusal | Red-team/audit suites, Windows junction escape test, real confinement test, Tekton port/worker approval-flow tests |

## Limits carried forward honestly

The original packs are design overviews, not six ready-made penetration-test executables.
Their full candidate lists remain intact. Learned behavioral baselines, estate-wide listening-
service discovery, independent Sentinel machine-failover drills, production backup restoration,
and independent recovery attestation require their owning host components and a separate
authorized exercise. A green gate-only report does not claim those exercises happened.

Actual Linux confinement is proven by `tests/test_sandbox_live.py`; an unavailable host is
reported as a skip, not a successful confinement exercise. The T590 rollout must separately
prove its installed worker version, owner settings and positive/negative controls.
